use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use itertools::Itertools;
use procfs::process::FDTarget;
use tracing::{error, info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
#[repr(C)]
struct ReplaceCase {
    fd: u64,
    path_offset: u64,
    flags: u64,
    position: u64,
    opened_fd: u64,
}

struct ProcessAccessor {
    process: ptrace::TracedProcess,
    cases: Vec<ReplaceCase>,
    paths: Vec<u8>,
}

impl Debug for ProcessAccessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.process.fmt(f)
    }
}

impl ProcessAccessor {
    fn new<T: IntoIterator<Item = (u64, PathBuf)>>(process: ptrace::TracedProcess, fds: T) -> anyhow::Result<ProcessAccessor> {
        let mut pairs = Vec::new();
        for entry in fds.into_iter() {
            pairs.push(entry);
        }
        pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        let mut cases = vec![];
        let mut cursor = Cursor::new(Vec::new());
        for (fd, path) in pairs.iter() {
            let case = ReplaceCase{
                fd: *fd,
                path_offset: cursor.position(),
                flags: 0,
                position: 0,
                opened_fd: 0,
            };
            cases.push(case);

            let mut path = path.to_str().ok_or(anyhow!("path contains non UTF-8 character"))?.as_bytes().to_vec();
            path.push(0);
            cursor.write_all(path.as_slice())?;
        }

        cursor.set_position(0);
        let mut paths = Vec::new();
        cursor.read_to_end(&mut paths)?;

        Ok(ProcessAccessor { process, cases, paths })
    }

    fn capture_and_close(&mut self) -> anyhow::Result<()> {
        let cases = &mut *self.cases.clone();
        let length = cases.len();
        let cases_ptr = &mut cases[0] as *mut ReplaceCase as *mut u8;
        let size = std::mem::size_of_val(cases);
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr, size) };

        let inject = move |addr| {
            let mut vec_rt =
                dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(addr as usize);

            dynasm!(vec_rt
                ; .arch x64
                ; ->cases:
                ; .bytes cases
                ; ->count:
                ; .qword cases.len() as i64
                ; nop
                ; nop
            );

            trace!("static bytes placed");
            let replace = vec_rt.offset();
            dynasm!(vec_rt
                ; .arch x64
                ; xor r15, r15
                // pointer to base of cases array
                ; lea r14, [->cases]

                ; jmp ->end
                ; ->start:

                // fcntl
                ; mov rax, 0x48
                ; mov rdi, [r14+r15] // fd
                ; mov rsi, libc::F_GETFL
                ; mov rdx, 0x0
                ; syscall
                ; mov [r14+r15+16], rax // save flags

                // lseek
                ; mov rax, 0x8
                ; mov rdi, [r14+r15] // fd
                ; mov rsi, 0
                ; mov rdx, libc::SEEK_CUR
                ; syscall
                ; mov [r14+r15+24], rax // save position

                // close
                ; mov rax, 0x3
                ; mov rdi, [r14+r15] // fd
                ; syscall

                ; add r15, std::mem::size_of::<ReplaceCase>() as i32
                ; ->end:
                ; mov r13, QWORD [->count]
                ; cmp r15, r13
                ; jb ->start

                ; int3
            );

            let instructions = vec_rt.finalize()?;

            Ok((replace.0 as u64, instructions))
        };

        let mut content = vec![0u8; size];
        let mut content = content.as_mut_slice();
        self.process.run_codes(Some(&mut content), inject)?;

        let content_ptr= content.as_ptr();
        let cases = unsafe { std::slice::from_raw_parts(content_ptr as *const ReplaceCase, length) };

        self.cases = cases.to_vec();

        trace!("after capture, self.cases: {:X?}", self.cases);

        Ok(())
    }

    fn reopen(&mut self) -> anyhow::Result<()> {
        let paths = self.paths.as_slice();

        let cases = &mut *self.cases.clone();
        let length = cases.len();
        let cases_ptr = &mut cases[0] as *mut ReplaceCase as *mut u8;
        let size = std::mem::size_of_val(cases);
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr, size) };

        let inject = move |addr| {
            let mut vec_rt =
                dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(addr as usize);

            dynasm!(vec_rt
                ; .arch x64
                ; ->cases:
                ; .bytes cases
                ; ->cases_length:
                ; .qword cases.len() as i64
                ; ->paths:
                ; .bytes paths
                ; nop
                ; nop
            );

            let replace = vec_rt.offset();
            dynasm!(vec_rt
                ; .arch x64
                // set r15 to 0
                ; xor r15, r15
                ; lea r14, [-> cases]

                ; jmp ->end
                ; ->start:
                // open
                ; mov rax, 0x2
                ; lea rdi, [-> paths]
                ; add rdi, QWORD [r14+r15+8] // path
                ; mov rsi, [r14+r15+16] // flags
                ; mov rdx, 0x0
                ; syscall
                ; mov QWORD [r14+r15+32], rax // opened_fd
                ; test rax, rax
                ; js ->skip

                ; mov rsi, QWORD [r14+r15] // fd
                ; cmp rax, rsi
                ; jz ->lseek
                // dup2
                ; mov r12, rax
                ; mov rdi, rax
                ; mov rax, 0x21
                ; syscall
                ; mov QWORD [r14+r15+32], rax // opened_fd
                // close
                ; mov rax, 0x3
                ; mov rdi, r12
                ; syscall

                ; ->lseek:
                // lseek
                ; mov rdi, rax
                ; mov rax, 0x8
                ; mov rsi, QWORD [r14+r15+24] // position
                ; mov rdx, libc::SEEK_SET
                ; syscall

                ; ->skip:
                ; add r15, std::mem::size_of::<ReplaceCase>() as i32
                ; ->end:
                ; mov r13, QWORD [->cases_length]
                ; cmp r15, r13
                ; jb ->start

                ; int3
            );

            let instructions = vec_rt.finalize()?;

            Ok((replace.0 as u64, instructions))
        };

        let mut content = vec![0u8; size];
        let mut content = content.as_mut_slice();
        self.process.run_codes(Some(&mut content), inject)?;

        let content_ptr= content.as_ptr();
        let cases = unsafe { std::slice::from_raw_parts(content_ptr as *const ReplaceCase, length) };

        self.cases = cases.to_vec();
        trace!("after reopen, self.cases: {:X?}", self.cases);

        let mismatched : Vec<_> = self.cases.iter().filter(|case| case.fd != case.opened_fd).collect();
        if mismatched.len() > 0 {
            error!("mismatched cases: {:X?}", mismatched);
            return Err(anyhow!("some files not opened with original fd number"));
        }

        Ok(())
    }
}

pub struct FdReplacer {
    accessors: HashMap<i32, ProcessAccessor>,
}

impl FdReplacer {
    pub fn prepare<P1: AsRef<Path>>(
        detect_path: P1,
    ) -> Result<FdReplacer> {
        info!("preparing fd replacer");

        let detect_path = detect_path.as_ref();

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;

                let traced_process = match ptrace::trace(pid) {
                    Ok(p) => p,
                    Err(err) => {
                        error!("fail to trace process: {} {}", pid, err);
                        return None;
                    }
                };
                let fd = process.fd().ok()?.filter_map(|fd| fd.ok());

                Some((traced_process, fd))
            })
            .flat_map(|(process, fd)| {
                fd.into_iter()
                    .filter_map(|entry| match entry.target {
                        FDTarget::Path(path) => Some((entry.fd as u64, path)),
                        _ => None,
                    })
                    .filter_map(move |(fd, path)| {
                        if path.starts_with(detect_path) {
                            Some((process.clone(), (fd, path)))
                        } else {
                            None
                        }
                    })
            })
            .group_by(|(process, _)| process.pid)
            .into_iter()
            .filter_map(|(pid, group)| Some((ptrace::trace(pid).ok()?, group)))
            .map(|(process, group)| (process, group.map(|(_, group)| group)))
            .filter_map(|(process, group)| {
                let pid = process.pid;
                Some((pid, ProcessAccessor::new(process, group).ok()?))
            })
            .collect();

        Ok(FdReplacer { accessors: processes })
    }
}

impl Replacer for FdReplacer {
    fn after_mount(&mut self) -> Result<()> {
        info!("replacing open FDs");
        for (_, accessor) in self.accessors.iter_mut() {
            accessor.capture_and_close()?;
            accessor.reopen()?;
        }
        Ok(())
    }

    fn before_unmount(&mut self) -> Result<()> {
        info!("capturing info and closing open FDs");
        for (_, accessor) in self.accessors.iter_mut() {
            accessor.capture_and_close()?;
        }
        Ok(())
    }

    fn after_unmount(&mut self) -> Result<()> {
        info!("reopening closed FDs");
        for (_, accessor) in self.accessors.iter_mut() {
            accessor.reopen()?;
        }
        Ok(())
    }
}
