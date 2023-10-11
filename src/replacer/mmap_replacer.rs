use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use itertools::Itertools;
use nix::sys::mman::{MapFlags, ProtFlags};
use procfs::process::{MMapPath,MMPermissions};
use tracing::{error, info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Clone, Debug)]
struct ReplaceCase {
    pub memory_addr: u64,
    pub length: u64,
    pub prot: u64,
    pub flags: u64,
    pub path: PathBuf,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
#[repr(C)]
struct RawReplaceCase {
    memory_addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    new_path_offset: u64,
    offset: u64,
    new_mapped_addr: u64,
}

impl RawReplaceCase {
    pub fn new(
        memory_addr: u64,
        length: u64,
        prot: u64,
        flags: u64,
        new_path_offset: u64,
        offset: u64,
    ) -> RawReplaceCase {
        RawReplaceCase {
            memory_addr,
            length,
            prot,
            flags,
            new_path_offset,
            offset,
            new_mapped_addr: 0,
        }
    }
}

// TODO: encapsulate this struct for fd replacer and mmap replacer
struct ProcessAccessorBuilder {
    cases: Vec<RawReplaceCase>,
    new_paths: Cursor<Vec<u8>>,
}

impl ProcessAccessorBuilder {
    pub fn new() -> ProcessAccessorBuilder {
        ProcessAccessorBuilder {
            cases: Vec::new(),
            new_paths: Cursor::new(Vec::new()),
        }
    }

    pub fn build(self, process: ptrace::TracedProcess) -> Result<ProcessAccessor> {
        Ok(ProcessAccessor {
            process,

            cases: self.cases,
            new_paths: self.new_paths,
        })
    }

    pub fn push_case(
        &mut self,
        memory_addr: u64,
        length: u64,
        prot: u64,
        flags: u64,
        new_path: PathBuf,
        offset: u64,
    ) -> anyhow::Result<()> {
        info!("push case");

        let mut new_path = new_path
            .to_str()
            .ok_or(anyhow!("fd contains non-UTF-8 character"))?
            .as_bytes()
            .to_vec();

        new_path.push(0);

        let new_path_offset = self.new_paths.position();
        self.new_paths.write_all(new_path.as_slice())?;

        self.cases.push(RawReplaceCase::new(
            memory_addr,
            length,
            prot,
            flags,
            new_path_offset,
            offset,
        ));

        Ok(())
    }
}

impl FromIterator<ReplaceCase> for ProcessAccessorBuilder {
    fn from_iter<T: IntoIterator<Item = ReplaceCase>>(iter: T) -> Self {
        let mut builder = Self::new();
        for case in iter {
            if let Err(err) = builder.push_case(
                case.memory_addr,
                case.length,
                case.prot,
                case.flags,
                case.path,
                case.offset,
            ) {
                error!("fail to write to AccessorBuilder. Error: {:?}", err)
            }
        }

        builder
    }
}

struct ProcessAccessor {
    process: ptrace::TracedProcess,

    cases: Vec<RawReplaceCase>,
    new_paths: Cursor<Vec<u8>>,
}

impl Debug for ProcessAccessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.process.fmt(f)
    }
}

impl ProcessAccessor {
    fn unmap(&mut self) -> anyhow::Result<()> {
        trace!("self.cases: {:X?}", self.cases);

        let cases = &mut *self.cases.clone();
        let length = cases.len();
        let cases_ptr = &mut cases[0] as *mut RawReplaceCase as *mut u8;
        let size = std::mem::size_of_val(cases);
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr, size) };

        let code = |addr| {
            let mut vec_rt =
                dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(addr as usize);
            dynasm!(vec_rt
                ; .arch x64
                ; ->cases:
                ; .bytes cases
                ; ->cases_length:
                ; .qword cases.len() as i64
                ; nop
                ; nop
            );

            trace!("static bytes placed");
            let replace = vec_rt.offset();
            dynasm!(vec_rt
                ; .arch x64
                // set r15 to 0
                ; xor r15, r15
                ; lea r14, [-> cases]

                ; jmp ->end
                ; ->start:
                // munmap
                ; mov rax, 0x0B
                ; mov rdi, QWORD [r14+r15] // addr
                ; mov rsi, QWORD [r14+r15+8] // length
                ; mov rdx, 0x0
                ; syscall

                // mmap a temporary anonymous mapping to hold the address
                ; mov rax, 0x9
                ; mov rdi, QWORD [r14+r15] // addr
                ; mov rsi, QWORD [r14+r15+8] // length
                ; mov rdx, QWORD [r14+r15+16] // prot
                ; mov r10, 34 // flags = MAP_PRIVATE | MAP_ANON
                ; xor r8, r8 // fd
                ; xor r9, r9 // offset
                ; syscall
                ; mov QWORD [r14+r15+48], rax

                ; add r15, std::mem::size_of::<RawReplaceCase>() as i32
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
        let content = content.as_mut_slice();
        self.process.run_codes(Some(content), code)?;

        let content_ptr= content.as_ptr();
        let cases = unsafe { std::slice::from_raw_parts(content_ptr as *const RawReplaceCase, length) };

        self.cases = cases.to_vec();
        trace!("after remap, self.cases: {:X?}", self.cases);

        let mismatched : Vec<_> = self.cases.iter().filter(|case| case.memory_addr != case.new_mapped_addr).collect();
        if mismatched.len() > 0 {
            error!("mismatched cases: {:X?}", mismatched);
            return Err(anyhow!("some maps not restored with original address"));
        }

        trace!("unmap successful");
        Ok(())
    }

    fn remap(&mut self) -> anyhow::Result<()> {
        self.new_paths.set_position(0);

        let mut new_paths = Vec::new();
        self.new_paths.read_to_end(&mut new_paths)?;

        trace!("self.cases: {:X?}", self.cases);

        let cases = &mut *self.cases.clone();
        let length = cases.len();
        let cases_ptr = &mut cases[0] as *mut RawReplaceCase as *mut u8;
        let size = std::mem::size_of_val(cases);
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr, size) };

        let code = |addr| {

            let mut vec_rt =
                dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(addr as usize);
            dynasm!(vec_rt
                ; .arch x64
                ; ->cases:
                ; .bytes cases
                ; ->cases_length:
                ; .qword cases.len() as i64
                ; ->new_paths:
                ; .bytes new_paths.as_slice()
                ; nop
                ; nop
            );

            trace!("static bytes placed");
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
                ; lea rdi, [-> new_paths]
                ; add rdi, QWORD [r14+r15+32] // path
                ; mov rsi, libc::O_RDWR
                ; mov rdx, 0x0
                ; syscall
                ; mov r12, rax

                // munmap temporary anonymous mapping
                ; mov rax, 0x0B
                ; mov rdi, QWORD [r14+r15] // addr
                ; mov rsi, QWORD [r14+r15+8] // length
                ; syscall

                // mmap
                ; mov rax, 0x9
                ; mov rdi, QWORD [r14+r15] // addr
                ; mov rsi, QWORD [r14+r15+8] // length
                ; mov rdx, QWORD [r14+r15+16] // prot
                ; mov r10, QWORD [r14+r15+24] // flags
                ; mov r8, r12 // fd
                ; mov r9, QWORD [r14+r15+40] // offset
                ; syscall
                ; mov QWORD [r14+r15+48], rax

                // close
                ; mov rax, 0x3
                ; mov rdi, r12
                ; syscall

                ; add r15, std::mem::size_of::<RawReplaceCase>() as i32
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
        let content = content.as_mut_slice();
        self.process.run_codes(Some(content), code)?;

        let content_ptr= content.as_ptr();
        let cases = unsafe { std::slice::from_raw_parts(content_ptr as *const RawReplaceCase, length) };

        self.cases = cases.to_vec();
        trace!("after remap, self.cases: {:X?}", self.cases);

        let mismatched : Vec<_> = self.cases.iter().filter(|case| case.memory_addr != case.new_mapped_addr).collect();
        if mismatched.len() > 0 {
            error!("mismatched cases: {:X?}", mismatched);
            return Err(anyhow!("some maps not restored with original address"));
        }

        trace!("remap successful");
        Ok(())
    }
}

fn get_prot_and_flags_from_perms(perms: MMPermissions) -> (u64, u64) {
    let mut prot = ProtFlags::empty();
    if perms.contains(MMPermissions::READ) {
        prot |= ProtFlags::PROT_READ
    }
    if perms.contains(MMPermissions::WRITE) {
        prot |= ProtFlags::PROT_WRITE
    }
    if perms.contains(MMPermissions::EXECUTE) {
        prot |= ProtFlags::PROT_EXEC
    }

    let flags = if perms.contains(MMPermissions::SHARED) {
        MapFlags::MAP_SHARED
    } else {
        MapFlags::MAP_PRIVATE
    };

    trace!(
        "perms: {:?}, prot: {:?}, flags: {:?}",
        perms,
        prot,
        flags
    );
    (prot.bits() as u64, flags.bits() as u64)
}

pub struct MmapReplacer {
    processes: HashMap<i32, ProcessAccessor>,
}

impl MmapReplacer {
    pub fn prepare<P1: AsRef<Path>>(
        detect_path: P1,
    ) -> Result<MmapReplacer> {
        info!("preparing mmap replacer");

        let detect_path = detect_path.as_ref();

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;

                let traced_process = ptrace::trace(pid).ok()?;
                let maps = process.maps().ok()?;

                Some((traced_process, maps))
            })
            .flat_map(|(process, maps)| {
                maps.into_iter()
                    .filter_map(move |entry| {
                        match entry.pathname {
                            MMapPath::Path(path) => {
                                let (start_address, end_address) = entry.address;
                                let length = end_address - start_address;
                                let (prot, flags) = get_prot_and_flags_from_perms(entry.perms);
                                // TODO: extract permission from perms

                                let case = ReplaceCase {
                                    memory_addr: start_address,
                                    length,
                                    prot,
                                    flags,
                                    path,
                                    offset: entry.offset,
                                };
                                Some((process.clone(), case))
                            }
                            _ => None,
                        }
                    })
                    .filter(|(_, case)| case.path.starts_with(detect_path))
            })
            .group_by(|(process, _)| process.pid)
            .into_iter()
            .filter_map(|(pid, group)| Some((ptrace::trace(pid).ok()?, group)))
            .map(|(process, group)| (process, group.map(|(_, group)| group)))
            .filter_map(|(process, group)| {
                let pid = process.pid;

                match group.collect::<ProcessAccessorBuilder>().build(process) {
                    Ok(accessor) => Some((pid, accessor)),
                    Err(err) => {
                        error!("fail to build accessor: {:?}", err);
                        None
                    }
                }
            })
            .collect();

        Ok(MmapReplacer { processes })
    }
}

impl Replacer for MmapReplacer {
    fn after_mount(&mut self) -> Result<()> {
        info!("replacing mmap'd files");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.unmap()?;
            accessor.remap()?;
        }
        Ok(())
    }

    fn before_unmount(&mut self) -> Result<()> {
        info!("unmapping mmap'd files");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.unmap()?;
        }
        Ok(())
    }

    fn after_unmount(&mut self) -> Result<()> {
        info!("remapping mmap'd files");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.remap()?;
        }
        Ok(())
    }
}
