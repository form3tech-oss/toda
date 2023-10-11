use std::fmt::Debug;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::{info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Debug)]
pub struct CwdReplacer {
    processes: Vec<(ptrace::TracedProcess, PathBuf)>,
}

impl CwdReplacer {
    pub fn prepare<P1: AsRef<Path>>(
        detect_path: P1,
    ) -> Result<CwdReplacer> {
        info!("preparing cmdreplacer");

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;
                trace!("itering proc: {}", pid);

                match process.cwd() {
                    Ok(cwd) => Some((pid, cwd)),
                    Err(err) => {
                        trace!("filter out pid({}) because of error: {:?}", pid, err);
                        None
                    }
                }
            })
            .filter(|(_, path)| path.starts_with(detect_path.as_ref()))
            .filter_map(|(pid, path)| {
                Some((ptrace::trace(pid).ok()?, path))
            })
            .collect();

        Ok(CwdReplacer { processes })
    }
}

impl Replacer for CwdReplacer {
    fn after_mount(&mut self) -> Result<()> {
        info!("running cwd replacer");
        for (process, path) in self.processes.iter() {
            trace!("replacing cwd: {} to {:?}", process.pid, path);
            process.chdir(path)?;
        }

        Ok(())
    }

    fn before_unmount(&mut self) -> Result<()> {
        info!("setting cwd for running processes to /");
        for (process, _) in self.processes.iter() {
            trace!("replacing cwd: {} to /", process.pid);
            process.chdir("/")?;
        }

        Ok(())
    }

    fn after_unmount(&mut self) -> Result<()> {
        info!("restoring cwd for running processes");
        for (process, path) in self.processes.iter() {
            trace!("replacing cwd: {} to {:?}", process.pid, path);
            process.chdir(path)?;
        }

        Ok(())
    }
}
