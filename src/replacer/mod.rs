use std::path::Path;

use anyhow::Result;

use crate::ptrace;

mod cwd_replacer;
mod mmap_replacer;
mod fd_replacer;
mod utils;

use tracing::error;

pub trait Replacer {
    fn after_mount(&mut self) -> Result<()>;
    fn before_unmount(&mut self) -> Result<()>;
    fn after_unmount(&mut self) -> Result<()>;
}

#[derive(Default)]
pub struct UnionReplacer<'a> {
    replacers: Vec<Box<dyn Replacer + 'a>>,
}

impl<'a> UnionReplacer<'a> {
    pub fn prepare<P1: AsRef<Path>>(
        &mut self,
        detect_path: P1,
    ) -> Result<()> {
        match FdReplacer::prepare(&detect_path) {
            Err(err) => error!("Error while preparing fd replacer: {:?}", err),
            Ok(replacer) => self.replacers.push(Box::new(replacer)),
        }
        match MmapReplacer::prepare(&detect_path) {
            Err(err) => error!("Error while preparing mmap replacer: {:?}", err),
            Ok(replacer) => self.replacers.push(Box::new(replacer)),
        }
        match CwdReplacer::prepare(&detect_path) {
            Err(err) => error!("Error while preparing cwd replacer: {:?}", err),
            Ok(replacer) => self.replacers.push(Box::new(replacer)),
        }
        Ok(())
    }
}

impl<'a> Replacer for UnionReplacer<'a> {
    fn after_mount(&mut self) -> Result<()> {
        for replacer in self.replacers.iter_mut() {
            replacer.after_mount()?;
        }

        Ok(())
    }

    fn before_unmount(&mut self) -> Result<()> {
        for replacer in self.replacers.iter_mut() {
            replacer.before_unmount()?;
        }

        Ok(())
    }

    fn after_unmount(&mut self) -> Result<()> {
        for replacer in self.replacers.iter_mut() {
            replacer.after_unmount()?;
        }

        Ok(())
    }
}

pub use cwd_replacer::CwdReplacer;
pub use fd_replacer::FdReplacer;
pub use mmap_replacer::MmapReplacer;
