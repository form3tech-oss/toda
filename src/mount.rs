use std::path::Path;

use anyhow::Result;
use procfs::process::{self, Process};

#[derive(Debug, Clone)]
pub struct MountsInfo {
    mounts: Vec<process::MountInfo>,
}

impl MountsInfo {
    pub fn parse_mounts() -> Result<Self> {
        let process = Process::myself()?;
        let mounts = process.mountinfo()?;

        Ok(MountsInfo { mounts })
    }

    pub fn non_root<P: AsRef<Path>>(&self, path: P) -> Result<bool> {
        let mount_points = self.mounts.iter().map(|item| &item.mount_point);
        for mount_point in mount_points {
            if path.as_ref().starts_with(mount_point) {
                // The relationship is "contain" because if we want to inject /a/b, and /a is a mount point, we can still
                // use this method.
                return Ok(true);
            }
        }
        Ok(false)
    }
}
