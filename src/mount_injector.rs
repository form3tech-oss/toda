use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use nix::mount::umount;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use retry::delay::Fixed;
use retry::{retry, OperationResult};
use tracing::info;

use crate::injector::{InjectorConfig, MultiInjector};
use crate::{hookfs, mount, stop};

#[derive(Debug)]
pub struct MountInjector {
    mount_point: PathBuf,
    injector_config: Vec<InjectorConfig>,
}

pub struct MountInjectionGuard {
    mount_point: PathBuf,
    pub hookfs: Arc<hookfs::HookFs>,
    handler: Option<JoinHandle<Result<()>>>,
}

impl MountInjectionGuard {
    pub fn enable_injection(&self) {
        self.hookfs.enable_injection();
    }

    pub fn disable_injection(&self) {
        self.hookfs.disable_injection();
    }

    pub fn recover_mount(mut self) -> Result<()> {
        let mount_point = self.mount_point.clone();

        retry(Fixed::from_millis(500).take(20), || {
            if let Err(err) = umount(mount_point.as_path()) {
                info!("umount returns error: {:?}", err);
                OperationResult::Retry(err)
            } else {
                OperationResult::Ok(())
            }
        })?;

        info!("unmount successfully!");
        self.handler
            .take()
            .ok_or(anyhow!("handler is empty"))?
            .join()
            .unwrap()?;

        Ok(())
    }
}

impl MountInjector {
    pub fn create_injection<P: AsRef<Path>>(
        path: P,
        injector_config: Vec<InjectorConfig>,
    ) -> Result<MountInjector> {
        let original_path: PathBuf = path.as_ref().to_owned();

        let mut base_path: PathBuf = path.as_ref().to_owned();
        if !base_path.pop() {
            return Err(anyhow!("path is the root"));
        }

        Ok(MountInjector {
            mount_point: original_path,
            injector_config,
        })
    }

    // This method should be called in host namespace
    pub fn mount(&mut self) -> Result<MountInjectionGuard> {
        let mount_point = self.mount_point.clone();

        let mounts = mount::MountsInfo::parse_mounts()?;

        if !mounts.non_root(&mount_point)? {
            return Err(anyhow!("inject on a root mount"));
        }

        let dir_handle = open(&self.mount_point, OFlag::O_DIRECTORY | OFlag::O_PATH, Mode::empty())?;

        let injectors = MultiInjector::build(self.injector_config.clone())?;

        let hookfs = Arc::new(hookfs::HookFs::new(
            &self.mount_point,
            injectors,
            dir_handle,
        ));

        let original_path = self.mount_point.clone();
        let cloned_hookfs = hookfs.clone();

        let (before_mount_waiter, before_mount_guard) = stop::lock();
        let handler = std::thread::spawn(Box::new(move || {
            let fs = hookfs::AsyncFileSystem::from(cloned_hookfs);

            let args = ["allow_other", "fsname=toda", "default_permissions", "nonempty"];
            let flags: Vec<_> = args
                .iter()
                .flat_map(|item| vec![OsStr::new("-o"), OsStr::new(item)])
                .collect();

            info!("mount with flags {:?}", flags);

            drop(before_mount_guard);
            fuser::mount(fs, &original_path, &flags)?;

            drop(hookfs::runtime::RUNTIME.write().unwrap().take().unwrap());

            Ok(())
        }));
        // TODO: remove this. But wait for FUSE gets up
        // Related Issue: https://github.com/zargony/fuse-rs/issues/9
        before_mount_waiter.wait();
        std::thread::sleep(std::time::Duration::from_millis(200));

        Ok(MountInjectionGuard {
            handler: Some(handler),
            hookfs,
            mount_point: self.mount_point.clone(),
        })
    }
}
