mod async_fs;
mod errors;
mod reply;
pub mod runtime;
mod utils;

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

pub use async_fs::{AsyncFileSystem, AsyncFileSystemImpl};
use async_trait::async_trait;
use derive_more::{Deref, DerefMut, From};
pub use errors::{HookFsError as Error, Result};
use fuser::*;
use libc::{c_void, fgetxattr, fsetxattr, flistxattr, fremovexattr};
use nix::dir;
use nix::errno::Errno;
use nix::fcntl::{openat, renameat, OFlag, AtFlags};
use nix::sys::{stat, statfs};
use nix::unistd::{
    close, fchownat, fsync, linkat, symlinkat, ftruncate, AccessFlags, FchownatFlags,
    Gid, LinkatFlags, Uid, UnlinkatFlags,
};
pub use reply::Reply;
use reply::*;
use runtime::spawn_blocking;
use slab::Slab;
use tokio::sync::RwLock;
use tracing::{debug, error, instrument, trace};
use utils::*;

use crate::injector::{Injector, Method, MultiInjector};

// use fuse::consts::FOPEN_DIRECT_IO;

macro_rules! inject {
    ($self:ident, $method:ident, $path:expr) => {
        if $self.enable_injection.load(Ordering::SeqCst) {
            $self
                .injector
                .read()
                .await
                .inject(&Method::$method, $path)
                .await?;
        }
    };
}

macro_rules! inject_with_ino {
    ($self:ident, $method:ident, $ino:ident) => {{
        let inode_map = $self.inode_map.read().await;
        if let Ok(path) = inode_map.get_path($ino) {
            let path = path.to_owned();
            trace!("getting attr from path {}", path.display());
            drop(inode_map);
            inject!($self, $method, &path);
        }
    }};
}

macro_rules! inject_with_fh {
    ($self:ident, $method:ident, $fh:ident) => {{
        let opened_files = $self.opened_files.read().await;
        if let Ok(file) = opened_files.get($fh as usize) {
            let path = file.path().to_owned();
            drop(opened_files);
            inject!($self, $method, &path);
        }
    }};
}

macro_rules! inject_write_data {
    ($self:ident, $fh:ident, $data:ident) => {{
        let opened_files = $self.opened_files.read().await;
        if let Ok(file) = opened_files.get($fh as usize) {
            trace!("Write data before inject {:?}", $data);
            $self
                .injector
                .read()
                .await
                .inject_write_data(file.path(), &mut $data)?;
            trace!("Write data after inject {:?}", $data);
        }
    }};
}

macro_rules! inject_with_dir_fh {
    ($self:ident, $method:ident, $fh:ident) => {{
        let opened_dirs = $self.opened_dirs.read().await;
        if let Ok(dir) = opened_dirs.get($fh as usize) {
            let path = dir.path().to_owned();
            drop(opened_dirs);
            inject!($self, $method, &path);
        }
    }};
}

macro_rules! inject_with_parent_and_name {
    ($self:ident, $method:ident, $parent:ident, $name:expr) => {{
        let inode_map = $self.inode_map.read().await;
        if let Ok(parent_path) = inode_map.get_path($parent) {
            let old_path = parent_path.join($name);
            trace!("get path: {}", old_path.display());
            drop(inode_map);
            inject!($self, $method, old_path.as_path());
        }
    }};
}

macro_rules! inject_attr {
    ($self:ident, $attr:ident, $path:expr) => {
        if $self.enable_injection.load(Ordering::SeqCst) {
            $self
                .injector
                .read()
                .await
                .inject_attr(&mut $attr, $path);
        }
    };
}

macro_rules! inject_reply {
    ($self:ident, $method:ident, $path:expr, $reply:ident, $reply_typ:ident) => {
        if $self.enable_injection.load(Ordering::SeqCst) {
            trace!("before inject {:?}", $reply);
            $self.injector.read().await.inject_reply(
                &Method::$method,
                $path,
                &mut Reply::$reply_typ(&mut $reply),
            )?;
            trace!("after inject {:?}", $reply);
        }
    };
}

#[derive(Debug)]
pub struct HookFs {
    mount_path: PathBuf,

    enable_injection: AtomicBool,

    opened_files: RwLock<FhMap<File>>,

    opened_dirs: RwLock<FhMap<Dir>>,

    pub injector: RwLock<MultiInjector>,

    // map from inode to real path
    inode_map: RwLock<InodeMap>,

    dir_handle: RawFd,
}

#[derive(Debug, Default)]
struct Node {
    pub ref_count: u64,
    // TODO: optimize paths with a combination data structure
    paths: Vec<PathBuf>,
}

impl Node {
    fn get_path(&self) -> Option<&Path> {
        self.paths.last().map(|item| item.as_path())
    }

    fn insert(&mut self, path: PathBuf) {
        for p in self.paths.iter() {
            if p == &path {
                return;
            }
        }

        self.paths.push(path);
    }

    fn remove(&mut self, path: &Path) {
        self.paths.retain(|x| x != path);
    }
}

#[derive(Debug, Deref, DerefMut, From)]
struct InodeMap(HashMap<u64, Node>);

impl InodeMap {
    fn get_path(&self, inode: u64) -> Result<&Path> {
        self.0
            .get(&inode)
            .and_then(|item| item.get_path())
            .ok_or(Error::InodeNotFound { inode })
    }

    fn increase_ref(&mut self, inode: u64) {
        if let Some(node) = self.0.get_mut(&inode) {
            node.ref_count += 1;
        }
    }

    fn decrease_ref(&mut self, inode: u64, nlookup: u64) {
        if let Some(node) = self.0.get_mut(&inode) {
            if node.ref_count <= nlookup {
                self.0.remove(&inode);
            }
        }
    }

    fn insert_path<P: AsRef<Path>>(&mut self, inode: u64, path: P) {
        self.0
            .entry(inode)
            .or_default()
            .insert(path.as_ref().to_owned());
    }

    fn remove_path<P: AsRef<Path>>(&mut self, inode: u64, path: P) {
        match self.0.get_mut(&inode) {
            Some(set) => {
                set.remove(path.as_ref());
            }
            None => {
                error!("cannot find inode {} in inode_map", inode);
            }
        }
    }
}

#[derive(Debug, Deref, DerefMut, From)]
struct FhMap<T>(Slab<T>);

impl<T> FhMap<T> {
    fn get(&self, key: usize) -> Result<&T> {
        self.0.get(key).ok_or(Error::FhNotFound { fh: key as u64 })
    }
    fn get_mut(&mut self, key: usize) -> Result<&mut T> {
        self.0
            .get_mut(key)
            .ok_or(Error::FhNotFound { fh: key as u64 })
    }
}

#[derive(Debug)]
pub struct Dir {
    dir: dir::Dir,
    path: PathBuf,
}

impl Dir {
    fn new<P: AsRef<Path>>(dir: dir::Dir, path: P) -> Dir {
        Dir {
            dir,
            path: path.as_ref().to_owned(),
        }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for Dir {
    type Target = dir::Dir;

    fn deref(&self) -> &Self::Target {
        &self.dir
    }
}

impl std::ops::DerefMut for Dir {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.dir
    }
}

#[derive(Debug)]
pub struct File {
    pub fd: RawFd,
    path: PathBuf,
}

impl File {
    fn new<P: AsRef<Path>>(fd: RawFd, path: P) -> File {
        File {
            fd,
            path: path.as_ref().to_owned(),
        }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}

unsafe impl Send for Dir {}
unsafe impl Sync for Dir {}

impl HookFs {
    pub fn new<P1: AsRef<Path>>(
        mount_path: P1,
        injector: MultiInjector,
        dir_handle: RawFd,
    ) -> HookFs {
        let mut inode_map = InodeMap::from(HashMap::new());
        inode_map.insert_path(1, PathBuf::from(mount_path.as_ref()));

        let inode_map = RwLock::new(inode_map);

        HookFs {
            mount_path: mount_path.as_ref().to_owned(),
            opened_files: RwLock::new(FhMap::from(Slab::new())),
            opened_dirs: RwLock::new(FhMap::from(Slab::new())),
            injector: RwLock::new(injector),
            inode_map,
            enable_injection: AtomicBool::from(false),
            dir_handle,
        }
    }

    pub fn enable_injection(&self) {
        self.enable_injection.store(true, Ordering::SeqCst);
    }

    pub fn disable_injection(&self) {
        self.enable_injection.store(false, Ordering::SeqCst);

        // TODO: create a standalone runtime only for interrupt is too ugly.
        //       this RWLock is actually redundant, and the injector is rarely written.
        let mut rt  = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let injector = self.injector.read().await;
            injector.interrupt();
        });
    }

    pub fn relative_path<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let tail = path.as_ref().strip_prefix(self.mount_path.as_path())?;
        let rel = PathBuf::from("./").join(tail);
        Ok(rel.to_path_buf())
    }
}

impl HookFs {
    async fn get_file_attr(&self, path: &Path) -> Result<FileAttr> {
        let rel = self.relative_path(path)?;

        let mut attr = async_stat(self.dir_handle, &rel)
            .await
            .map(convert_libc_stat_to_fuse_stat)??;

        trace!("before inject attr {:?}", &attr);
        inject_attr!(self, attr, path);
        trace!("after inject attr {:?}", &attr);

        Ok(attr)
    }
}

#[async_trait]
impl AsyncFileSystemImpl for HookFs {
    fn init(&self) -> Result<()> {
        trace!("init");

        stat::umask(stat::Mode::empty());

        Ok(())
    }

    fn destroy(&self) {
        trace!("destroy");
    }

    #[instrument(skip(self))]
    async fn lookup(&self, parent: u64, name: OsString) -> Result<Entry> {
        trace!("lookup");
        inject_with_parent_and_name!(self, LOOKUP, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(name)
        };
        trace!("lookup in {}", path.display());

        let stat = self.get_file_attr(&path).await?;

        debug!("insert ({}, {}) into inode_map", stat.ino, path.display());
        inode_map.insert_path(stat.ino, path.clone());
        inode_map.increase_ref(stat.ino);
        // TODO: support generation number
        // this can be implemented with ioctl FS_IOC_GETVERSION
        trace!("return with {:?}", stat);

        let mut reply = Entry::new(stat, 0);
        inject_reply!(self, LOOKUP, path.as_path(), reply, Entry);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn forget(&self, ino: u64, nlookup: u64) {
        trace!("forget");
        self.inode_map.write().await.decrease_ref(ino, nlookup)
    }

    #[instrument(skip(self))]
    async fn getattr(&self, ino: u64) -> Result<Attr> {
        trace!("getattr");

        inject_with_ino!(self, GETATTR, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?;
        trace!("getting attr from path {}", path.display());
        let stat = self.get_file_attr(path).await?;

        trace!("return with {:?}", stat);

        let mut reply = Attr::new(stat);
        inject_reply!(self, GETATTR, path, reply, Attr);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
    ) -> Result<Attr> {
        trace!("setattr");
        inject_with_ino!(self, SETATTR, ino);

        // TODO: support setattr with fh

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?;

        let rel = self.relative_path(path)?;
        async_fchownat(self.dir_handle, &rel, uid, gid).await?;

        if let Some(mode) = mode {
            async_fchmodat(self.dir_handle, &rel, mode).await?;
        }

        if let Some(size) = size {
            let fd = async_openat(self.dir_handle, &rel, OFlag::O_WRONLY, stat::Mode::empty()).await?;
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
            spawn_blocking(move || ftruncate(borrowed_fd, size as i64)).await??;
            async_close(fd).await?;
        }

        let times = [convert_time(atime), convert_time(mtime)];
        let cpath = CString::new(rel.as_os_str().as_bytes())?;
        async_utimensat(self.dir_handle, cpath, times).await?;

        let stat = self.get_file_attr(path).await?;
        trace!("return with {:?}", stat);
        let mut reply = Attr::new(stat);
        inject_reply!(self, GETATTR, path, reply, Attr);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn readlink(&self, ino: u64) -> Result<Data> {
        trace!("readlink");

        inject_with_ino!(self, READLINK, ino);
        let inode_map = self.inode_map.read().await;
        let link_path = inode_map.get_path(ino)?;

        let rel_path = self.relative_path(link_path)?;
        let path = async_readlinkat(self.dir_handle, &rel_path).await?;

        let path = CString::new(path.as_os_str().as_bytes())?;

        let data = path.as_bytes_with_nul();
        trace!("reply with data: {:?}", data);

        let mut reply = Data::new(path.into_bytes());
        inject_reply!(self, READLINK, &link_path, reply, Data);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn mknod(
        &self,
        parent: u64,
        name: OsString,
        mode: u32,
        _umask: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Entry> {
        trace!("mknod");
        inject_with_parent_and_name!(self, MKNOD, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let parent_path = inode_map.get_path(parent)?;
        let path = parent_path.join(&name);
        inject!(self, MKNOD, path.as_path());

        let rel = self.relative_path(path.clone())?;
        let rel_cpath = CString::new(rel.as_os_str().as_bytes())?;

        trace!("mknod for {:?}", rel_cpath);

        async_mknodat(self.dir_handle, rel_cpath, mode, rdev as u64).await?;
        async_fchownat(self.dir_handle, &rel, Some(uid), Some(gid)).await?;

        let stat = self.get_file_attr(&path).await?;
        inode_map.insert_path(stat.ino, path.clone());
        inode_map.increase_ref(stat.ino);
        let mut reply = Entry::new(stat, 0);
        inject_reply!(self, LOOKUP, path.as_path(), reply, Entry);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn mkdir(
        &self,
        parent: u64,
        name: OsString,
        mode: u32,
        _umask: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Entry> {
        trace!("mkdir");
        inject_with_parent_and_name!(self, MKDIR, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(&name)
        };
        let rel = self.relative_path(path.clone())?;

        let mode = stat::Mode::from_bits_truncate(mode);
        trace!("create directory with mode: {:?}", mode);
        async_mkdirat(self.dir_handle, &rel, mode).await?;
        trace!("setting owner {}:{}", uid, gid);
        async_fchownat(self.dir_handle, &rel, Some(uid), Some(gid)).await?;

        let stat = self.get_file_attr(&path).await?;
        inode_map.insert_path(stat.ino, path.clone());
        inode_map.increase_ref(stat.ino);
        let mut reply = Entry::new(stat, 0);
        inject_reply!(self, LOOKUP, path.as_path(), reply, Entry);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn unlink(&self, parent: u64, name: OsString) -> Result<()> {
        trace!("unlink");
        inject_with_parent_and_name!(self, UNLINK, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(name)
        };
        let rel =  self.relative_path(path.clone())?;

        let stat = self.get_file_attr(&path).await?;

        trace!("unlinking {}", rel.display());
        async_unlinkat(self.dir_handle, &rel, UnlinkatFlags::NoRemoveDir).await?;

        trace!("remove {:x} from inode_map", &stat.ino);
        inode_map.remove_path(stat.ino, path);

        Ok(())
    }

    #[instrument(skip(self))]
    async fn rmdir(&self, parent: u64, name: OsString) -> Result<()> {
        trace!("rmdir");
        inject_with_parent_and_name!(self, RMDIR, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(name)
        };
        let stat = self.get_file_attr(&path).await?;

        let rel = self.relative_path(path.clone())?;
        async_unlinkat(self.dir_handle, &rel, UnlinkatFlags::RemoveDir).await?;

        trace!("remove {:x} from inode_map", &stat.ino);
        inode_map.remove_path(stat.ino, &path);

        Ok(())
    }

    #[instrument(skip(self))]
    async fn symlink(
        &self,
        parent: u64,
        name: OsString,
        link: PathBuf,
        uid: u32,
        gid: u32,
    ) -> Result<Entry> {
        trace!("symlink");
        inject_with_parent_and_name!(self, SYMLINK, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(&name)
        };

        trace!("create symlink: {} => {}", path.display(), link.display());

        let rel = self.relative_path(path.clone())?;
        let rel_clone = rel.clone();
        let dir_handle = self.dir_handle;
        spawn_blocking(move || symlinkat(&link, Some(dir_handle), &rel_clone)).await??;

        trace!("setting owner {}:{}", uid, gid);
        async_fchownat(self.dir_handle, &rel, Some(uid), Some(gid)).await?;

        let stat = self.get_file_attr(&path).await?;
        inode_map.insert_path(stat.ino, path.clone());
        inode_map.increase_ref(stat.ino);
        let mut reply = Entry::new(stat, 0);
        inject_reply!(self, LOOKUP, path.as_path(), reply, Entry);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn rename(
        &self,
        parent: u64,
        name: OsString,
        newparent: u64,
        newname: OsString,
        _flags: u32,
    ) -> Result<()> {
        trace!("rename");
        inject_with_parent_and_name!(self, RENAME, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let old_path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(&name)
        };
        trace!("get original path: {}", old_path.display());

        let parent_path = inode_map.get_path(parent)?;
        let old_path = parent_path.join(&name);

        let new_parent_path = inode_map.get_path(newparent)?;
        let new_path = new_parent_path.join(&newname);

        trace!("get new path: {}", new_path.display());
        trace!(
            "rename from {} to {}",
            old_path.display(),
            new_path.display()
        );

        let dir_fd = self.dir_handle;
        let old_rel = self.relative_path(old_path.clone())?;
        let new_rel = self.relative_path(new_path.clone())?;
        trace!(
            "rename relative from {} to {}",
            old_rel.display(),
            new_rel.display()
        );

        spawn_blocking(move || renameat(Some(dir_fd), &old_rel, Some(dir_fd), &new_rel)).await??;

        let stat = self.get_file_attr(&new_path).await?;
        trace!("remove ({:x}, {})", stat.ino, old_path.display());
        inode_map.remove_path(stat.ino, &old_path);
        trace!("insert ({:x}, {})", stat.ino, new_path.display());
        inode_map.insert_path(stat.ino, &new_path);

        Ok(())
    }

    #[instrument(skip(self))]
    async fn link(&self, ino: u64, newparent: u64, newname: OsString) -> Result<Entry> {
        trace!("link");
        inject_with_ino!(self, LINK, ino);

        let mut inode_map = self.inode_map.write().await;
        let original_path = inode_map.get_path(ino)?.to_owned();
        let new_parent_path = inode_map.get_path(newparent)?.to_owned();
        let new_path = new_parent_path.join(&newname);

        trace!(
            "link from {} to {}",
            new_path.display(),
            original_path.display()
        );

        let dir_fd = self.dir_handle;
        let new_rel = self.relative_path(&new_path)?;
        let original_rel = self.relative_path(&original_path)?;

        spawn_blocking(move || {
            linkat(
                Some(dir_fd),
                &original_rel,
                Some(dir_fd),
                &new_rel,
                LinkatFlags::NoSymlinkFollow,
            )
        })
        .await??;

        let stat = self.get_file_attr(&new_path).await?;
        inode_map.insert_path(stat.ino, new_path.clone());
        inode_map.increase_ref(stat.ino);
        let mut reply = Entry::new(stat, 0);
        inject_reply!(self, LOOKUP, new_path.as_path(), reply, Entry);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn open(&self, ino: u64, flags: i32) -> Result<Open> {
        trace!("open");
        inject_with_ino!(self, OPEN, ino);

        // TODO: support direct io
        if flags & libc::O_DIRECT != 0 {
            debug!("direct io flag is ignored directly")
        }
        // filter out append. The kernel layer will translate the
        // offsets for us appropriately.
        let filtered_flags = flags & (!libc::O_APPEND) & (!libc::O_DIRECT);
        let filtered_flags = OFlag::from_bits_truncate(filtered_flags);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?;

        trace!("open with flags: {:?}", filtered_flags);

        let rel = self.relative_path(path)?;
        let fd = async_openat(self.dir_handle, &rel, filtered_flags, stat::Mode::empty()).await?;
        let fh = self.opened_files.write().await.insert(File::new(fd, path)) as u64;

        debug!("open: return with fh: {}, flags: {}", fh, 0);

        let mut reply = Open::new(fh, 0);
        inject_reply!(self, OPEN, path, reply, Open);
        // TODO: force DIRECT_IO is not a great option
        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn read(
        &self,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> Result<Data> {
        trace!("read");
        inject_with_fh!(self, READ, fh);

        let opened_files = self.opened_files.read().await;
        let file = opened_files.get(fh as usize)?;
        let buf = async_read(file.fd, size as usize, offset).await?;

        let mut reply = Data::new(buf);
        inject_reply!(self, READ, &file.path(), reply, Data);
        Ok(reply)
    }

    #[instrument(skip(self, data))]
    async fn write(
        &self,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut data: Vec<u8>,
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> Result<Write> {
        trace!("write");
        inject_with_fh!(self, WRITE, fh);
        inject_write_data!(self, fh, data);
        let opened_files = self.opened_files.read().await;
        let file = opened_files.get(fh as usize)?;

        let size = async_write(file.fd, data, offset).await?;
        let mut reply = Write::new(size as u32);
        inject_reply!(self, WRITE, file.path(), reply, Write);
        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn flush(&self, _ino: u64, fh: u64, _lock_owner: u64) -> Result<()> {
        trace!("flush");
        inject_with_fh!(self, FLUSH, fh);

        // flush is implemented with fsync. Is it the correct way?
        let opened_files = self.opened_files.read().await;
        let fd: RawFd = {
            let file = opened_files.get(fh as usize)?;
            file.fd
        };
        spawn_blocking(move || fsync(fd)).await??;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn release(
        &self,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
    ) -> Result<()> {
        trace!("release");

        let mut opened_files = self.opened_files.write().await;
        if let Ok(file) = opened_files.get(fh as usize) {
            async_close(file.fd).await?;
        }
        opened_files.remove(fh as usize);
        Ok(())
    }

    #[instrument(skip(self))]
    async fn fsync(&self, _ino: u64, fh: u64, _datasync: bool) -> Result<()> {
        trace!("fsync");
        inject_with_fh!(self, FSYNC, fh);

        let opened_files = self.opened_files.read().await;
        let fd: RawFd = {
            let file = opened_files.get(fh as usize)?;
            file.fd
        };

        spawn_blocking(move || fsync(fd)).await??;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn opendir(&self, ino: u64, flags: i32) -> Result<Open> {
        trace!("opendir");
        inject_with_ino!(self, OPENDIR, ino);

        let inode_map = self.inode_map.read().await;
        let path = { inode_map.get_path(ino)?.to_owned() };
        let filtered_flags = flags & (!libc::O_APPEND);
        let filtered_flags = OFlag::from_bits_truncate(filtered_flags);

        trace!("opening directory {}", path.display());
        let rel = self.relative_path(path.clone())?;
        let dir_fd = async_openat(self.dir_handle, &rel, filtered_flags, stat::Mode::empty()).await?;
        let dir = dir::Dir::from_fd(dir_fd)?;

        trace!("directory {} opened", path.display());
        let fh = self.opened_dirs.write().await.insert(Dir::new(dir, &path)) as u64;
        trace!("return with fh: {}, flags: {}", fh, flags);

        let mut reply = Open::new(fh, flags);
        inject_reply!(self, OPENDIR, &path, reply, Open);
        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn readdir(
        &self,
        _ino: u64,
        fh: u64,
        offset: i64,
        reply: &mut ReplyDirectory,
    ) -> Result<()> {
        trace!("readdir");
        inject_with_dir_fh!(self, READDIR, fh);

        let offset = offset as usize;
        let mut opened_dirs = self.opened_dirs.write().await;
        // TODO: optimize the implementation
        let all_entries: Vec<_> = {
            let dir = opened_dirs.get_mut(fh as usize)?;

            dir.iter().collect()
        };
        if offset >= all_entries.len() {
            trace!("empty reply");
            return Ok(());
        }
        for (index, entry) in all_entries.iter().enumerate().skip(offset) {
            let entry = (*entry)?;

            let name = entry.file_name();
            let name = OsStr::from_bytes(name.to_bytes());

            let file_type = convert_filetype(entry.file_type().ok_or(Error::UnknownFileType)?);

            if !reply.add(entry.ino(), (index + 1) as i64, file_type, name) {
                trace!("add file {:?}", entry);
            } else {
                trace!("buffer is full");
                break;
            }
        }

        trace!("iterated all files");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn releasedir(&self, _ino: u64, fh: u64, _flags: i32) -> Result<()> {
        trace!("releasedir");

        self.opened_dirs.write().await.remove(fh as usize);
        Ok(())
    }

    #[instrument(skip(self))]
    async fn fsyncdir(&self, ino: u64, fh: u64, _datasync: bool) -> Result<()> {
        // TODO: inject

        let path;
            let inode_map = self.inode_map.read().await;
            path = inode_map.get_path(ino)?.to_owned();

        let rel = self.relative_path(&path)?;
        let fd = async_openat(self.dir_handle, &rel, OFlag::O_DIRECTORY, stat::Mode::empty()).await?;
        spawn_blocking(move || -> Result<_> {
            fsync(fd)?;
            Ok(())
        }).await??;
        async_close(fd).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn statfs(&self, ino: u64) -> Result<StatFs> {
        trace!("statfs");
        inject_with_ino!(self, STATFS, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?.to_owned();
        let rel = self.relative_path(&path)?;

        let dir_handle = self.dir_handle;
        let fd = async_openat(dir_handle, &rel, OFlag::O_PATH, stat::Mode::empty()).await?;
        let stat = {
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
            let stat = spawn_blocking(move || statfs::fstatfs(borrowed_fd)).await??;
            async_close(fd).await?;
            stat
        };

        let mut reply = StatFs::new(
            stat.blocks(),
            stat.blocks_free(),
            stat.blocks_available(),
            stat.files(),
            stat.files_free(),
            stat.block_size() as u32,
            stat.maximum_name_length() as u32,
            stat.block_size() as u32,
        );
        inject_reply!(self, STATFS, &path, reply, StatFs);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn setxattr(
        &self,
        ino: u64,
        name: OsString,
        value: Vec<u8>,
        flags: i32,
        _position: u32,
    ) -> Result<()> {
        trace!("setxattr");
        inject_with_ino!(self, SETXATTR, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?.to_owned();

        let rel = self.relative_path(path)?;
        let fd = async_openat(self.dir_handle, &rel, OFlag::O_RDONLY, stat::Mode::empty()).await?;

        let name = CString::new(name.as_bytes())?;
        async_fsetxattr(fd, name, value, flags).await?;

        async_close(fd).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn getxattr(&self, ino: u64, name: OsString, size: u32) -> Result<Xattr> {
        trace!("getxattr");
        inject_with_ino!(self, GETXATTR, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?;

        let rel = self.relative_path(path)?;
        let fd = async_openat(self.dir_handle, &rel, OFlag::O_RDONLY, stat::Mode::empty()).await?;

        let name = CString::new(name.as_bytes())?;
        let data = async_fgetxattr(fd, name, size as usize).await?;

        async_close(fd).await?;

        let mut reply = if size == 0 {
            trace!("return with size {}", data.len());
            Xattr::size(data.len() as u32)
        } else {
            trace!("return with data {:?}", data.as_slice());
            Xattr::data(data)
        };
        inject_reply!(self, GETXATTR, path, reply, Xattr);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn listxattr(&self, ino: u64, size: u32) -> Result<Xattr> {
        trace!("listxattr");
        inject_with_ino!(self, LISTXATTR, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?.to_owned();

        let buf = vec![0u8; size as usize];

        let shared_buf = std::sync::Arc::new(buf);
        let buf_clone = shared_buf.clone();

        let rel = self.relative_path(path.clone())?;
        let fd = async_openat(self.dir_handle, &rel, OFlag::O_RDONLY, stat::Mode::empty()).await?;

        let ret = spawn_blocking(move || {
            let buf_ptr = buf_clone.as_slice() as *const [u8] as *mut [u8] as *mut libc::c_char;
            unsafe { flistxattr(fd, buf_ptr, size as usize) }
        })
        .await?;

        async_close(fd).await?;

        if ret == -1 {
            return Err(Error::last());
        }

        let mut reply = if size == 0 {
            Xattr::size(ret as u32)
        } else {
            Xattr::data(shared_buf.as_slice().to_owned())
        };
        inject_reply!(self, LISTXATTR, &path, reply, Xattr);

        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn removexattr(&self, ino: u64, name: OsString) -> Result<()> {
        trace!("removexattr");
        inject_with_ino!(self, REMOVEXATTR, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?.to_owned();
        let name = CString::new(name.as_bytes())?;

        let rel = self.relative_path(path)?;
        let fd = async_openat(self.dir_handle, &rel, OFlag::O_RDONLY, stat::Mode::empty()).await?;

        let ret = spawn_blocking(move || {
            let name_ptr = &name.as_bytes_with_nul()[0] as *const u8 as *const libc::c_char;
            unsafe { fremovexattr(fd, name_ptr) }
        })
        .await?;

        async_close(fd).await?;

        if ret == -1 {
            return Err(Error::last());
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn access(&self, ino: u64, mask: i32) -> Result<()> {
        trace!("access");
        inject_with_ino!(self, ACCESS, ino);

        let inode_map = self.inode_map.read().await;
        let path = inode_map.get_path(ino)?.to_owned();
        let rel = self.relative_path(&path)?;
        let cpath = CString::new(rel.as_os_str().as_bytes())?;
        let mask = AccessFlags::from_bits_truncate(mask).bits();
        let dir_fd = self.dir_handle;

        spawn_blocking(move || unsafe {
            let path_ptr = &cpath.as_bytes_with_nul()[0] as *const u8 as *const libc::c_char;
            libc::faccessat(dir_fd, path_ptr, mask, 0)
        }).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn create(
        &self,
        parent: u64,
        name: OsString,
        mode: u32,
        _umask: u32,
        flags: i32,
        uid: u32,
        gid: u32,
    ) -> Result<Create> {
        trace!("create");
        inject_with_parent_and_name!(self, CREATE, parent, &name);

        let mut inode_map = self.inode_map.write().await;
        let path = {
            let parent_path = inode_map.get_path(parent)?;
            parent_path.join(name)
        };

        let filtered_flags = flags & (!libc::O_APPEND);
        let filtered_flags = OFlag::from_bits_truncate(filtered_flags);
        let mode = stat::Mode::from_bits_truncate(mode);

        trace!("create with flags: {:?}, mode: {:?}", filtered_flags, mode);
        let rel = self.relative_path(path.clone())?;
        let fd = async_openat(self.dir_handle, &rel, filtered_flags, mode).await?;
        trace!("setting owner {}:{} for file", uid, gid);
        async_fchownat(self.dir_handle, &rel, Some(uid), Some(gid)).await?;

        let stat = self.get_file_attr(&path).await?;
        let fh = self.opened_files.write().await.insert(File::new(fd, &path));

        // TODO: support generation number
        // this can be implemented with ioctl FS_IOC_GETVERSION
        trace!("return with stat: {:?} fh: {}", stat, fh);
        inode_map.insert_path(stat.ino, path.clone());
        inode_map.increase_ref(stat.ino);
        let mut reply = Create::new(stat, 0, fh as u64, flags);
        inject_reply!(self, CREATE, path.as_path(), reply, Create);
        debug!("create: return with fh: {}", reply.fh);
        Ok(reply)
    }

    #[instrument(skip(self))]
    async fn getlk(
        &self,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
    ) -> Result<Lock> {
        trace!("getlk");
        // kernel will implement for hookfs
        Err(Error::Sys(Errno::ENOSYS))
    }

    #[instrument(skip(self))]
    async fn setlk(
        &self,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
    ) -> Result<()> {
        trace!("setlk");
        Err(Error::Sys(Errno::ENOSYS))
    }

    #[instrument(skip(self))]
    async fn bmap(&self, _ino: u64, _blocksize: u32, _idx: u64, reply: ReplyBmap) {
        error!("unimplemented");
        reply.error(nix::libc::ENOSYS);
    }
}

async fn async_fgetxattr(fd: RawFd, name: CString, size: usize) -> Result<Vec<u8>> {
    spawn_blocking(move || {
        let mut buf = vec![0; size];

        let name_ptr = &name.as_bytes_with_nul()[0] as *const u8 as *const libc::c_char;
        let buf_ptr = buf.as_slice() as *const [u8] as *mut [u8] as *mut libc::c_void;

        let ret = unsafe { fgetxattr(fd, name_ptr, buf_ptr, size as usize) };
        if ret == -1 {
            Err(Error::last())
        } else {
            buf.resize(ret as usize, 0);
            Ok(buf)
        }
    })
    .await?
}

async fn async_fsetxattr(fd: RawFd, name: CString, data: Vec<u8>, flags:i32) -> Result<()> {
    spawn_blocking(move || {
        let name_ptr = &name.as_bytes_with_nul()[0] as *const u8 as *const libc::c_char;
        let data_ptr = &data[0] as *const u8 as *const libc::c_void;
        let ret = unsafe { fsetxattr(fd, name_ptr, data_ptr, data.len(), flags) };

        if ret == -1 {
            Err(Error::last())
        } else {
            Ok(())
        }
    })
    .await?
}

async fn async_read(fd: RawFd, count: usize, offset: i64) -> Result<Vec<u8>> {
    spawn_blocking(move || unsafe {
        let mut buf = vec![0; count];
        let ret = libc::pread(fd, buf.as_ptr() as *mut c_void, count, offset);
        if ret == -1 {
            Err(Error::last())
        } else {
            buf.resize(ret as usize, 0);
            Ok(buf)
        }
    })
    .await?
}

async fn async_write(fd: RawFd, data: Vec<u8>, offset: i64) -> Result<isize> {
    spawn_blocking(move || unsafe {
        let ret = libc::pwrite(fd, data.as_ptr() as *const c_void, data.len(), offset);
        if ret == -1 {
            Err(Error::last())
        } else {
            Ok(ret)
        }
    })
    .await?
}

async fn async_stat(dir: RawFd, path: &Path) -> Result<stat::FileStat> {
    let path_clone = path.to_path_buf();
    trace!("async read stat from path {}", path_clone.display());
    Ok(spawn_blocking(move || nix::sys::stat::fstatat(dir, &path_clone, AtFlags::AT_SYMLINK_NOFOLLOW,)).await??)
}

async fn async_fchownat(dir: RawFd, path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    let path_clone = path.to_path_buf();
    spawn_blocking(move || {
        fchownat(
            Some(dir),
            &path_clone,
            uid.map(Uid::from_raw),
            gid.map(Gid::from_raw),
            FchownatFlags::NoFollowSymlink,
        )
    })
    .await??;
    Ok(())
}

async fn async_fchmodat(dir: RawFd, path: &Path, mode: u32) -> Result<()> {
    let path_clone = path.to_path_buf();
    spawn_blocking(move || {
        stat::fchmodat(
            Some(dir),
            &path_clone,
            stat::Mode::from_bits_truncate(mode),
            stat::FchmodatFlags::FollowSymlink,
        )
    })
    .await??;
    Ok(())
}

async fn async_utimensat(dir: RawFd, path: CString, times: [libc::timespec; 2]) -> Result<()> {
    spawn_blocking(move || unsafe {
        let path_ptr = &path.as_bytes_with_nul()[0] as *const u8 as *mut i8;
        let ret = libc::utimensat(
            dir,
            path_ptr,
            &times as *const [libc::timespec; 2] as *const libc::timespec,
            libc::AT_SYMLINK_NOFOLLOW,
        );

        if ret != 0 {
            Err(Error::last())
        } else {
            Ok(())
        }
    })
    .await??;
    Ok(())
}

async fn async_readlinkat(dir: RawFd, path: &Path) -> Result<OsString> {
    let path_clone = path.to_path_buf();
    Ok(spawn_blocking(move || nix::fcntl::readlinkat(dir, &path_clone)).await??)
}

async fn async_mknodat(dir: RawFd, path: CString, mode: u32, rdev: u64) -> Result<()> {
    spawn_blocking(move || {
        let path_ptr = &path.as_bytes_with_nul()[0] as *const u8 as *mut i8;
        let ret = unsafe { libc::mknodat(dir, path_ptr, mode, rdev) };

        if ret != 0 {
            Err(Error::last())
        } else {
            Ok(())
        }
    })
    .await?
}

async fn async_mkdirat(dir: RawFd, path: &Path, mode: stat::Mode) -> Result<()> {
    let path_clone = path.to_path_buf();
    spawn_blocking(move || stat::mkdirat(dir, &path_clone, mode)).await??;
    Ok(())
}

async fn async_unlinkat(dir: RawFd, path: &Path, flags: UnlinkatFlags) -> Result<()> {
    let path_clone = path.to_path_buf();
    spawn_blocking(move || nix::unistd::unlinkat(Some(dir), &path_clone, flags)).await??;
    Ok(())
}

async fn async_openat(dir: RawFd, path: &Path, filtered_flags: OFlag, mode: stat::Mode) -> Result<RawFd> {
    let path_clone = path.to_path_buf();
    let fd = spawn_blocking(move || { openat(dir, &path_clone, filtered_flags, mode) }).await??;
    Ok(fd)
}

async fn async_close(fd: RawFd) -> Result<()> {
    Ok(spawn_blocking(move || close(fd)).await??)
}
