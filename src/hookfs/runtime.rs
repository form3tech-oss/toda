use once_cell::sync::Lazy;

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use std::future::Future;

use log::trace;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    trace!("build tokio runtime");

    tokio::runtime::Builder::new()
        .threaded_scheduler()
        .core_threads(1)
        .thread_name("fuse-thread")
        .enable_all()
        .build()
        .unwrap()
});

pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    RUNTIME.spawn(future)
}

pub fn spawn_blocking<F, R>(func: F) -> JoinHandle<R>
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    RUNTIME.handle().spawn_blocking(func)
}
