mod device;
mod engine;
mod storage;

use anyhow::Context;
use device::{DeviceService, OBJECT_PATH};
use futures_util::StreamExt;
use zbus::conn::Builder;

const MANAGER_DEST: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const SERVICE_NAME: &str = "io.github.uunicorn.Fprint";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            // Honor RUST_LOG when set (e.g. RUST_LOG=sil6250d=debug); fall back
            // to info-level for our crate otherwise. Adding an explicit
            // directive on top of from_default_env() would override RUST_LOG.
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sil6250d=info")),
        )
        .init();

    // Harden file creation: all newly created files/directories are owner-only.
    // This complements the explicit modes used in storage.rs.
    unsafe {
        libc::umask(0o077);
    }

    storage::init_storage().context("initialize enrollment storage directory")?;

    let devpath = std::env::var("SIL6250_DEV").unwrap_or_else(|_| "/dev/sil6250".into());
    tracing::info!(devpath, "starting sil6250d");

    let conn = Builder::system()?
        .name(SERVICE_NAME)?
        .serve_at(OBJECT_PATH, DeviceService::new(devpath))?
        .build()
        .await
        .context("connect to system D-Bus")?;

    register_with_manager(&conn).await?;

    tracing::info!("running; monitoring open-fprintd manager");
    std::future::pending::<()>().await;
    Ok(())
}

async fn register_with_manager(conn: &zbus::Connection) -> anyhow::Result<()> {
    let proxy = zbus::fdo::DBusProxy::new(conn).await?;
    let mut name_owner_changed = proxy.receive_name_owner_changed().await?;

    if let Err(e) = try_register(conn).await {
        tracing::info!("initial registration failed; waiting for open-fprintd: {e}");
    }

    tokio::spawn({
        let conn = conn.clone();
        async move {
            while let Some(signal) = name_owner_changed.next().await {
                if let Ok(args) = signal.args() {
                    if args.name() == MANAGER_DEST
                        && args.new_owner().as_deref().unwrap_or("") != ""
                    {
                        tracing::info!("open-fprintd appeared; registering");
                        if let Err(e) = try_register(&conn).await {
                            tracing::error!("register failed: {e}");
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

async fn try_register(conn: &zbus::Connection) -> anyhow::Result<()> {
    let manager = zbus::Proxy::new(conn, MANAGER_DEST, MANAGER_PATH, MANAGER_IFACE)
        .await
        .context("create manager proxy")?;

    manager
        .call_method("RegisterDevice", &(OBJECT_PATH,))
        .await
        .context("RegisterDevice")?;

    tracing::info!("device registered at {OBJECT_PATH}");
    Ok(())
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use std::time::Duration;

    struct Manager(Arc<AtomicUsize>);

    #[zbus::interface(name = "net.reactivated.Fprint.Manager")]
    impl Manager {
        fn register_device(&self, path: &str) {
            assert_eq!(path, OBJECT_PATH);
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_for_calls(calls: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while calls.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("manager did not receive registration");
    }

    #[tokio::test]
    #[ignore = "requires an isolated bus: dbus-run-session -- cargo test -p sil6250d -- --ignored"]
    async fn registers_after_manager_appears_and_restarts() {
        let early_backend = zbus::Connection::session().await.unwrap();
        register_with_manager(&early_backend).await.unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let manager = Builder::session().unwrap()
            .name(MANAGER_DEST).unwrap()
            .serve_at(MANAGER_PATH, Manager(calls.clone())).unwrap()
            .build().await.unwrap();
        wait_for_calls(&calls, 1).await;

        let late_backend = zbus::Connection::session().await.unwrap();
        register_with_manager(&late_backend).await.unwrap();
        wait_for_calls(&calls, 2).await;

        manager.release_name(MANAGER_DEST).await.unwrap();
        let new_calls = Arc::new(AtomicUsize::new(0));
        let replacement = Builder::session().unwrap()
            .name(MANAGER_DEST).unwrap()
            .serve_at(MANAGER_PATH, Manager(new_calls.clone())).unwrap()
            .build().await.unwrap();
        wait_for_calls(&new_calls, 2).await;
        replacement.release_name(MANAGER_DEST).await.unwrap();
    }
}
