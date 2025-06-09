use crate::{TproxyArgs, TproxyState};

#[cfg(target_os = "linux")]
use crate::linux::{_tproxy_remove, _tproxy_setup};

#[cfg(target_os = "windows")]
use crate::windows::{_tproxy_remove, _tproxy_setup};

#[cfg(target_os = "macos")]
use crate::macos::{_tproxy_remove, _tproxy_setup};

impl Drop for TproxyState {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            log::debug!("restoring network settings");
            let mut state = inner.lock().await;

            _ = _tproxy_remove(&mut state).await;
        });
    }
}

pub async fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<TproxyState> {
    log::debug!("Setting up TProxy with args: {:?}", tproxy_args);
    match _tproxy_setup(tproxy_args).await {
        Ok(state) => {
            log::debug!("TProxy setup completed successfully");
            Ok(TproxyState::new(state))
        }
        Err(e) => {
            log::error!("Failed to set up TProxy: {}", e);
            Err(std::io::Error::other(format!("{}", e)))
        }
    }
}

pub async fn tproxy_remove(state: Option<TproxyState>) -> std::io::Result<()> {
    match state {
        Some(state) => {
            let inner = state.inner.clone();
            let mut state = inner.lock().await;
            return _tproxy_remove(&mut state)
                .await
                .map_err(|e| std::io::Error::other(format!("{}", e)));
        }
        #[cfg(all(feature = "unsafe-state-file", any(target_os = "macos", target_os = "windows")))]
        None => {
            if let Ok(mut state) = crate::retrieve_intermediate_state() {
                return _tproxy_remove(&mut state)
                    .await
                    .map_err(|e| std::io::Error::other(format!("{}", e)));
            }
            Ok(())
        }
        #[cfg(not(all(feature = "unsafe-state-file", any(target_os = "macos", target_os = "windows"))))]
        None => Ok(()),
    }
}
