//! Biometric unlock for yobei (ADR-0009).
//!
//! Android only. The Kotlin side (`BiometricPlugin`) shows a BiometricPrompt
//! bound to a CryptoObject and keeps the vault key encrypted under an
//! Android Keystore key. The Rust side only ever sees the vault key (and its
//! fingerprint) in memory; the key never enters the webview, and the plugin
//! exposes no JS commands.

use serde::{Deserialize, Serialize};
use tauri::{Manager, Runtime, plugin::TauriPlugin};

#[cfg(mobile)]
use tauri::plugin::PluginHandle;

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.tauri.yobei.biometric";

/// Outcome of a device-capability probe (Kotlin `status`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// "available" | "no_hardware" | "not_enrolled" | "unavailable".
    pub state: String,
    /// Whether a wrapped vault key blob is stored on this device.
    pub enrolled: bool,
}

/// What the Kotlin side returns after a successful biometric unlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockResponse {
    pub vault_key_b64: String,
    pub key_check_b64: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("biometric unlock is not supported on this platform")]
    UnsupportedPlatform,
    /// The user backed out of the prompt; the UI stays silent.
    #[error("biometric_cancelled")]
    Cancelled,
    /// The device key is gone (new fingerprint enrolled, keystore reset):
    /// the blob was deleted and the user must fall back to the password.
    #[error("biometric_key_invalidated")]
    KeyInvalidated,
    /// No usable biometric or device credential on this device.
    #[error("biometric_not_available")]
    NotAvailable,
    /// Too many failed attempts; the system locks biometrics for a while.
    #[error("biometric_locked_out")]
    LockedOut,
    #[error("biometric failed: {0}")]
    Plugin(String),
}

/// `PluginInvokeError` only exists on mobile targets (it is defined in
/// `tauri::plugin::mobile`); the desktop build never produces one.
#[cfg(mobile)]
impl From<tauri::plugin::mobile::PluginInvokeError> for Error {
    fn from(e: tauri::plugin::mobile::PluginInvokeError) -> Self {
        match e {
            tauri::plugin::mobile::PluginInvokeError::InvokeRejected(r) => {
                match r.code.as_deref() {
                    Some("cancelled") => Error::Cancelled,
                    Some("key_invalidated") => Error::KeyInvalidated,
                    Some("not_available") => Error::NotAvailable,
                    Some("locked_out") => Error::LockedOut,
                    _ => Error::Plugin(match r.message {
                        Some(m) => m,
                        None => r.to_string(),
                    }),
                }
            }
            other => Error::Plugin(other.to_string()),
        }
    }
}

/// Access to the biometric APIs, managed by the plugin as app state.
///
/// Obtain an instance via [`BiometricExt::biometric`].
pub struct Biometric<R: Runtime> {
    #[cfg(mobile)]
    mobile_plugin_handle: Option<PluginHandle<R>>,
    #[cfg(not(mobile))]
    _marker: std::marker::PhantomData<fn() -> R>,
}

impl<R: Runtime> Biometric<R> {
    #[cfg(mobile)]
    fn handle(&self) -> Result<&PluginHandle<R>, Error> {
        self.mobile_plugin_handle
            .as_ref()
            .ok_or(Error::UnsupportedPlatform)
    }

    pub async fn status(&self) -> Result<StatusResponse, Error> {
        #[cfg(mobile)]
        return self
            .handle()?
            .run_mobile_plugin_async("status", serde_json::json!({}))
            .await
            .map_err(Into::into);
        #[cfg(not(mobile))]
        Err(Error::UnsupportedPlatform)
    }

    pub async fn enroll(
        &self,
        vault_key_b64: &str,
        key_check_b64: &str,
        title: &str,
        subtitle: &str,
    ) -> Result<(), Error> {
        #[cfg(mobile)]
        return self
            .handle()?
            .run_mobile_plugin_async(
                "enroll",
                serde_json::json!({
                    "vault_key_b64": vault_key_b64,
                    "key_check_b64": key_check_b64,
                    "title": title,
                    "subtitle": subtitle,
                }),
            )
            .await
            .map_err(Into::into);
        #[cfg(not(mobile))]
        {
            let _ = (vault_key_b64, key_check_b64, title, subtitle);
            Err(Error::UnsupportedPlatform)
        }
    }

    pub async fn unlock(&self, title: &str, subtitle: &str) -> Result<UnlockResponse, Error> {
        #[cfg(mobile)]
        return self
            .handle()?
            .run_mobile_plugin_async(
                "unlock",
                serde_json::json!({ "title": title, "subtitle": subtitle }),
            )
            .await
            .map_err(Into::into);
        #[cfg(not(mobile))]
        {
            let _ = (title, subtitle);
            Err(Error::UnsupportedPlatform)
        }
    }

    pub async fn remove(&self) -> Result<(), Error> {
        #[cfg(mobile)]
        return self
            .handle()?
            .run_mobile_plugin_async("remove", serde_json::json!({}))
            .await
            .map_err(Into::into);
        #[cfg(not(mobile))]
        Err(Error::UnsupportedPlatform)
    }
}

/// Extensions to [`tauri::App`], [`tauri::AppHandle`], [`tauri::WebviewWindow`],
/// [`tauri::Webview`] and [`tauri::Window`] to access the biometric APIs.
pub trait BiometricExt<R: Runtime> {
    fn biometric(&self) -> &Biometric<R>;
}

impl<R: Runtime, T: Manager<R>> BiometricExt<R> for T {
    fn biometric(&self) -> &Biometric<R> {
        self.state::<Biometric<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("yobei-biometric")
        .setup(|app, api| {
            #[cfg(not(target_os = "android"))]
            let _ = api;
            #[cfg(target_os = "android")]
            let handle = Some(api.register_android_plugin(PLUGIN_IDENTIFIER, "BiometricPlugin")?);
            #[cfg(all(mobile, not(target_os = "android")))]
            let handle: Option<PluginHandle<R>> = None;
            app.manage(Biometric {
                #[cfg(mobile)]
                mobile_plugin_handle: handle,
                #[cfg(not(mobile))]
                _marker: std::marker::PhantomData::<fn() -> R>,
            });
            Ok(())
        })
        .build()
}
