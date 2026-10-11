use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::Context as _;
use matrix_sdk_crypto::OlmMachine;
use ruma::{OwnedDeviceId, OwnedUserId};
use tokio::sync::{Mutex, RwLock};

use crate::config::Config;
use crate::crypto;
use crate::crypto::device::{self, DeviceConflict, DeviceUnchecked};
use crate::upstream::Upstream;

/// Everything the proxy knows about one logged-in device (one Bearer token).
pub struct AccountContext {
    pub user_id: OwnedUserId,
    pub device_id: OwnedDeviceId,
    pub token: String,
    pub olm: OlmMachine,
    pub upstream: Upstream,
    /// Serializes outgoing_requests/mark_request_as_sent cycles, as required
    /// by the matrix-sdk-crypto integration contract.
    pub pump_lock: Mutex<()>,
    /// Serializes the claim/share section of the send path so concurrent
    /// sends don't race on session establishment.
    pub share_lock: Mutex<()>,
    /// Room metadata tracked from proxied traffic.
    pub rooms: crypto::rooms::RoomTracker,
    /// Persistent mxc -> attachment-encryption-key cache.
    pub media: crypto::media::MediaKeyCache,
    /// Bookkeeping for the processing of sync responses.
    pub sync: crypto::sync::SyncState,
    /// Placeholders shown to the client, awaiting their room keys.
    pub repairs: crypto::repair::RepairQueue,
    /// How recent verification flows ended.
    pub verifications: crypto::verify::VerificationLog,
}

#[derive(Clone, Default)]
pub struct SessionManager {
    inner: Arc<RwLock<HashMap<String, Arc<AccountContext>>>>,
    /// Sessions turned away, the latest per device, for `ctl debug check`.
    refused: Arc<std::sync::Mutex<Vec<DeviceConflict>>>,
}

impl SessionManager {
    /// The sessions turned away because of their device's keys, until the
    /// user has a working session again.
    pub fn refused(&self) -> Vec<DeviceConflict> {
        self.refused.lock().unwrap().clone()
    }

    fn refuse(&self, conflict: DeviceConflict) -> anyhow::Error {
        let mut refused = self.refused.lock().unwrap();
        refused.retain(|other| {
            (&other.user_id, &other.device_id) != (&conflict.user_id, &conflict.device_id)
        });
        refused.push(conflict.clone());
        conflict.into()
    }

    pub async fn get(&self, token: &str) -> Option<Arc<AccountContext>> {
        self.inner.read().await.get(token).cloned()
    }

    pub async fn list(&self) -> Vec<Arc<AccountContext>> {
        self.inner.read().await.values().cloned().collect()
    }

    pub async fn remove(&self, token: &str) {
        self.inner.write().await.remove(token);
    }

    /// Look up the context for a token, initializing it via /account/whoami
    /// if this token has not been seen before (restored ement sessions never
    /// re-login through the proxy).
    pub async fn get_or_init(
        &self,
        config: &Config,
        upstream: &Upstream,
        token: &str,
    ) -> anyhow::Result<Arc<AccountContext>> {
        if let Some(ctx) = self.get(token).await {
            return Ok(ctx);
        }

        let (status, body) = upstream
            .json_request(
                reqwest::Method::GET,
                "/_matrix/client/v3/account/whoami",
                token,
                None,
            )
            .await?;
        if !status.is_success() {
            anyhow::bail!("whoami failed with {status}: {body}");
        }
        let user_id = body["user_id"]
            .as_str()
            .context("whoami response missing user_id")?;
        let device_id = body["device_id"]
            .as_str()
            .context("whoami response missing device_id (appservice tokens are unsupported)")?;

        self.insert(config, upstream, token, user_id, device_id)
            .await
    }

    /// Create a context from a successful login response body.
    pub async fn insert_from_login(
        &self,
        config: &Config,
        upstream: &Upstream,
        login_response: &serde_json::Value,
    ) -> anyhow::Result<Arc<AccountContext>> {
        let token = login_response["access_token"]
            .as_str()
            .context("login response missing access_token")?
            .to_owned();
        let user_id = login_response["user_id"]
            .as_str()
            .context("login response missing user_id")?;
        let device_id = login_response["device_id"]
            .as_str()
            .context("login response missing device_id")?;
        self.insert(config, upstream, &token, user_id, device_id)
            .await
    }

    async fn insert(
        &self,
        config: &Config,
        upstream: &Upstream,
        token: &str,
        user_id: &str,
        device_id: &str,
    ) -> anyhow::Result<Arc<AccountContext>> {
        let user_id: OwnedUserId = user_id.parse().context("invalid user_id")?;
        let device_id: OwnedDeviceId = device_id.into();
        let store_dir = crypto::machine::account_store_dir(config, &user_id, &device_id);

        // A device ID keeps the identity keys it has (see crypto::device), so
        // find out which ones the homeserver knows. Asked before taking the
        // lock: it is a request to the homeserver.
        let published = device::published_identity(upstream, token, &user_id, &device_id).await;

        let mut guard = self.inner.write().await;
        // Re-check under the write lock: two concurrent requests may race here.
        if let Some(ctx) = guard.get(token) {
            return Ok(ctx.clone());
        }

        let has_store = device::has_store(&store_dir);
        if !has_store {
            // The store about to be made brings new identity keys, which only
            // a device that has none may be given.
            match &published {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Err(self.refuse(DeviceConflict {
                        user_id,
                        device_id,
                        store: None,
                    }));
                }
                Err(e) => {
                    let reason = format!("{e:#}");
                    return Err(DeviceUnchecked { device_id, reason }.into());
                }
            }
        }

        let olm = crypto::machine::open_machine(config, &user_id, &device_id).await?;
        let mut republish = false;
        if has_store {
            match &published {
                Ok(Some(key)) if *key != olm.identity_keys().ed25519.to_base64() => {
                    return Err(self.refuse(DeviceConflict {
                        user_id,
                        device_id,
                        store: Some(store_dir),
                    }));
                }
                Ok(Some(_)) => {}
                // The homeserver has lost them: the session was signed out
                // from another client, and the client has logged in again.
                Ok(None) => republish = true,
                // Not knowing is harmless here: a store's keys are published
                // once, and only anew where they are known to be missing.
                Err(e) => tracing::debug!(error = ?e, "could not check the published device keys"),
            }
        }
        // open_machine created the directory.
        let media = crypto::media::MediaKeyCache::open(&store_dir.join("media.sqlite"))?;
        tracing::info!(%user_id, %device_id, "session initialized");

        let ctx = Arc::new(AccountContext {
            user_id,
            device_id,
            token: token.to_owned(),
            olm,
            upstream: upstream.clone(),
            pump_lock: Mutex::new(()),
            share_lock: Mutex::new(()),
            rooms: crypto::rooms::RoomTracker::default(),
            media,
            sync: crypto::sync::SyncState::default(),
            repairs: crypto::repair::RepairQueue::default(),
            verifications: crypto::verify::VerificationLog::default(),
        });
        guard.insert(token.to_owned(), ctx.clone());
        drop(guard);
        // The user has a working session: earlier refusals are history.
        self.refused
            .lock()
            .unwrap()
            .retain(|conflict| conflict.user_id != ctx.user_id);

        spawn_periodic_pump(&ctx);
        // Flush initial device keys / one-time keys right away so the device
        // shows up on the server without waiting for the first sync.
        tokio::spawn({
            let ctx = ctx.clone();
            async move {
                if republish {
                    match device::republish(&ctx).await {
                        Ok(()) => tracing::info!(
                            user_id = %ctx.user_id,
                            device_id = %ctx.device_id,
                            "the homeserver had lost this device's keys (was the session signed \
                             out from another client?); published them again"
                        ),
                        Err(e) => tracing::error!(
                            error = ?e,
                            "the homeserver has lost this device's keys, and publishing them \
                             again failed"
                        ),
                    }
                }
                crypto::machine::pump(&ctx).await
            }
        });

        Ok(ctx)
    }
}

/// Safety net: retry any pending outgoing crypto requests once a minute even
/// if no sync/send triggers a pump (e.g. after transient upstream errors).
fn spawn_periodic_pump(ctx: &Arc<AccountContext>) {
    let weak: Weak<AccountContext> = Arc::downgrade(ctx);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match weak.upgrade() {
                Some(ctx) => crypto::machine::pump(&ctx).await,
                None => break,
            }
        }
    });
}

/// Directory-safe encoding of an ID for use in store paths.
pub fn sanitize_for_path(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':' | '=' | '+') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_matrix_ids_readable() {
        assert_eq!(sanitize_for_path("@alice:example.org"), "@alice:example.org");
        assert_eq!(sanitize_for_path("ABCDEFGHIJ"), "ABCDEFGHIJ");
        assert_eq!(sanitize_for_path("a.b-c_d=e+f"), "a.b-c_d=e+f");
    }

    #[test]
    fn sanitize_neutralizes_path_syntax() {
        // IDs come from the homeserver; they must not be able to climb out of
        // the store directory.
        assert_eq!(sanitize_for_path("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize_for_path("a/b\\c"), "a_b_c");
        assert_eq!(sanitize_for_path("dev ice\0\n"), "dev_ice__");
        assert_eq!(sanitize_for_path("gerät"), "ger_t");
        assert!(!sanitize_for_path("@a/../../b:hs").contains('/'));
    }
}
