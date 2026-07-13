use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::Context as _;
use matrix_sdk_crypto::OlmMachine;
use ruma::{OwnedDeviceId, OwnedUserId};
use tokio::sync::{Mutex, RwLock};

use crate::config::Config;
use crate::crypto;
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
    /// Room metadata tracked from proxied traffic.
    pub rooms: crypto::rooms::RoomTracker,
}

#[derive(Clone, Default)]
pub struct SessionManager {
    inner: Arc<RwLock<HashMap<String, Arc<AccountContext>>>>,
}

impl SessionManager {
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

        let mut guard = self.inner.write().await;
        // Re-check under the write lock: two concurrent requests may race here.
        if let Some(ctx) = guard.get(token) {
            return Ok(ctx.clone());
        }

        let olm = crypto::machine::open_machine(config, &user_id, &device_id).await?;
        tracing::info!(%user_id, %device_id, "session initialized");

        let ctx = Arc::new(AccountContext {
            user_id,
            device_id,
            token: token.to_owned(),
            olm,
            upstream: upstream.clone(),
            pump_lock: Mutex::new(()),
            rooms: crypto::rooms::RoomTracker::default(),
        });
        guard.insert(token.to_owned(), ctx.clone());
        drop(guard);

        spawn_periodic_pump(&ctx);
        // Flush initial device keys / one-time keys right away so the device
        // shows up on the server without waiting for the first sync.
        tokio::spawn({
            let ctx = ctx.clone();
            async move { crypto::machine::pump(&ctx).await }
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
