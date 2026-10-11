//! The proxy's side of `ement-e2ee ctl debug`: health checks that name their
//! remedy, and inspectors for the things that go wrong in practice (a
//! message that will not decrypt, a room, a device list).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use matrix_sdk_crypto::Device;
use ruma::{OwnedRoomId, OwnedUserId, UserId};
use serde_json::{Value, json};
use tracing::Level;

use crate::crypto::decrypt::{self, Decryption};
use crate::crypto::device;
use crate::crypto::machine::{account_store_dir, enc};
use crate::crypto::rooms;
use crate::proxy::AppState;
use crate::session::AccountContext;

/// A client that has not synced for this long is taken to be disconnected.
const CLIENT_SYNC_STALE: Duration = Duration::from_secs(120);
const CLOCK_SKEW_WARN: Duration = Duration::from_secs(30);
const CLOCK_SKEW_FAIL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

/// One health check: what was looked at, how it stands, and what to do.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl Check {
    fn ok(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Ok,
            detail: detail.into(),
            hint: None,
        }
    }

    fn warn(id: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Warn,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }

    fn fail(id: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Fail,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn age_secs(time: Option<SystemTime>) -> Option<u64> {
    Some(time?.elapsed().unwrap_or_default().as_secs())
}

/// GET /_ement/debug/check — every health check, proxy-wide and per session.
pub async fn check(state: &AppState) -> Value {
    let mut proxy = check_homeserver(state).await;
    let sessions = state.sessions.list().await;
    let refused = state.sessions.refused();
    if !sessions.is_empty() {
        proxy.push(Check::ok(
            "sessions",
            format!("{} connected", sessions.len()),
        ));
    } else if refused.is_empty() {
        proxy.push(Check::warn(
            "sessions",
            "no session yet",
            "connect ement through the proxy (`ement-e2ee setup` prints how)",
        ));
    }
    // ement did connect; the proxy would not have its session.
    for conflict in &refused {
        proxy.push(Check::fail(
            "refused_session",
            conflict.detail(),
            conflict.hint(),
        ));
    }
    proxy.push(check_store(state));
    proxy.push(check_log(state));

    let mut session_reports = Vec::new();
    let (mut ok, mut warn, mut fail) = (0, 0, 0);
    let mut tally = |checks: &[Check]| {
        for check in checks {
            match check.status {
                Status::Ok => ok += 1,
                Status::Warn => warn += 1,
                Status::Fail => fail += 1,
            }
        }
    };
    tally(&proxy);
    for ctx in &sessions {
        let checks = check_session(state, ctx).await;
        tally(&checks);
        session_reports.push(json!({
            "user_id": ctx.user_id,
            "device_id": ctx.device_id,
            "checks": checks,
        }));
    }

    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "homeserver": state.config.homeserver.as_str(),
        "listen": state.config.listen.to_string(),
        "uptime_secs": state.started.elapsed().unwrap_or_default().as_secs(),
        "proxy": proxy,
        "sessions": session_reports,
        "summary": { "ok": ok, "warn": warn, "fail": fail },
    })
}

/// Is the homeserver there, and do our clocks agree?
async fn check_homeserver(state: &AppState) -> Vec<Check> {
    let homeserver = &state.config.homeserver;
    let started = Instant::now();
    let response = state
        .upstream
        .http
        .get(state.upstream.url("/_matrix/client/versions"))
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(e) => {
            return vec![Check::fail(
                "homeserver",
                format!("{homeserver} is unreachable: {e}"),
                "check the network and the `homeserver` setting",
            )];
        }
    };
    let elapsed = started.elapsed();
    let mut checks = vec![if response.status().is_success() {
        Check::ok(
            "homeserver",
            format!("{homeserver} answers in {} ms", elapsed.as_millis()),
        )
    } else {
        Check::fail(
            "homeserver",
            format!(
                "{homeserver} answered {} to /_matrix/client/versions",
                response.status()
            ),
            "is `homeserver` the client-server API base URL?",
        )
    }];

    let server_time = response
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok());
    if let Some(server_time) = server_time {
        checks.push(clock_check(SystemTime::now(), server_time, elapsed));
    }
    checks
}

/// Compare our clock with the homeserver's `Date` header (one-second
/// resolution, read `round_trip` ago at most).
fn clock_check(now: SystemTime, server_time: SystemTime, round_trip: Duration) -> Check {
    let skew = match now.duration_since(server_time) {
        Ok(ahead) => ahead,
        Err(behind) => behind.duration(),
    };
    // What the header's resolution and the request's duration can explain.
    let skew = skew.saturating_sub(round_trip + Duration::from_secs(1));
    let hint = "sync the system clock (on WSL2: `sudo hwclock -s`, or restart WSL)";
    if skew >= CLOCK_SKEW_FAIL {
        Check::fail(
            "clock",
            format!("{} s off the homeserver's clock", skew.as_secs()),
            hint,
        )
    } else if skew >= CLOCK_SKEW_WARN {
        Check::warn(
            "clock",
            format!("{} s off the homeserver's clock", skew.as_secs()),
            hint,
        )
    } else {
        Check::ok("clock", "agrees with the homeserver's")
    }
}

fn check_store(state: &AppState) -> Check {
    let dir = &state.config.store_dir;
    let at_rest = if state.config.store_passphrase.is_some() {
        "encrypted with the store passphrase"
    } else {
        "not encrypted at rest"
    };
    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => {
            Check::ok("store", format!("{} ({at_rest})", dir.display()))
        }
        // Created on first use.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Check::ok("store", format!("{} (not created yet)", dir.display()))
        }
        _ => Check::fail(
            "store",
            format!("{} is not a usable directory", dir.display()),
            "check `store_dir` and its permissions",
        ),
    }
}

fn check_log(state: &AppState) -> Check {
    let window = Duration::from_secs(600);
    let errors = state.logs.count_since(Level::ERROR, window);
    let warnings = state.logs.count_since(Level::WARN, window) - errors;
    if errors > 0 {
        Check::warn(
            "log",
            format!("{errors} error(s) and {warnings} warning(s) in the last 10 minutes"),
            "see `ement-e2ee ctl debug logs --level warn`",
        )
    } else {
        Check::ok(
            "log",
            format!("no errors in the last 10 minutes ({warnings} warning(s))"),
        )
    }
}

async fn check_session(state: &AppState, ctx: &Arc<AccountContext>) -> Vec<Check> {
    let mut checks = vec![check_token(ctx).await];
    // Nothing below can be judged with a dead token.
    if checks[0].status == Status::Fail {
        return checks;
    }
    checks.push(check_device_keys(state, ctx).await);
    checks.push(check_one_time_keys(ctx).await);
    checks.push(check_cross_signing(ctx).await);
    checks.push(check_device_verified(state, ctx).await);
    checks.push(check_backup(ctx).await);
    checks.push(check_client_sync(ctx));
    checks.push(check_placeholders(ctx));
    checks
}

async fn check_token(ctx: &AccountContext) -> Check {
    let result = ctx
        .upstream
        .json_request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            &ctx.token,
            None,
        )
        .await;
    match result {
        Ok((status, body)) if status.is_success() => {
            if body["device_id"] == ctx.device_id.as_str() {
                Check::ok("token", "access token is valid")
            } else {
                Check::fail(
                    "token",
                    format!("the token now belongs to device {}", body["device_id"]),
                    "restart the proxy and reconnect ement",
                )
            }
        }
        Ok((status, body)) => Check::fail(
            "token",
            format!(
                "the homeserver rejects the access token ({status} {})",
                body["errcode"]
            ),
            "log in again from ement (through the proxy)",
        ),
        Err(e) => Check::fail(
            "token",
            format!("could not ask the homeserver: {e:#}"),
            "check the network",
        ),
    }
}

/// How to give up a device whose ID is of no use any more.
fn new_device_hint(state: &AppState, ctx: &AccountContext) -> String {
    format!(
        "sign this session out from another client, delete {} and log in again from ement to \
         continue as a new device",
        account_store_dir(&state.config, &ctx.user_id, &ctx.device_id).display()
    )
}

/// Does the homeserver publish the keys this device actually holds?
async fn check_device_keys(state: &AppState, ctx: &AccountContext) -> Check {
    let published =
        device::published_identity(&ctx.upstream, &ctx.token, &ctx.user_id, &ctx.device_id).await;
    let ours = ctx.olm.identity_keys().ed25519.to_base64();
    match published {
        Ok(Some(key)) if key == ours => {
            Check::ok("device_keys", format!("published (ed25519 {ours})"))
        }
        Ok(Some(_)) => Check::fail(
            "device_keys",
            "the homeserver has other keys on record for this device ID than this device holds",
            format!(
                "a device's keys cannot be replaced: {}",
                new_device_hint(state, ctx)
            ),
        ),
        Ok(None) => Check::fail(
            "device_keys",
            "this device's keys are not on the homeserver",
            "they are published when a session starts: reconnect ement (M-x ement-disconnect, \
             M-x ement-connect); if they stay missing see `ement-e2ee ctl debug logs --level warn`",
        ),
        Err(e) => Check::warn(
            "device_keys",
            format!("could not ask the homeserver: {e:#}"),
            "retry later",
        ),
    }
}

async fn check_one_time_keys(ctx: &AccountContext) -> Check {
    // An empty upload is the standard way to ask for the current counts.
    let result = ctx
        .upstream
        .json_request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/upload",
            &ctx.token,
            Some(&json!({})),
        )
        .await;
    match result {
        Ok((status, body)) if status.is_success() => {
            let count = body
                .pointer("/one_time_key_counts/signed_curve25519")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if count == 0 {
                Check::warn(
                    "one_time_keys",
                    "no one-time keys left on the homeserver",
                    "others cannot open new sessions with this device until they are \
                     replenished, which happens on the next sync; if it stays at 0 see the logs",
                )
            } else {
                Check::ok("one_time_keys", format!("{count} on the homeserver"))
            }
        }
        Ok((status, _)) => Check::warn(
            "one_time_keys",
            format!("keys/upload answered {status}"),
            "retry later",
        ),
        Err(e) => Check::warn(
            "one_time_keys",
            format!("keys/upload failed: {e:#}"),
            "retry later",
        ),
    }
}

async fn check_cross_signing(ctx: &AccountContext) -> Check {
    let status = ctx.olm.cross_signing_status().await;
    match (
        status.has_master,
        status.has_self_signing,
        status.has_user_signing,
    ) {
        (true, true, true) => {
            Check::ok("cross_signing", "all three private keys are on this device")
        }
        (false, false, false) => Check::warn(
            "cross_signing",
            "this device has no cross-signing keys",
            "run `ement-e2ee ctl bootstrap` with your recovery key",
        ),
        (master, self_signing, user_signing) => Check::warn(
            "cross_signing",
            format!(
                "only some private keys are here (master: {master}, self-signing: \
                 {self_signing}, user-signing: {user_signing})"
            ),
            "run `ement-e2ee ctl bootstrap` again",
        ),
    }
}

/// Does the device carry a signature of the account's self-signing key that
/// was made over other keys than the device has? Synapse leaves a device
/// ID's signatures in place when the device is signed out, serves them with
/// the keys the ID gets next, and skips every signature uploaded after.
async fn has_stale_cross_signature(ctx: &AccountContext, device: &Device) -> bool {
    if device.is_cross_signed_by_owner() {
        return false;
    }
    let Ok(Some(identity)) = ctx.olm.get_identity(&ctx.user_id, None).await else {
        return false;
    };
    let Some(self_signing_key) = identity
        .own()
        .and_then(|own| own.self_signing_key().get_first_key())
    else {
        return false;
    };
    let key_id = format!("ed25519:{}", self_signing_key.to_base64());
    serde_json::to_value(device.as_device_keys())
        .ok()
        .and_then(|keys| {
            keys["signatures"][ctx.user_id.as_str()]
                .get(&key_id)
                .cloned()
        })
        .is_some()
}

async fn check_device_verified(state: &AppState, ctx: &AccountContext) -> Check {
    let hint =
        "run `ement-e2ee ctl bootstrap`, or `ement-e2ee ctl verify` against a verified device";
    match ctx.olm.get_device(&ctx.user_id, &ctx.device_id, None).await {
        Ok(Some(device)) if device.is_cross_signed_by_owner() => Check::ok(
            "device_verified",
            "cross-signed: other clients show it as verified",
        ),
        Ok(Some(device)) if has_stale_cross_signature(ctx, &device).await => Check::fail(
            "device_verified",
            "the homeserver holds a cross-signing signature for this device ID that does not \
             match the device's keys, and keeps it whatever is signed anew: other clients show \
             this device as unverified, and verifying it again changes nothing",
            format!(
                "this device ID had other keys once: {}",
                new_device_hint(state, ctx)
            ),
        ),
        Ok(Some(_)) => Check::warn(
            "device_verified",
            "not cross-signed: other clients show this device as unverified",
            hint,
        ),
        Ok(None) => Check::warn(
            "device_verified",
            "this device is not in its own device list yet",
            "it appears after the first key query; retry in a moment",
        ),
        Err(e) => Check::fail(
            "device_verified",
            format!("store error: {e}"),
            "see the logs",
        ),
    }
}

async fn check_backup(ctx: &AccountContext) -> Check {
    let backups = ctx.olm.backup_machine();
    let enabled = backups.enabled().await;
    let local_version = backups
        .get_backup_keys()
        .await
        .ok()
        .and_then(|keys| keys.backup_version);
    let server_version = match ctx
        .upstream
        .json_request(
            reqwest::Method::GET,
            "/_matrix/client/v3/room_keys/version",
            &ctx.token,
            None,
        )
        .await
    {
        Ok((status, body)) if status.is_success() => {
            body["version"].as_str().map(ToOwned::to_owned)
        }
        Ok((status, _)) if status == reqwest::StatusCode::NOT_FOUND => None,
        Ok((status, _)) => {
            return Check::warn(
                "backup",
                format!("room_keys/version answered {status}"),
                "retry later",
            );
        }
        Err(e) => {
            return Check::warn(
                "backup",
                format!("could not ask the homeserver: {e:#}"),
                "retry later",
            );
        }
    };

    match (enabled, local_version, server_version) {
        (true, Some(local), Some(server)) if local == server => {
            let counts = backups.room_key_counts().await.ok();
            let progress = counts.map_or(String::new(), |counts| {
                format!(
                    ", {} of {} room keys uploaded",
                    counts.backed_up, counts.total
                )
            });
            Check::ok("backup", format!("version {server}{progress}"))
        }
        (true, local, Some(server)) => Check::warn(
            "backup",
            format!(
                "this device backs up to version {}, the account is now on version {server}",
                local.as_deref().unwrap_or("?")
            ),
            "the backup was reset elsewhere: run `ement-e2ee ctl bootstrap` again",
        ),
        (true, _, None) => Check::warn(
            "backup",
            "this device has a backup key but the account has no backup any more",
            "set up key backup again in another client, then `ement-e2ee ctl bootstrap`",
        ),
        (false, _, Some(server)) => Check::warn(
            "backup",
            format!("the account has a key backup (version {server}) this device does not use"),
            "run `ement-e2ee ctl bootstrap` to restore from it and back up new keys",
        ),
        (false, _, None) => Check::ok("backup", "the account has no key backup"),
    }
}

/// The client's sync is what moves everything: to-device messages (room
/// keys, verification) only reach the proxy inside ement's /sync responses.
fn check_client_sync(ctx: &AccountContext) -> Check {
    let hint = "keys and verification only move while ement is connected and syncing";
    match age_secs(ctx.sync.stats().last_client_sync) {
        Some(age) if age <= CLIENT_SYNC_STALE.as_secs() => {
            Check::ok("client_sync", format!("ement synced {age} s ago"))
        }
        Some(age) => Check::warn(
            "client_sync",
            format!("ement last synced {age} s ago"),
            hint,
        ),
        None => Check::warn(
            "client_sync",
            "ement has not synced since the proxy started",
            hint,
        ),
    }
}

fn check_placeholders(ctx: &AccountContext) -> Check {
    let pending = ctx.repairs.pending();
    if pending.is_empty() {
        return Check::ok("placeholders", "no message is waiting for a key");
    }
    let rooms: std::collections::BTreeSet<&str> = pending
        .iter()
        .map(|repair| repair.room_id.as_str())
        .collect();
    Check::warn(
        "placeholders",
        format!(
            "{} message(s) in {} room(s) are shown as undecryptable",
            pending.len(),
            rooms.len()
        ),
        "they repair themselves when a key arrives; `ement-e2ee ctl debug room ROOM` lists \
         them and `ement-e2ee ctl debug event ROOM EVENT` says what each is missing",
    )
}

/// GET /_ement/debug/session — one session in detail.
pub async fn session(state: &AppState, ctx: &Arc<AccountContext>) -> Value {
    let stats = ctx.sync.stats();
    let identity = ctx.olm.identity_keys();
    let cross_signing = ctx.olm.cross_signing_status().await;
    let backups = ctx.olm.backup_machine();
    let counts = backups.room_key_counts().await.ok();
    let tracked_users = ctx.olm.tracked_users().await.map(|users| users.len()).ok();
    let flows = ctx.olm.get_verification_requests(&ctx.user_id).len();
    json!({
        "user_id": ctx.user_id,
        "device_id": ctx.device_id,
        "identity_keys": {
            "ed25519": identity.ed25519.to_base64(),
            "curve25519": identity.curve25519.to_base64(),
        },
        "store": crate::crypto::machine::account_store_dir(&state.config, &ctx.user_id, &ctx.device_id),
        "cross_signing": {
            "has_master": cross_signing.has_master,
            "has_self_signing": cross_signing.has_self_signing,
            "has_user_signing": cross_signing.has_user_signing,
        },
        "backup": {
            "enabled": backups.enabled().await,
            "version": backups.get_backup_keys().await.ok().and_then(|keys| keys.backup_version),
            "room_keys": counts.as_ref().map(|counts| counts.total),
            "room_keys_backed_up": counts.as_ref().map(|counts| counts.backed_up),
        },
        "client_sync": {
            "count": stats.client_syncs,
            "last_secs_ago": age_secs(stats.last_client_sync),
        },
        "to_device": {
            "processed": stats.to_device_events,
            "duplicates_dropped": stats.to_device_duplicates,
            "room_keys_received": stats.room_keys_received,
        },
        "tracked_users": tracked_users,
        "pending_placeholders": ctx.repairs.pending().len(),
        "room_keys_requested": ctx.rooms.requested_sessions.lock().await.len(),
        "active_verifications": flows,
    })
}

/// GET /_ement/debug/devices — a user's devices as this device knows them.
pub async fn devices(ctx: &AccountContext, user: &UserId) -> anyhow::Result<Value> {
    let known = ctx.olm.get_user_devices(user, None).await?;
    let mut devices: Vec<Value> = known
        .devices()
        .map(|device| {
            json!({
                "device_id": device.device_id(),
                "display_name": device.display_name(),
                "ed25519": device.ed25519_key().map(|key| key.to_base64()),
                "this_device": user == ctx.user_id && device.device_id() == ctx.device_id,
                "verified": device.is_verified(),
                "cross_signed": device.is_cross_signed_by_owner(),
                "locally_trusted": device.is_locally_trusted(),
                "blacklisted": device.is_blacklisted(),
            })
        })
        .collect();
    devices.sort_by(|a, b| a["device_id"].as_str().cmp(&b["device_id"].as_str()));
    let tracked = ctx.olm.tracked_users().await?.contains(user);
    Ok(json!({ "user_id": user, "tracked": tracked, "devices": devices }))
}

/// GET /_ement/debug/room/{room} — what the proxy knows and would do for a
/// room.
pub async fn room(ctx: &Arc<AccountContext>, room_id: &OwnedRoomId) -> anyhow::Result<Value> {
    let settings = ctx.olm.room_settings(room_id).await?;
    let encryption = match &settings {
        Some(settings) => json!({
            "encrypted": true,
            "algorithm": settings.algorithm.to_string(),
            "rotation_period_secs": settings.session_rotation_period.map(|d| d.as_secs()),
            "rotation_period_messages": settings.session_rotation_period_messages,
        }),
        None if ctx.rooms.is_known_unencrypted(room_id).await => json!({ "encrypted": false }),
        // Not asked yet; a send would look it up.
        None => json!({ "encrypted": null }),
    };

    // Who would a message be encrypted for?
    let members = match rooms::joined_members(ctx, room_id).await {
        Ok(members) => {
            let mut rows = Vec::new();
            for member in &members {
                let devices = ctx.olm.get_user_devices(member, None).await?;
                let total = devices.devices().count();
                let verified = devices
                    .devices()
                    .filter(|device| device.is_verified())
                    .count();
                rows.push(
                    json!({ "user_id": member, "devices": total, "verified_devices": verified }),
                );
            }
            rows.sort_by(|a, b| a["user_id"].as_str().cmp(&b["user_id"].as_str()));
            json!(rows)
        }
        Err(e) => json!({ "error": format!("{e:#}") }),
    };

    let placeholders: Vec<Value> = ctx
        .repairs
        .pending()
        .into_iter()
        .filter(|repair| &repair.room_id == room_id)
        .map(|repair| json!({ "event_id": repair.event_id, "session_id": repair.session_id }))
        .collect();

    Ok(json!({
        "room_id": room_id,
        "joined_per_client_sync": ctx.rooms.last_unread_notifications(room_id).is_some(),
        "encryption": encryption,
        "history_visibility": ctx.rooms.history_visibility(room_id).await.map(|v| v.to_string()),
        "members": members,
        "pending_placeholders": placeholders,
    }))
}

/// GET /_ement/debug/event/{room}/{event} — fetch one event and explain why
/// it can or cannot be decrypted.
pub async fn event(
    ctx: &Arc<AccountContext>,
    room_id: &OwnedRoomId,
    event_id: &str,
) -> anyhow::Result<Value> {
    let path = format!(
        "/_matrix/client/v3/rooms/{}/event/{}",
        enc(room_id.as_str()),
        enc(event_id)
    );
    let (status, raw) = ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await?;
    anyhow::ensure!(
        status.is_success(),
        "the homeserver does not hand out this event ({status} {})",
        raw["errcode"].as_str().unwrap_or_default()
    );

    let mut report = json!({
        "room_id": room_id,
        "event_id": event_id,
        "sender": raw["sender"],
        "type": raw["type"],
    });
    if raw["type"] != "m.room.encrypted" {
        report["outcome"] = "not_encrypted".into();
        report["explanation"] =
            "this event was sent in the clear; there is nothing to decrypt".into();
        return Ok(report);
    }
    let content = &raw["content"];
    report["algorithm"] = content["algorithm"].clone();
    report["session_id"] = content["session_id"].clone();
    report["sender_device"] = content["device_id"].clone();

    // Do we hold the megolm session at all?
    let session = match content["session_id"].as_str() {
        Some(session_id) => {
            ctx.olm
                .store()
                .get_inbound_group_session(room_id, session_id)
                .await?
        }
        None => None,
    };
    report["room_key"] = match &session {
        Some(session) => json!({
            "held": true,
            "first_known_index": session.first_known_index(),
            "imported": session.has_been_imported(),
            "backed_up": session.backed_up(),
        }),
        None => json!({ "held": false }),
    };

    match decrypt::decrypt(ctx, room_id, &raw).await {
        Decryption::Decrypted(plain) => {
            report["outcome"] = "decrypted".into();
            report["decrypted_type"] = plain["type"].clone();
            report["encryption_info"] = plain["unsigned"]["ement_e2ee"]["encryption_info"].clone();
            report["explanation"] = "the event decrypts".into();
        }
        Decryption::Undecryptable {
            reason, session_id, ..
        } => {
            report["outcome"] = "undecryptable".into();
            report["reason"] = reason.clone().into();
            let requested = match &session_id {
                Some(id) => ctx.rooms.requested_sessions.lock().await.contains(id),
                None => false,
            };
            report["key_requested"] = requested.into();
            let in_backup = match &session_id {
                Some(id) => key_in_backup(ctx, room_id, id).await,
                None => None,
            };
            report["key_in_server_backup"] = in_backup.into();
            let (explanation, hint) = explain_undecryptable(&reason, session.is_some(), in_backup);
            report["explanation"] = explanation.into();
            report["hint"] = hint.into();
        }
        Decryption::Untouched => {
            report["outcome"] = "error".into();
            report["explanation"] =
                "the event is malformed or the store failed; see `ement-e2ee ctl debug logs`"
                    .into();
        }
    }
    Ok(report)
}

/// Is this room key in the account's server-side backup? Asks for the
/// account's current backup, whether or not this device uses it yet. None if
/// there is no backup or the homeserver cannot say.
async fn key_in_backup(
    ctx: &AccountContext,
    room_id: &OwnedRoomId,
    session_id: &str,
) -> Option<bool> {
    let (status, backup) = ctx
        .upstream
        .json_request(
            reqwest::Method::GET,
            "/_matrix/client/v3/room_keys/version",
            &ctx.token,
            None,
        )
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    let path = format!(
        "/_matrix/client/v3/room_keys/keys/{}/{}?version={}",
        enc(room_id.as_str()),
        enc(session_id),
        enc(backup["version"].as_str()?)
    );
    let (status, _) = ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await
        .ok()?;
    if status.is_success() {
        Some(true)
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Some(false)
    } else {
        None
    }
}

/// Turn the SDK's reason into what it means here and what to do about it.
fn explain_undecryptable(
    reason: &str,
    key_held: bool,
    in_backup: Option<bool>,
) -> (&'static str, &'static str) {
    if key_held {
        return (
            "this device has the room key, but only from a later point in the session than \
             this message (or the message is corrupt)",
            "import a key export from a device that can read it (`ement-e2ee ctl keys import`)",
        );
    }
    if in_backup == Some(true) {
        return (
            "this device was never given the room key, but the key is in your server-side backup",
            "run `ement-e2ee ctl bootstrap`: it restores the backup and repairs the message",
        );
    }
    if reason.contains("Malformed") || reason.contains("Deserialization") {
        return (
            "the event is not a well-formed encrypted message",
            "nothing can decrypt it; the sender's client produced it this way",
        );
    }
    (
        "this device was never given the room key for this message: it was sent before the \
         device existed, or the sender's client did not share the key with it",
        "a key request has gone to your other devices. Otherwise: `ement-e2ee ctl bootstrap` \
         (restores your backup), `ement-e2ee ctl keys import` (from an export made on a device \
         that can read it), or ask the sender to send it again",
    )
}

/// GET /_ement/debug/logs — the in-memory tail of the log.
pub fn logs(state: &AppState, level: Level, limit: usize) -> Value {
    let lines: Vec<Value> = state
        .logs
        .tail(level, limit)
        .into_iter()
        .map(|line| {
            json!({
                "time": unix_secs(line.time),
                "secs_ago": line.time.elapsed().unwrap_or_default().as_secs(),
                "level": line.level,
                "target": line.target,
                "message": line.message,
            })
        })
        .collect();
    json!({ "lines": lines })
}

/// GET /_ement/debug/report — everything in one document, for a bug report.
/// Contains Matrix IDs (users, devices, rooms, events) and public keys; no
/// tokens, passphrases or private keys.
pub async fn report(state: &AppState) -> Value {
    let mut sessions = Vec::new();
    for ctx in state.sessions.list().await {
        let own_devices = match devices(&ctx, &ctx.user_id).await {
            Ok(devices) => devices,
            Err(e) => json!({ "error": format!("{e:#}") }),
        };
        let placeholders: Vec<Value> = ctx
            .repairs
            .pending()
            .into_iter()
            .map(|repair| {
                json!({
                    "room_id": repair.room_id,
                    "event_id": repair.event_id,
                    "session_id": repair.session_id,
                })
            })
            .collect();
        sessions.push(json!({
            "session": session(state, &ctx).await,
            "devices": own_devices,
            "pending_placeholders": placeholders,
        }));
    }
    json!({
        "generated_at": unix_secs(SystemTime::now()),
        "check": check(state).await,
        "sessions": sessions,
        "logs": logs(state, Level::INFO, 200),
    })
}

pub fn parse_user(user: &str) -> anyhow::Result<OwnedUserId> {
    user.parse()
        .map_err(|_| anyhow::anyhow!("{user:?} is not a Matrix user ID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_check_allows_for_header_resolution_and_latency() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let at = |offset: i64| {
            if offset >= 0 {
                now + Duration::from_secs(offset as u64)
            } else {
                now - Duration::from_secs(offset.unsigned_abs())
            }
        };
        let quick = Duration::from_millis(50);
        assert_eq!(clock_check(now, at(0), quick).status, Status::Ok);
        assert_eq!(clock_check(now, at(-20), quick).status, Status::Ok);
        // Either direction counts.
        assert_eq!(clock_check(now, at(-45), quick).status, Status::Warn);
        assert_eq!(clock_check(now, at(45), quick).status, Status::Warn);
        assert_eq!(clock_check(now, at(-900), quick).status, Status::Fail);
        // A slow request explains a late-looking header.
        let slow = Duration::from_secs(40);
        assert_eq!(clock_check(now, at(-45), slow).status, Status::Ok);
        let check = clock_check(now, at(400), quick);
        assert!(check.detail.contains("s off the homeserver's clock"));
        assert!(check.hint.unwrap().contains("hwclock"));
    }

    #[test]
    fn undecryptable_explanations_name_the_right_remedy() {
        let (what, hint) = explain_undecryptable("MissingMegolmSession", false, Some(true));
        assert!(what.contains("server-side backup"));
        assert!(hint.contains("ctl bootstrap"));

        let (what, hint) = explain_undecryptable("MissingMegolmSession", false, Some(false));
        assert!(what.contains("never given the room key"));
        assert!(hint.contains("keys import"));

        // Holding the key and still failing is a different problem from
        // lacking it, whatever the backup says.
        let (what, _) = explain_undecryptable("UnknownMegolmMessageIndex", true, Some(true));
        assert!(what.contains("later point in the session"));

        let (what, hint) = explain_undecryptable("MalformedEncryptedEvent", false, None);
        assert!(what.contains("not a well-formed"));
        assert!(hint.contains("nothing can decrypt it"));
    }
}
