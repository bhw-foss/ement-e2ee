//! One device ID, one set of identity keys.
//!
//! The identity keys of a device cannot be replaced. Clients that know the
//! old ones reject the new (matrix-sdk-crypto logs "Rejecting device update"
//! and goes on encrypting for the old), and Synapse keeps the cross-signing
//! signature made over the old ones while skipping every later one. ement
//! makes that easy to run into: it asks for the same device ID on every
//! login, whatever has become of the store. So the proxy
//!
//! - chooses the device ID of a login itself: that of the store it has for
//!   the login, or else a new one from the homeserver;
//! - publishes a store's device keys again when the homeserver has lost them
//!   (the session was signed out from another client, and the client logged
//!   in again);
//! - refuses a session whose device has keys on the homeserver that are not
//!   the store's, rather than replace them.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context as _;
use ruma::{DeviceId, OwnedDeviceId, OwnedUserId, UserId};
use serde_json::{Value, json};

use crate::session::{AccountContext, sanitize_for_path};
use crate::upstream::Upstream;

/// The crypto store's database, as matrix-sdk-sqlite names it.
const STORE_FILE: &str = "matrix-sdk-crypto.sqlite3";

/// In a device's store directory: which device ID the client asks for at
/// login when it means this device.
const LOGIN_FILE: &str = "login.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginRecord {
    device_id: String,
    requested_device_id: String,
}

/// Is there a crypto store in this directory?
pub fn has_store(dir: &Path) -> bool {
    dir.join(STORE_FILE).is_file()
}

/// What to make of a login request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LoginPlan {
    /// The body to send in place of the client's, where the device ID is
    /// not the one the client asked for.
    pub body: Option<Vec<u8>>,
    /// The device ID the client asked for, if the choice was the proxy's.
    pub requested: Option<String>,
}

/// Decide which device a login continues. A login that names no device, or
/// no user to look up a store for, is left as it is.
pub fn plan_login(store_dir: &Path, body: &[u8]) -> LoginPlan {
    let Ok(mut login) = serde_json::from_slice::<Value>(body) else {
        return LoginPlan::default();
    };
    let Some(requested) = login
        .get("device_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return LoginPlan::default();
    };
    // Who logs in is certain only once the homeserver has answered; the
    // store has to be found from what the client says.
    let Some(user) = login
        .pointer("/identifier/user")
        .or_else(|| login.get("user"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return LoginPlan::default();
    };

    match device_id_for_login(store_dir, &user, &requested) {
        Some(device_id) if device_id == requested => {
            return LoginPlan {
                body: None,
                requested: Some(requested),
            };
        }
        Some(device_id) => login["device_id"] = device_id.into(),
        // A new device: the homeserver picks an ID that has never had keys.
        None => {
            if let Some(login) = login.as_object_mut() {
                login.remove("device_id");
            }
        }
    }
    LoginPlan {
        body: serde_json::to_vec(&login).ok(),
        requested: Some(requested),
    }
}

/// The device a login continues: the one whose store is here and which the
/// client means by `requested`. None if there is no such store.
fn device_id_for_login(store_dir: &Path, user: &str, requested: &str) -> Option<String> {
    let mut newest: Option<(SystemTime, String)> = None;
    for user_dir in subdirs(store_dir) {
        if !names_user(&user_dir, user) {
            continue;
        }
        // A store from before the proxy chose device IDs sits under the
        // client's own.
        if has_store(&user_dir.join(sanitize_for_path(requested))) {
            return Some(requested.to_owned());
        }
        for device_dir in subdirs(&user_dir) {
            if !has_store(&device_dir) {
                continue;
            }
            let Some(record) = read_login_record(&device_dir) else {
                continue;
            };
            if record.requested_device_id != requested {
                continue;
            }
            let used = std::fs::metadata(device_dir.join(STORE_FILE))
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            if newest.as_ref().is_none_or(|(latest, _)| used > *latest) {
                newest = Some((used, record.device_id));
            }
        }
    }
    newest.map(|(_, device_id)| device_id)
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.is_dir())
        .collect()
}

/// Is this the store directory of the user a client logs in as with `login`
/// (a user ID, or only its local part)?
fn names_user(user_dir: &Path, login: &str) -> bool {
    let Some(name) = user_dir.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(name) = name.strip_prefix('@') else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let login = sanitize_for_path(login.strip_prefix('@').unwrap_or(login)).to_ascii_lowercase();
    if login.contains(':') {
        name == login
    } else {
        name.split_once(':')
            .is_some_and(|(local_part, _)| local_part == login)
    }
}

fn read_login_record(device_dir: &Path) -> Option<LoginRecord> {
    let bytes = std::fs::read(device_dir.join(LOGIN_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Note, in a device's store directory, which device ID the client asks for
/// when it means this device.
pub fn record_login(device_dir: &Path, device_id: &str, requested: &str) -> anyhow::Result<()> {
    let record = LoginRecord {
        device_id: device_id.to_owned(),
        requested_device_id: requested.to_owned(),
    };
    // The login is noted before its store is made.
    std::fs::create_dir_all(device_dir)
        .with_context(|| format!("failed to create {}", device_dir.display()))?;
    let path = device_dir.join(LOGIN_FILE);
    std::fs::write(&path, serde_json::to_vec_pretty(&record)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// The ed25519 identity key the homeserver publishes for a device, if any.
pub async fn published_identity(
    upstream: &Upstream,
    token: &str,
    user_id: &UserId,
    device_id: &DeviceId,
) -> anyhow::Result<Option<String>> {
    let body = json!({ "device_keys": { user_id.as_str(): [device_id.as_str()] } });
    let (status, response) = upstream
        .json_request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            token,
            Some(&body),
        )
        .await
        .context("keys/query failed")?;
    anyhow::ensure!(status.is_success(), "keys/query answered {status}");
    let key = response
        .get("device_keys")
        .and_then(|users| users.get(user_id.as_str()))
        .and_then(|devices| devices.get(device_id.as_str()))
        .and_then(|device| device.get("keys"))
        .and_then(|keys| keys.get(format!("ed25519:{device_id}")))
        .and_then(Value::as_str);
    Ok(key.map(ToOwned::to_owned))
}

/// Publish this store's device keys again, for a device the homeserver has
/// lost the keys of. The olm account counts them as published and would
/// never send them a second time.
pub async fn republish(ctx: &AccountContext) -> anyhow::Result<()> {
    let device = ctx
        .olm
        .get_device(&ctx.user_id, &ctx.device_id, None)
        .await?
        .context("this device is missing from its own store")?;
    let body = json!({ "device_keys": device.as_device_keys() });
    let (status, response) = ctx
        .upstream
        .json_request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/upload",
            &ctx.token,
            Some(&body),
        )
        .await?;
    anyhow::ensure!(
        status.is_success(),
        "keys/upload answered {status}: {response}"
    );
    Ok(())
}

/// A session the proxy does not serve: the homeserver has identity keys for
/// its device that are not the ones in the store.
#[derive(Debug, Clone)]
pub struct DeviceConflict {
    pub user_id: OwnedUserId,
    pub device_id: OwnedDeviceId,
    /// The store holding other keys; None if the device has no store here.
    pub store: Option<PathBuf>,
}

impl DeviceConflict {
    /// What is wrong.
    pub fn detail(&self) -> String {
        let Self {
            user_id, device_id, ..
        } = self;
        match &self.store {
            None => format!(
                "the homeserver has encryption keys for device {device_id} of {user_id} that \
                 this proxy does not hold (its store was deleted, or another program set the \
                 device up)"
            ),
            Some(store) => format!(
                "the homeserver publishes other encryption keys for device {device_id} of \
                 {user_id} than the store in {} holds",
                store.display()
            ),
        }
    }

    /// What to do about it.
    pub fn hint(&self) -> String {
        let again = "log in again to continue as a new device (in ement: C-u M-x ement-connect)";
        match &self.store {
            None => format!("a device's keys cannot be replaced: {again}"),
            Some(store) => format!(
                "a device's keys cannot be replaced: move {} away and {again}",
                store.display()
            ),
        }
    }
}

impl std::fmt::Display for DeviceConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; {}", self.detail(), self.hint())
    }
}

impl std::error::Error for DeviceConflict {}

/// A new device that got no keys yet, because the homeserver did not say
/// whether the device ID already has some.
#[derive(Debug, thiserror::Error)]
#[error(
    "could not find out whether device {device_id} already has encryption keys, so none were \
     published for it yet: {reason}"
)]
pub struct DeviceUnchecked {
    pub device_id: OwnedDeviceId,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMENT_ID: &str = "03f8f9640d1c7a5b9e2f4c6a8b0d2e4f6a8c0e2b4d6f8a1c3e5b7d9f1a3c5e7b";

    /// Make a store for a device, as a login that asked for `requested` and
    /// got `device_id` leaves it behind.
    fn store(root: &Path, user: &str, device_id: &str, requested: Option<&str>) -> PathBuf {
        let dir = root
            .join(sanitize_for_path(user))
            .join(sanitize_for_path(device_id));
        if let Some(requested) = requested {
            record_login(&dir, device_id, requested).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(STORE_FILE), b"").unwrap();
        dir
    }

    fn login(user: &str, device_id: Option<&str>) -> Vec<u8> {
        let mut body = json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.user", "user": user },
            "password": "hunter2",
        });
        if let Some(device_id) = device_id {
            body["device_id"] = device_id.into();
        }
        serde_json::to_vec(&body).unwrap()
    }

    fn sent(plan: &LoginPlan) -> Value {
        serde_json::from_slice(plan.body.as_deref().expect("a rewritten body")).unwrap()
    }

    #[test]
    fn a_login_without_a_store_gets_a_new_device() {
        let root = tempfile::tempdir().unwrap();
        let plan = plan_login(root.path(), &login("@ben:example.org", Some(EMENT_ID)));
        assert_eq!(plan.requested.as_deref(), Some(EMENT_ID));
        let body = sent(&plan);
        // The homeserver is left to choose; everything else goes as it came.
        assert_eq!(body.get("device_id"), None);
        assert_eq!(body["password"], "hunter2");
        assert_eq!(body["identifier"]["user"], "@ben:example.org");

        // Other people's stores, and directories without a store, do not count.
        store(
            root.path(),
            "@eve:example.org",
            "EVESDEVICE",
            Some(EMENT_ID),
        );
        let empty = store(root.path(), "@ben:example.org", "GONE", Some(EMENT_ID));
        std::fs::remove_file(empty.join(STORE_FILE)).unwrap();
        let plan = plan_login(root.path(), &login("@ben:example.org", Some(EMENT_ID)));
        assert_eq!(sent(&plan).get("device_id"), None);
    }

    #[test]
    fn a_login_continues_the_device_its_store_was_made_for() {
        let root = tempfile::tempdir().unwrap();
        store(root.path(), "@ben:example.org", "ASSIGNED", Some(EMENT_ID));
        let plan = plan_login(root.path(), &login("@ben:example.org", Some(EMENT_ID)));
        assert_eq!(sent(&plan)["device_id"], "ASSIGNED");
        assert_eq!(plan.requested.as_deref(), Some(EMENT_ID));

        // The user may be named as typed: any case, or the local part alone.
        for user in ["@Ben:Example.org", "ben", "@ben"] {
            let plan = plan_login(root.path(), &login(user, Some(EMENT_ID)));
            assert_eq!(sent(&plan)["device_id"], "ASSIGNED", "{user}");
        }
        // The legacy `user` field names the user too.
        let legacy = json!({ "type": "m.login.password", "user": "ben", "device_id": EMENT_ID });
        let plan = plan_login(root.path(), &serde_json::to_vec(&legacy).unwrap());
        assert_eq!(sent(&plan)["device_id"], "ASSIGNED");

        // Another device ID (ement on another machine) is another device.
        let plan = plan_login(root.path(), &login("@ben:example.org", Some("OTHERHASH")));
        assert_eq!(sent(&plan).get("device_id"), None);
        // So is another user, even one whose name starts the same.
        for user in ["@benjamin:example.org", "@ben:example.com", "be"] {
            let plan = plan_login(root.path(), &login(user, Some(EMENT_ID)));
            assert_eq!(sent(&plan).get("device_id"), None, "{user}");
        }
    }

    #[test]
    fn a_store_under_the_requested_id_itself_is_continued_untouched() {
        let root = tempfile::tempdir().unwrap();
        store(root.path(), "@ben:example.org", EMENT_ID, None);
        // Even next to a newer store recorded for the same request.
        store(root.path(), "@ben:example.org", "ASSIGNED", Some(EMENT_ID));
        let plan = plan_login(root.path(), &login("@ben:example.org", Some(EMENT_ID)));
        assert_eq!(
            plan,
            LoginPlan {
                body: None,
                requested: Some(EMENT_ID.to_owned())
            }
        );
    }

    #[test]
    fn the_store_last_used_wins() {
        let root = tempfile::tempdir().unwrap();
        let old = store(root.path(), "@ben:example.org", "OLD", Some(EMENT_ID));
        let new = store(root.path(), "@ben:example.org", "NEW", Some(EMENT_ID));
        let touch = |dir: &Path, secs: u64| {
            let file = std::fs::File::options()
                .write(true)
                .open(dir.join(STORE_FILE))
                .unwrap();
            file.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
                .unwrap();
        };
        touch(&old, 1_000);
        touch(&new, 2_000);
        let plan = plan_login(root.path(), &login("@ben:example.org", Some(EMENT_ID)));
        assert_eq!(sent(&plan)["device_id"], "NEW");
        touch(&old, 3_000);
        let plan = plan_login(root.path(), &login("@ben:example.org", Some(EMENT_ID)));
        assert_eq!(sent(&plan)["device_id"], "OLD");
    }

    #[test]
    fn logins_the_proxy_cannot_place_are_left_alone() {
        let root = tempfile::tempdir().unwrap();
        store(root.path(), "@ben:example.org", "ASSIGNED", Some(EMENT_ID));
        let untouched = LoginPlan::default();
        // No device asked for: nothing to decide.
        assert_eq!(
            plan_login(root.path(), &login("@ben:example.org", None)),
            untouched
        );
        // No user to look up a store for (a login by e-mail address).
        let by_mail = json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.thirdparty", "medium": "email", "address": "b@x.org" },
            "device_id": EMENT_ID,
        });
        assert_eq!(
            plan_login(root.path(), &serde_json::to_vec(&by_mail).unwrap()),
            untouched
        );
        // Not JSON at all: the homeserver's to reject.
        assert_eq!(plan_login(root.path(), b"device_id=x"), untouched);
        // No store directory yet.
        let plan = plan_login(&root.path().join("missing"), &login("ben", Some(EMENT_ID)));
        assert_eq!(sent(&plan).get("device_id"), None);
    }

    #[test]
    fn conflicts_say_what_to_do() {
        let conflict = DeviceConflict {
            user_id: "@ben:example.org".parse().unwrap(),
            device_id: "ABCDEF".into(),
            store: None,
        };
        let text = conflict.to_string();
        assert!(text.contains("device ABCDEF of @ben:example.org"), "{text}");
        assert!(text.contains("log in again"), "{text}");
        assert!(text.contains("C-u M-x ement-connect"), "{text}");

        let conflict = DeviceConflict {
            store: Some("/stores/@ben:example.org/ABCDEF".into()),
            ..conflict
        };
        let hint = conflict.hint();
        assert!(
            hint.contains("move /stores/@ben:example.org/ABCDEF away"),
            "{hint}"
        );
        assert!(hint.contains("log in again"), "{hint}");
    }
}
