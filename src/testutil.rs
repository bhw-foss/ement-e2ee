//! Test-only harness: a fake homeserver implementing just enough of the
//! client-server API for matrix-sdk-crypto to run real key exchanges, plus a
//! proxy instance wired to it. Both speak real HTTP over loopback, so tests
//! drive the proxy exactly the way ement does.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, header};
use axum::response::Response;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};

use crate::config::Config;
use crate::crypto::machine::enc;
use crate::proxy::{self, AppState};

pub const SERVER_NAME: &str = "hs.test";
pub const ALICE: &str = "@alice:hs.test";
pub const BOB: &str = "@bob:hs.test";

/// One request as the homeserver saw it.
#[derive(Clone)]
pub struct Recorded {
    pub method: Method,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

#[derive(Clone)]
pub struct Media {
    pub content_type: Option<String>,
    pub filename: Option<String>,
    pub bytes: Vec<u8>,
}

struct StoredEvent {
    seq: u64,
    sender_device: String,
    txn_id: String,
    /// The event in /messages format (with room_id, without unsigned).
    json: Value,
}

#[derive(Default)]
struct Room {
    encryption: Option<Value>,
    members: Vec<String>,
    timeline: Vec<StoredEvent>,
}

#[derive(Default)]
pub struct Backup {
    pub version: String,
    pub auth_data: Value,
    /// room_id -> session_id -> KeyBackupData
    pub rooms: BTreeMap<String, BTreeMap<String, Value>>,
}

#[derive(Default)]
pub struct HsState {
    seq: u64,
    /// token -> (user_id, device_id)
    tokens: HashMap<String, (String, String)>,
    /// user_id -> (device_id, token) handed out by POST /login
    logins: HashMap<String, (String, String)>,
    device_keys: BTreeMap<String, BTreeMap<String, Value>>,
    one_time_keys: HashMap<(String, String), BTreeMap<String, Value>>,
    fallback_keys: HashMap<(String, String), BTreeMap<String, Value>>,
    /// (seq, user_id) for device_lists.changed
    device_changes: Vec<(u64, String)>,
    /// Pending to-device events with their stream position; delivered on
    /// every sync until a `since` token at or past that position acks them.
    to_device: HashMap<(String, String), Vec<(u64, Value)>>,
    /// Set by `sync` when a long-pollable request found nothing new.
    idle: bool,
    /// Served at /.well-known/matrix/client when set.
    pub well_known: Option<Value>,
    /// Answer /keys/query with an error (a homeserver in trouble).
    pub fail_keys_query: bool,
    /// Leave `device_one_time_keys_count` out of sync responses, as some
    /// homeservers do when nothing changed.
    pub omit_one_time_key_counts: bool,
    rooms: BTreeMap<String, Room>,
    media: HashMap<String, Media>,
    /// (user_id, event type) -> content
    pub account_data: HashMap<(String, String), Value>,
    /// user_id -> {master_key, self_signing_key, user_signing_key}
    pub cross_signing: HashMap<String, Value>,
    pub backup: Option<Backup>,
    pub requests: Vec<Recorded>,
    /// Swallow to-device messages instead of delivering them (lost room keys).
    pub drop_to_device: bool,
    /// Keep to-device messages back until `release_to_device` (late room keys).
    pub hold_to_device: bool,
    held_to_device: Vec<((String, String), Value)>,
}

fn json_response(status: u16, body: Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn matrix_error(status: u16, errcode: &str) -> Response {
    json_response(status, json!({ "errcode": errcode, "error": errcode }))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| percent_decode_str(v).decode_utf8_lossy().into_owned())
    })
}

impl HsState {
    /// The device keys a device has published.
    pub fn device_keys(&self, user: &str, device: &str) -> Value {
        self.device_keys[user][device].clone()
    }

    fn respond(&mut self, req: &Recorded, token: Option<&str>) -> Response {
        let decoded: Vec<String> = req
            .path
            .trim_start_matches('/')
            .split('/')
            .map(|s| percent_decode_str(s).decode_utf8_lossy().into_owned())
            .collect();
        let segments: Vec<&str> = decoded.iter().map(String::as_str).collect();
        let method = req.method.as_str();

        // Endpoints that take no access token.
        match (method, segments.as_slice()) {
            ("GET", ["_matrix", "client", "versions"]) => {
                return json_response(200, json!({ "versions": ["v1.11"] }));
            }
            ("POST", ["_matrix", "client", _, "login"]) => return self.login(&req.json()),
            ("GET", [".well-known", "matrix", "client"]) => {
                return match &self.well_known {
                    Some(body) => json_response(200, body.clone()),
                    None => matrix_error(404, "M_NOT_FOUND"),
                };
            }
            // Like current homeservers, serve media only on the authenticated
            // endpoint; the legacy one is frozen.
            ("GET", ["_matrix", "media", _, "download", ..]) => {
                return matrix_error(404, "M_NOT_FOUND");
            }
            _ => {}
        }

        let Some((user, device)) = token.and_then(|t| self.tokens.get(t).cloned()) else {
            return matrix_error(401, "M_UNKNOWN_TOKEN");
        };

        match (method, segments.as_slice()) {
            ("POST", ["_matrix", "media", _, "upload"]) => self.upload(req),
            ("GET", ["_matrix", "client", _, "media", "download", server, id, ..]) => {
                match self.media.get(&format!("mxc://{server}/{id}")) {
                    Some(media) => Response::builder()
                        .status(200)
                        .header(
                            header::CONTENT_TYPE,
                            media
                                .content_type
                                .as_deref()
                                .unwrap_or("application/octet-stream"),
                        )
                        .body(Body::from(media.bytes.clone()))
                        .unwrap(),
                    None => matrix_error(404, "M_NOT_FOUND"),
                }
            }
            (_, ["_matrix", "client", _, rest @ ..]) => {
                self.client_api(method, rest, req, &user, &device)
            }
            _ => matrix_error(404, "M_UNRECOGNIZED"),
        }
    }

    fn client_api(
        &mut self,
        method: &str,
        path: &[&str],
        req: &Recorded,
        user: &str,
        device: &str,
    ) -> Response {
        match (method, path) {
            ("GET", ["account", "whoami"]) => {
                json_response(200, json!({ "user_id": user, "device_id": device }))
            }
            ("POST", ["keys", "upload"]) => self.keys_upload(user, device, &req.json()),
            ("POST", ["keys", "query"]) => self.keys_query(user, &req.json()),
            ("POST", ["keys", "claim"]) => self.keys_claim(&req.json()),
            ("POST", ["keys", "signatures", "upload"]) => self.signatures_upload(&req.json()),
            ("POST", ["keys", "device_signing", "upload"]) => {
                self.cross_signing.insert(user.to_owned(), req.json());
                json_response(200, json!({}))
            }
            ("PUT", ["sendToDevice", event_type, _txn]) => {
                self.send_to_device(user, device, event_type, &req.json())
            }
            ("GET", ["sync"]) => self.sync(user, device, &req.query),
            ("GET", ["notifications"]) => self.notifications(user, device),
            ("GET", ["user", _, "account_data", event_type]) => {
                match self
                    .account_data
                    .get(&(user.to_owned(), (*event_type).to_owned()))
                {
                    Some(content) => json_response(200, content.clone()),
                    None => matrix_error(404, "M_NOT_FOUND"),
                }
            }
            ("GET", ["room_keys", "version"]) => match &self.backup {
                Some(backup) => json_response(
                    200,
                    json!({
                        "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                        "auth_data": backup.auth_data,
                        "version": backup.version,
                        "count": backup.rooms.values().map(BTreeMap::len).sum::<usize>(),
                        "etag": "0",
                    }),
                ),
                None => matrix_error(404, "M_NOT_FOUND"),
            },
            ("GET", ["room_keys", "keys", room_id, session_id]) => {
                let key = self
                    .backup
                    .as_ref()
                    .and_then(|backup| backup.rooms.get(*room_id)?.get(*session_id));
                match key {
                    Some(key) => json_response(200, key.clone()),
                    None => matrix_error(404, "M_NOT_FOUND"),
                }
            }
            ("GET", ["room_keys", "keys"]) => match &self.backup {
                Some(backup) => {
                    let rooms: serde_json::Map<String, Value> = backup
                        .rooms
                        .iter()
                        .map(|(room, sessions)| (room.clone(), json!({ "sessions": sessions })))
                        .collect();
                    json_response(200, json!({ "rooms": rooms }))
                }
                None => matrix_error(404, "M_NOT_FOUND"),
            },
            ("PUT", ["room_keys", "keys"]) => {
                let Some(backup) = &mut self.backup else {
                    return matrix_error(404, "M_NOT_FOUND");
                };
                let body = req.json();
                for (room, data) in body["rooms"].as_object().into_iter().flatten() {
                    for (session, key) in data["sessions"].as_object().into_iter().flatten() {
                        backup
                            .rooms
                            .entry(room.clone())
                            .or_default()
                            .insert(session.clone(), key.clone());
                    }
                }
                let count = backup.rooms.values().map(BTreeMap::len).sum::<usize>();
                json_response(200, json!({ "count": count, "etag": "1" }))
            }
            (_, ["rooms", room_id, rest @ ..]) => {
                self.room_api(method, room_id, rest, req, user, device)
            }
            _ => matrix_error(404, "M_UNRECOGNIZED"),
        }
    }

    fn room_api(
        &mut self,
        method: &str,
        room_id: &str,
        path: &[&str],
        req: &Recorded,
        user: &str,
        device: &str,
    ) -> Response {
        // Like Synapse, reveal nothing about rooms the user is not in.
        let Some(room) = self
            .rooms
            .get(room_id)
            .filter(|room| room.members.iter().any(|m| m == user))
        else {
            return matrix_error(403, "M_FORBIDDEN");
        };
        let index_of = |event_id: &str| {
            room.timeline
                .iter()
                .position(|e| e.json["event_id"] == event_id)
        };
        match (method, path) {
            // The state endpoint returns the event content directly.
            ("GET", ["state", "m.room.encryption"]) => match &room.encryption {
                Some(content) => json_response(200, content.clone()),
                None => matrix_error(404, "M_NOT_FOUND"),
            },
            ("GET", ["state", ..]) => matrix_error(404, "M_NOT_FOUND"),
            ("GET", ["joined_members"]) => {
                let joined: serde_json::Map<String, Value> = room
                    .members
                    .iter()
                    .map(|m| (m.clone(), json!({})))
                    .collect();
                json_response(200, json!({ "joined": joined }))
            }
            ("GET", ["messages"]) => {
                let chunk: Vec<Value> = room
                    .timeline
                    .iter()
                    .rev()
                    .map(|e| client_event(e, device, true))
                    .collect();
                json_response(200, json!({ "chunk": chunk, "start": "s", "end": "e" }))
            }
            ("GET", ["event", event_id]) => match index_of(event_id) {
                Some(i) => json_response(200, client_event(&room.timeline[i], device, true)),
                None => matrix_error(404, "M_NOT_FOUND"),
            },
            ("GET", ["context", event_id]) => match index_of(event_id) {
                Some(i) => {
                    let render = |events: &[StoredEvent]| -> Vec<Value> {
                        events
                            .iter()
                            .map(|e| client_event(e, device, true))
                            .collect()
                    };
                    json_response(
                        200,
                        json!({
                            "event": client_event(&room.timeline[i], device, true),
                            "events_before": render(&room.timeline[..i]),
                            "events_after": render(&room.timeline[i + 1..]),
                            "state": [],
                            "start": "s",
                            "end": "e",
                        }),
                    )
                }
                None => matrix_error(404, "M_NOT_FOUND"),
            },
            ("PUT", ["send", event_type, txn_id]) => {
                let event_id =
                    self.append_event(room_id, user, device, event_type, txn_id, req.json());
                json_response(200, json!({ "event_id": event_id }))
            }
            _ => matrix_error(404, "M_UNRECOGNIZED"),
        }
    }

    fn login(&mut self, body: &Value) -> Response {
        let user = body
            .pointer("/identifier/user")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some((assigned, token)) = self.logins.get(user).cloned() else {
            return matrix_error(403, "M_FORBIDDEN");
        };
        // A client may name its device; otherwise the homeserver picks an ID.
        let device = body["device_id"]
            .as_str()
            .map_or(assigned, ToOwned::to_owned);
        self.tokens
            .insert(token.clone(), (user.to_owned(), device.clone()));
        json_response(
            200,
            json!({ "user_id": user, "device_id": device, "access_token": token }),
        )
    }

    fn upload(&mut self, req: &Recorded) -> Response {
        self.seq += 1;
        let mxc = format!("mxc://{SERVER_NAME}/media{}", self.seq);
        self.media.insert(
            mxc.clone(),
            Media {
                content_type: req.content_type.clone(),
                filename: query_param(&req.query, "filename"),
                bytes: req.body.clone(),
            },
        );
        json_response(200, json!({ "content_uri": mxc }))
    }

    fn otk_counts(&self, user: &str, device: &str) -> Value {
        let count = self
            .one_time_keys
            .get(&(user.to_owned(), device.to_owned()))
            .map_or(0, BTreeMap::len);
        json!({ "signed_curve25519": count })
    }

    fn keys_upload(&mut self, user: &str, device: &str, body: &Value) -> Response {
        let key = (user.to_owned(), device.to_owned());
        if let Some(device_keys) = body.get("device_keys") {
            self.device_keys
                .entry(user.to_owned())
                .or_default()
                .insert(device.to_owned(), device_keys.clone());
            self.seq += 1;
            self.device_changes.push((self.seq, user.to_owned()));
        }
        for (field, store) in [
            ("one_time_keys", &mut self.one_time_keys),
            ("fallback_keys", &mut self.fallback_keys),
        ] {
            if let Some(keys) = body.get(field).and_then(Value::as_object) {
                store
                    .entry(key.clone())
                    .or_default()
                    .extend(keys.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }
        json_response(
            200,
            json!({ "one_time_key_counts": self.otk_counts(user, device) }),
        )
    }

    fn keys_query(&self, requester: &str, body: &Value) -> Response {
        if self.fail_keys_query {
            return matrix_error(500, "M_UNKNOWN");
        }
        let mut response = json!({
            "device_keys": {},
            "failures": {},
            "master_keys": {},
            "self_signing_keys": {},
            "user_signing_keys": {},
        });
        for user in body["device_keys"]
            .as_object()
            .into_iter()
            .flat_map(|o| o.keys())
        {
            response["device_keys"][user] =
                json!(self.device_keys.get(user).cloned().unwrap_or_default());
            if let Some(keys) = self.cross_signing.get(user) {
                response["master_keys"][user] = keys["master_key"].clone();
                response["self_signing_keys"][user] = keys["self_signing_key"].clone();
                // Only ever visible to the user themselves.
                if user == requester {
                    response["user_signing_keys"][user] = keys["user_signing_key"].clone();
                }
            }
        }
        json_response(200, response)
    }

    fn keys_claim(&mut self, body: &Value) -> Response {
        let mut claimed = json!({});
        for (user, devices) in body["one_time_keys"].as_object().into_iter().flatten() {
            for device in devices.as_object().into_iter().flat_map(|o| o.keys()) {
                let key = (user.clone(), device.clone());
                let one_time_key = self
                    .one_time_keys
                    .get_mut(&key)
                    .and_then(BTreeMap::pop_first)
                    .or_else(|| {
                        let fallback = self.fallback_keys.get(&key)?.iter().next()?;
                        Some((fallback.0.clone(), fallback.1.clone()))
                    });
                if let Some((key_id, value)) = one_time_key {
                    claimed[user][device] = json!({ key_id: value });
                }
            }
        }
        json_response(200, json!({ "one_time_keys": claimed, "failures": {} }))
    }

    /// Merge uploaded cross-signing signatures into the stored device keys.
    fn signatures_upload(&mut self, body: &Value) -> Response {
        for (user, objects) in body.as_object().into_iter().flatten() {
            for (id, signed) in objects.as_object().into_iter().flatten() {
                let Some(device_keys) = self.device_keys.get_mut(user).and_then(|d| d.get_mut(id))
                else {
                    continue;
                };
                for (signer, signatures) in signed["signatures"].as_object().into_iter().flatten() {
                    for (key_id, signature) in signatures.as_object().into_iter().flatten() {
                        device_keys["signatures"][signer][key_id] = signature.clone();
                    }
                }
                self.seq += 1;
                self.device_changes.push((self.seq, user.clone()));
            }
        }
        json_response(200, json!({ "failures": {} }))
    }

    fn send_to_device(
        &mut self,
        sender: &str,
        sender_device: &str,
        event_type: &str,
        body: &Value,
    ) -> Response {
        if self.drop_to_device {
            return json_response(200, json!({}));
        }
        for (user, devices) in body["messages"].as_object().into_iter().flatten() {
            for (device, content) in devices.as_object().into_iter().flatten() {
                let targets: Vec<String> = if device == "*" {
                    self.tokens
                        .values()
                        .filter(|(u, d)| u == user && d != sender_device)
                        .map(|(_, d)| d.clone())
                        .collect()
                } else {
                    vec![device.clone()]
                };
                for target in targets {
                    let event = json!({ "type": event_type, "sender": sender, "content": content });
                    if self.hold_to_device {
                        self.held_to_device.push(((user.clone(), target), event));
                    } else {
                        self.queue_to_device((user.clone(), target), event);
                    }
                }
            }
        }
        json_response(200, json!({}))
    }

    fn queue_to_device(&mut self, target: (String, String), event: Value) {
        self.seq += 1;
        self.to_device
            .entry(target)
            .or_default()
            .push((self.seq, event));
    }

    fn sync(&mut self, user: &str, device: &str, query: &str) -> Response {
        let since_param = query_param(query, "since");
        let since: u64 = since_param
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // As on a real homeserver, a to-device event keeps being delivered
        // (to every sync stream of the device) until some request's `since`
        // acknowledges it.
        let pending = self
            .to_device
            .entry((user.to_owned(), device.to_owned()))
            .or_default();
        pending.retain(|(position, _)| *position > since);
        let to_device: Vec<Value> = pending.iter().map(|(_, event)| event.clone()).collect();

        let mut join = serde_json::Map::new();
        for (room_id, room) in &self.rooms {
            if !room.members.iter().any(|m| m == user) {
                continue;
            }
            // Sync events carry no room_id (it is the map key).
            let events: Vec<Value> = room
                .timeline
                .iter()
                .filter(|e| e.seq > since)
                .map(|e| client_event(e, device, false))
                .collect();
            let mut state = Vec::new();
            if since == 0
                && let Some(content) = &room.encryption
            {
                state.push(json!({
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": content,
                    "sender": room.members[0],
                    "event_id": format!("$encryption-{room_id}"),
                    "origin_server_ts": 1,
                }));
            }
            if events.is_empty() && state.is_empty() {
                continue;
            }
            let unread = room
                .timeline
                .iter()
                .filter(|e| e.json["sender"] != user)
                .count();
            join.insert(
                room_id.clone(),
                json!({
                    "timeline": { "events": events, "limited": false },
                    "state": { "events": state },
                    "unread_notifications": {
                        "notification_count": unread,
                        "highlight_count": 0,
                    },
                }),
            );
        }

        let mut changed: Vec<&String> = self
            .device_changes
            .iter()
            .filter(|(seq, _)| *seq > since)
            .map(|(_, user)| user)
            .collect();
        changed.sort();
        changed.dedup();

        let fallback_types: Vec<&str> = self
            .fallback_keys
            .get(&(user.to_owned(), device.to_owned()))
            .map_or(vec![], |_| vec!["signed_curve25519"]);
        self.idle =
            since_param.is_some() && to_device.is_empty() && join.is_empty() && changed.is_empty();
        let mut response = json!({
            "next_batch": self.seq.to_string(),
            "to_device": { "events": to_device },
            "device_lists": { "changed": changed, "left": [] },
            "device_one_time_keys_count": self.otk_counts(user, device),
            "device_unused_fallback_key_types": fallback_types,
            "rooms": { "join": join },
        });
        if self.omit_one_time_key_counts {
            let response = response.as_object_mut().unwrap();
            response.remove("device_one_time_keys_count");
            response.remove("device_unused_fallback_key_types");
        }
        json_response(200, response)
    }

    /// Notify on every event someone else sent into one of the user's rooms.
    fn notifications(&self, user: &str, device: &str) -> Response {
        let mut notifications = Vec::new();
        for (room_id, room) in &self.rooms {
            if !room.members.iter().any(|m| m == user) {
                continue;
            }
            for event in room.timeline.iter().filter(|e| e.json["sender"] != user) {
                notifications.push(json!({
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }],
                    "event": client_event(event, device, true),
                    "read": false,
                    "room_id": room_id,
                    "ts": event.json["origin_server_ts"],
                }));
            }
        }
        json_response(200, json!({ "notifications": notifications }))
    }

    fn append_event(
        &mut self,
        room_id: &str,
        sender: &str,
        sender_device: &str,
        event_type: &str,
        txn_id: &str,
        content: Value,
    ) -> String {
        self.seq += 1;
        let seq = self.seq;
        let event_id = format!("$event{seq}");
        let room = self.rooms.get_mut(room_id).expect("room exists");
        room.timeline.push(StoredEvent {
            seq,
            sender_device: sender_device.to_owned(),
            txn_id: txn_id.to_owned(),
            json: json!({
                "type": event_type,
                "content": content,
                "sender": sender,
                "event_id": event_id,
                "origin_server_ts": 1_700_000_000_000u64 + seq,
                "room_id": room_id,
            }),
        });
        event_id
    }
}

/// Serialize a stored event for a client: `transaction_id` is only echoed to
/// the device that sent the event, as on a real homeserver.
fn client_event(event: &StoredEvent, device: &str, with_room_id: bool) -> Value {
    let mut json = event.json.clone();
    if !with_room_id {
        json.as_object_mut().unwrap().remove("room_id");
    }
    let mut unsigned = json!({ "age": 1 });
    if event.sender_device == device {
        unsigned["transaction_id"] = event.txn_id.clone().into();
    }
    json["unsigned"] = unsigned;
    json
}

struct Shared {
    state: Mutex<HsState>,
    /// Wakes long-polling syncs when something may have changed.
    changed: tokio::sync::Notify,
}

async fn hs_handle(State(shared): State<Arc<Shared>>, req: Request) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(ToOwned::to_owned);
    let mut recorded = Recorded {
        method: req.method().clone(),
        path: req.uri().path().to_owned(),
        query: req.uri().query().unwrap_or_default().to_owned(),
        headers: req.headers().clone(),
        content_type: req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned),
        body: Vec::new(),
    };
    recorded.body = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    shared.state.lock().unwrap().requests.push(recorded.clone());

    // /sync?timeout=N long-polls: hold the request until there is something
    // to say or the timeout passes.
    let deadline = query_param(&recorded.query, "timeout")
        .and_then(|t| t.parse::<u64>().ok())
        .map(|ms| tokio::time::Instant::now() + Duration::from_millis(ms));
    loop {
        // Register for wake-ups before looking, so none is missed.
        let changed = shared.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let mut hs = shared.state.lock().unwrap();
            hs.idle = false;
            let response = hs.respond(&recorded, token.as_deref());
            let wait = hs.idle && deadline.is_some_and(|d| tokio::time::Instant::now() < d);
            if !wait {
                drop(hs);
                if recorded.method != Method::GET {
                    shared.changed.notify_waiters();
                }
                return response;
            }
        }
        tokio::select! {
            () = &mut changed => {}
            () = tokio::time::sleep_until(deadline.unwrap()) => {}
        }
    }
}

/// Handle to the fake homeserver; cheap to clone.
#[derive(Clone)]
pub struct FakeHomeserver {
    pub url: reqwest::Url,
    shared: Arc<Shared>,
}

impl FakeHomeserver {
    pub async fn start() -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(HsState::default()),
            changed: tokio::sync::Notify::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let router = Router::new().fallback(hs_handle).with_state(shared.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, shared }
    }

    pub fn lock(&self) -> MutexGuard<'_, HsState> {
        self.shared.state.lock().unwrap()
    }

    /// Wake long-polling syncs after changing state behind their back.
    fn changed(&self) {
        self.shared.changed.notify_waiters();
    }

    /// Make `token` a valid access token for the given device.
    pub fn add_device(&self, user: &str, device: &str, token: &str) {
        self.lock()
            .tokens
            .insert(token.to_owned(), (user.to_owned(), device.to_owned()));
    }

    /// Let the next POST /login for `user` succeed, handing out `token`.
    /// `device` is the ID assigned when the client does not ask for one.
    pub fn add_login(&self, user: &str, device: &str, token: &str) {
        self.lock()
            .logins
            .insert(user.to_owned(), (device.to_owned(), token.to_owned()));
    }

    pub fn revoke(&self, token: &str) {
        self.lock().tokens.remove(token);
        self.changed();
    }

    /// Sign a device out, as another client's session manager does: its
    /// tokens, keys and pending messages go, and everyone is told.
    pub fn delete_device(&self, user: &str, device: &str) {
        {
            let mut hs = self.lock();
            hs.tokens.retain(|_, (u, d)| !(u == user && d == device));
            if let Some(devices) = hs.device_keys.get_mut(user) {
                devices.remove(device);
            }
            let key = (user.to_owned(), device.to_owned());
            hs.one_time_keys.remove(&key);
            hs.fallback_keys.remove(&key);
            hs.to_device.remove(&key);
            hs.seq += 1;
            let seq = hs.seq;
            hs.device_changes.push((seq, user.to_owned()));
        }
        self.changed();
    }

    /// Deliver the to-device messages kept back by `hold_to_device`.
    pub fn release_to_device(&self) {
        {
            let mut hs = self.lock();
            hs.hold_to_device = false;
            for (target, event) in std::mem::take(&mut hs.held_to_device) {
                hs.queue_to_device(target, event);
            }
        }
        self.changed();
    }

    pub fn create_room(&self, members: &[&str], encrypted: bool) -> String {
        let mut hs = self.lock();
        let room_id = format!("!room{}:{SERVER_NAME}", hs.rooms.len() + 1);
        hs.rooms.insert(
            room_id.clone(),
            Room {
                encryption: encrypted.then(|| json!({ "algorithm": "m.megolm.v1.aes-sha2" })),
                members: members.iter().map(|m| (*m).to_owned()).collect(),
                timeline: Vec::new(),
            },
        );
        room_id
    }

    /// Append an event as if sent by some other client; returns its event ID.
    pub fn inject_event(
        &self,
        room_id: &str,
        sender: &str,
        event_type: &str,
        content: Value,
    ) -> String {
        let event_id = {
            let mut hs = self.lock();
            let txn_id = format!("injected{}", hs.seq);
            hs.append_event(room_id, sender, "ELSEWHERE", event_type, &txn_id, content)
        };
        self.changed();
        event_id
    }

    /// The event exactly as the homeserver stores it.
    pub fn event(&self, event_id: &str) -> Value {
        self.lock()
            .rooms
            .values()
            .flat_map(|r| &r.timeline)
            .find(|e| e.json["event_id"] == event_id)
            .map(|e| e.json.clone())
            .unwrap_or_else(|| panic!("no event {event_id} on the homeserver"))
    }

    pub fn add_media(&self, content_type: &str, bytes: &[u8]) -> String {
        let mut hs = self.lock();
        hs.seq += 1;
        let mxc = format!("mxc://{SERVER_NAME}/media{}", hs.seq);
        hs.media.insert(
            mxc.clone(),
            Media {
                content_type: Some(content_type.to_owned()),
                filename: None,
                bytes: bytes.to_vec(),
            },
        );
        mxc
    }

    pub fn media(&self, mxc: &str) -> Media {
        self.lock()
            .media
            .get(mxc)
            .cloned()
            .unwrap_or_else(|| panic!("no media {mxc} on the homeserver"))
    }

    /// How many one-time keys the device has on the homeserver.
    pub fn one_time_key_count(&self, user: &str, device: &str) -> usize {
        self.lock()
            .one_time_keys
            .get(&(user.to_owned(), device.to_owned()))
            .map_or(0, BTreeMap::len)
    }

    /// The ed25519 identity key the homeserver publishes for a device.
    pub fn identity_key(&self, user: &str, device: &str) -> Option<String> {
        self.lock().device_keys.get(user)?.get(device)?["keys"][format!("ed25519:{device}")]
            .as_str()
            .map(ToOwned::to_owned)
    }

    pub fn has_device_keys(&self, user: &str, device: &str) -> bool {
        let hs = self.lock();
        hs.device_keys
            .get(user)
            .is_some_and(|devices| devices.contains_key(device))
            && hs
                .one_time_keys
                .contains_key(&(user.to_owned(), device.to_owned()))
    }

    /// Requests seen so far whose path contains `needle`.
    pub fn requests_to(&self, needle: &str) -> Vec<Recorded> {
        self.lock()
            .requests
            .iter()
            .filter(|r| r.path.contains(needle))
            .cloned()
            .collect()
    }
}

/// Poll `condition` until it holds; panics after ten seconds.
pub async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting until {what}");
}

/// Like [`wait_until`], for conditions that need to await.
pub async fn wait_for(what: &str, mut condition: impl AsyncFnMut() -> bool) {
    for _ in 0..1000 {
        if condition().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting until {what}");
}

/// A proxy instance in front of a fake homeserver.
pub struct Harness {
    pub hs: FakeHomeserver,
    pub state: AppState,
    /// Base URL of the proxy.
    pub url: String,
    pub http: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
    _store_dir: Option<tempfile::TempDir>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A client sync loop started by [`Harness::keep_syncing`]; stops on drop.
pub struct SyncLoop(tokio::task::JoinHandle<()>);

impl Drop for SyncLoop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Options for starting a [`Harness`]; the defaults match a default config.
#[derive(Default)]
pub struct HarnessBuilder {
    hs: Option<FakeHomeserver>,
    admin_token: Option<String>,
    store_dir: Option<PathBuf>,
}

impl HarnessBuilder {
    /// Use an existing homeserver (for multi-proxy tests).
    pub fn homeserver(mut self, hs: &FakeHomeserver) -> Self {
        self.hs = Some(hs.clone());
        self
    }

    pub fn admin_token(mut self, token: &str) -> Self {
        self.admin_token = Some(token.to_owned());
        self
    }

    /// Use a caller-owned store directory (for restart tests).
    pub fn store_dir(mut self, dir: &Path) -> Self {
        self.store_dir = Some(dir.to_owned());
        self
    }

    pub async fn start(self) -> Harness {
        let hs = match self.hs {
            Some(hs) => hs,
            None => FakeHomeserver::start().await,
        };
        let (store_dir, owned_dir) = match self.store_dir {
            Some(dir) => (dir, None),
            None => {
                let dir = tempfile::tempdir().unwrap();
                (dir.path().to_owned(), Some(dir))
            }
        };
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            homeserver: hs.url.clone(),
            store_dir,
            log_level: "off".to_owned(),
            store_passphrase: None,
            admin_token: self.admin_token,
        };
        let state = AppState::new(Arc::new(config)).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = proxy::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Harness {
            hs,
            state,
            url,
            http: reqwest::Client::new(),
            server,
            _store_dir: owned_dir,
        }
    }
}

impl Harness {
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::default()
    }

    pub async fn start() -> Self {
        Self::builder().start().await
    }

    /// Stop the proxy and wait until it has let go of its sessions (and with
    /// them the crypto stores), as a process exit would.
    pub async fn shutdown(self) {
        let sessions: Vec<_> = self
            .state
            .sessions
            .list()
            .await
            .iter()
            .map(Arc::downgrade)
            .collect();
        self.server.abort();
        drop(self);
        wait_until("the proxy has released its sessions", || {
            sessions.iter().all(|session| session.upgrade().is_none())
        })
        .await;
    }

    /// An admin API client for this proxy, as `ctl` would build it.
    pub fn ctl(&self) -> crate::admin::ctl::Client {
        crate::admin::ctl::Client::new(&self.url, self.state.config.admin_token.clone())
    }

    /// Send a request through the proxy; returns (status, JSON body or Null).
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut req = self.http.request(method, format!("{}{path}", self.url));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    pub async fn get(&self, token: &str, path: &str) -> (u16, Value) {
        self.request(Method::GET, path, Some(token), None).await
    }

    pub async fn put(&self, token: &str, path: &str, body: &Value) -> (u16, Value) {
        self.request(Method::PUT, path, Some(token), Some(body))
            .await
    }

    pub async fn post(&self, token: Option<&str>, path: &str, body: &Value) -> (u16, Value) {
        self.request(Method::POST, path, token, Some(body)).await
    }

    /// Register a device on the homeserver, sync once through the proxy (as a
    /// restored ement session would) and wait for its keys to be published.
    /// Returns the access token.
    pub async fn connect(&self, user: &str, device: &str) -> String {
        let token = format!("token-{device}");
        self.hs.add_device(user, device, &token);
        let (status, _) = self.get(&token, "/_matrix/client/r0/sync").await;
        assert_eq!(status, 200, "initial sync for {device}");
        wait_until("device keys are uploaded", || {
            self.hs.has_device_keys(user, device)
        })
        .await;
        token
    }

    /// Send an event the way ement does; returns the event ID.
    pub async fn send(
        &self,
        token: &str,
        room_id: &str,
        event_type: &str,
        txn_id: &str,
        content: &Value,
    ) -> String {
        let path = format!(
            "/_matrix/client/r0/rooms/{}/send/{event_type}/{txn_id}",
            enc(room_id)
        );
        let (status, body) = self.put(token, &path, content).await;
        assert_eq!(status, 200, "send failed: {body}");
        body["event_id"].as_str().expect("event_id").to_owned()
    }

    pub async fn send_text(&self, token: &str, room_id: &str, text: &str) -> String {
        // Unique per call: the request log only grows.
        let txn_id = format!("txn{}", self.hs.lock().requests.len());
        let content = json!({ "msgtype": "m.text", "body": text });
        self.send(token, room_id, "m.room.message", &txn_id, &content)
            .await
    }

    /// Full sync through the proxy; returns the whole response body.
    pub async fn sync(&self, token: &str) -> Value {
        let (status, body) = self.get(token, "/_matrix/client/r0/sync").await;
        assert_eq!(status, 200, "sync failed: {body}");
        body
    }

    /// Incremental sync from `since`, long-polling for up to `timeout_ms`.
    pub async fn sync_since(&self, token: &str, since: &str, timeout_ms: u64) -> Value {
        let path = format!("/_matrix/client/r0/sync?since={since}&timeout={timeout_ms}");
        let (status, body) = self.get(token, &path).await;
        assert_eq!(status, 200, "sync failed: {body}");
        body
    }

    /// Keep syncing like a running ement would: incremental long-polls, one
    /// after the other, until the returned guard is dropped.
    pub async fn keep_syncing(&self, token: &str) -> SyncLoop {
        let mut since = self.sync(token).await["next_batch"]
            .as_str()
            .expect("next_batch")
            .to_owned();
        let (http, url, token) = (self.http.clone(), self.url.clone(), token.to_owned());
        SyncLoop(tokio::spawn(async move {
            loop {
                let request = http
                    .get(format!(
                        "{url}/_matrix/client/r0/sync?since={since}&timeout=30000"
                    ))
                    .bearer_auth(&token)
                    .send();
                let Ok(response) = request.await else { return };
                let Ok(body) = response.json::<Value>().await else {
                    return;
                };
                match body["next_batch"].as_str() {
                    Some(next_batch) => since = next_batch.to_owned(),
                    None => return,
                }
            }
        }))
    }

    /// Full sync through the proxy; returns the room's timeline events.
    pub async fn sync_timeline(&self, token: &str, room_id: &str) -> Vec<Value> {
        let (status, body) = self.get(token, "/_matrix/client/r0/sync").await;
        assert_eq!(status, 200, "sync failed: {body}");
        body["rooms"]["join"][room_id]["timeline"]["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
}
