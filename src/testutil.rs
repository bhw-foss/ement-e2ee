//! Test-only harness: a fake homeserver implementing just enough of the
//! client-server API for matrix-sdk-crypto to run real key exchanges, plus a
//! proxy instance wired to it. Both speak real HTTP over loopback, so tests
//! drive the proxy exactly the way ement does.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
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
    to_device: HashMap<(String, String), Vec<Value>>,
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
        let Some((device, token)) = self.logins.get(user).cloned() else {
            return matrix_error(403, "M_FORBIDDEN");
        };
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
                    self.to_device
                        .entry((user.clone(), target))
                        .or_default()
                        .push(json!({ "type": event_type, "sender": sender, "content": content }));
                }
            }
        }
        json_response(200, json!({}))
    }

    fn sync(&mut self, user: &str, device: &str, query: &str) -> Response {
        let since: u64 = query_param(query, "since")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let to_device = self
            .to_device
            .remove(&(user.to_owned(), device.to_owned()))
            .unwrap_or_default();

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
            join.insert(
                room_id.clone(),
                json!({
                    "timeline": { "events": events, "limited": false },
                    "state": { "events": state },
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
        json_response(
            200,
            json!({
                "next_batch": self.seq.to_string(),
                "to_device": { "events": to_device },
                "device_lists": { "changed": changed, "left": [] },
                "device_one_time_keys_count": self.otk_counts(user, device),
                "device_unused_fallback_key_types": fallback_types,
                "rooms": { "join": join },
            }),
        )
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

async fn hs_handle(State(state): State<Arc<Mutex<HsState>>>, req: Request) -> Response {
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

    let mut hs = state.lock().unwrap();
    hs.requests.push(recorded.clone());
    hs.respond(&recorded, token.as_deref())
}

/// Handle to the fake homeserver; cheap to clone.
#[derive(Clone)]
pub struct FakeHomeserver {
    pub url: reqwest::Url,
    state: Arc<Mutex<HsState>>,
}

impl FakeHomeserver {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(HsState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let router = Router::new().fallback(hs_handle).with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, state }
    }

    pub fn lock(&self) -> MutexGuard<'_, HsState> {
        self.state.lock().unwrap()
    }

    /// Make `token` a valid access token for the given device.
    pub fn add_device(&self, user: &str, device: &str, token: &str) {
        self.lock()
            .tokens
            .insert(token.to_owned(), (user.to_owned(), device.to_owned()));
    }

    /// Let POST /login for `user` succeed, handing out `token`.
    pub fn add_login(&self, user: &str, device: &str, token: &str) {
        self.lock()
            .logins
            .insert(user.to_owned(), (device.to_owned(), token.to_owned()));
    }

    pub fn revoke(&self, token: &str) {
        self.lock().tokens.remove(token);
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
        let mut hs = self.lock();
        let txn_id = format!("injected{}", hs.seq);
        hs.append_event(room_id, sender, "ELSEWHERE", event_type, &txn_id, content)
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

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(FakeHomeserver::start().await, None).await
    }

    /// Start a proxy against an existing homeserver (for multi-proxy tests).
    pub async fn start_with(hs: FakeHomeserver, admin_token: Option<&str>) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let mut harness = Self::start_in(hs, admin_token, store_dir.path()).await;
        harness._store_dir = Some(store_dir);
        harness
    }

    /// Start a proxy on a caller-owned store directory (for restart tests).
    pub async fn start_in(hs: FakeHomeserver, admin_token: Option<&str>, store_dir: &Path) -> Self {
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            homeserver: hs.url.clone(),
            store_dir: store_dir.to_owned(),
            log_level: "off".to_owned(),
            store_passphrase: None,
            admin_token: admin_token.map(ToOwned::to_owned),
        };
        let state = AppState::new(Arc::new(config)).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = proxy::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            hs,
            state,
            url,
            http: reqwest::Client::new(),
            server,
            _store_dir: None,
        }
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
