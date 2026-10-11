//! End-to-end tests: real matrix-sdk-crypto machines on both ends, a fake
//! homeserver in the middle, everything driven over HTTP through the proxy
//! the way ement drives it.

use anyhow::Context as _;
use axum::http::Method;
use matrix_sdk_crypto::secret_storage::SecretStorageKey;
use matrix_sdk_crypto::store::types::BackupDecryptionKey;
use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
use matrix_sdk_crypto::{EncryptionSettings, OlmMachine, OlmMachineBuilder};
use ruma::events::AnyMessageLikeEventContent;
use ruma::events::secret::request::SecretName;
use ruma::serde::Raw;
use ruma::{RoomId, UserId};
use serde_json::{Value, json};

use crate::admin::verify::{self, VerifyUi};
use crate::crypto::machine::enc;
use crate::testutil::{
    ALICE, BOB, Backup, FakeHomeserver, Harness, SERVER_NAME, SyncLoop, wait_for, wait_until,
};

/// Alice and Bob, each connected through the proxy, sharing one room.
async fn alice_and_bob(encrypted: bool) -> (Harness, String, String, String) {
    let h = Harness::start().await;
    let room = h.hs.create_room(&[ALICE, BOB], encrypted);
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    let bob = h.connect(BOB, "BOBDEVICE").await;
    (h, room, alice, bob)
}

fn assert_decrypted_text(event: &Value, text: &str) {
    assert_eq!(event["type"], "m.room.message", "event: {event}");
    assert_eq!(event["content"]["body"], text, "event: {event}");
    assert_eq!(event["unsigned"]["ement_e2ee"]["decrypted"], true);
}

fn assert_utd(event: &Value) {
    assert_eq!(event["type"], "m.room.message", "event: {event}");
    assert_eq!(
        event["unsigned"]["ement_e2ee"]["utd"], true,
        "event: {event}"
    );
    assert!(
        event["content"]["body"]
            .as_str()
            .unwrap()
            .contains("undecryptable")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_message_round_trip() {
    let (h, room, alice, bob) = alice_and_bob(true).await;

    let event_id = h.send_text(&alice, &room, "hello bob").await;

    // The homeserver only ever saw ciphertext.
    let stored = h.hs.event(&event_id);
    assert_eq!(stored["type"], "m.room.encrypted");
    assert_eq!(stored["content"]["algorithm"], "m.megolm.v1.aes-sha2");
    assert!(!stored.to_string().contains("hello bob"));
    assert!(
        h.hs.requests_to("/send/m.room.message/").is_empty(),
        "plaintext send reached the homeserver"
    );

    // Bob reads it in plain text.
    let events = h.sync_timeline(&bob, &room).await;
    assert_eq!(events.len(), 1);
    assert_decrypted_text(&events[0], "hello bob");
    assert_eq!(events[0]["event_id"], event_id.as_str());
    assert_eq!(events[0]["sender"], ALICE);
    assert!(events[0]["unsigned"]["ement_e2ee"]["encryption_info"].is_object());

    // Alice gets her own message back decrypted, with the transaction ID that
    // ement's local-echo resolution depends on.
    let events = h.sync_timeline(&alice, &room).await;
    assert_decrypted_text(&events[0], "hello bob");
    assert!(events[0]["unsigned"]["transaction_id"].is_string());

    // And the conversation works in the other direction too.
    h.send_text(&bob, &room, "hello alice").await;
    let events = h.sync_timeline(&alice, &room).await;
    assert_decrypted_text(&events[1], "hello alice");
}

#[tokio::test]
async fn reactions_and_edits_are_encrypted() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let target = h.send_text(&alice, &room, "original").await;

    let reaction = json!({
        "m.relates_to": { "rel_type": "m.annotation", "event_id": target, "key": "👍" },
    });
    let reaction_id = h.send(&bob, &room, "m.reaction", "react1", &reaction).await;
    let edit = json!({
        "msgtype": "m.text",
        "body": "* edited",
        "m.new_content": { "msgtype": "m.text", "body": "edited" },
        "m.relates_to": { "rel_type": "m.replace", "event_id": target },
    });
    let edit_id = h
        .send(&alice, &room, "m.room.message", "edit1", &edit)
        .await;

    for event_id in [&reaction_id, &edit_id] {
        let stored = h.hs.event(event_id);
        assert_eq!(stored["type"], "m.room.encrypted");
        // Relations stay in the clear so the server can aggregate them.
        assert_eq!(
            stored["content"]["m.relates_to"]["event_id"],
            target.as_str()
        );
        assert!(!stored.to_string().contains("edited"));
    }

    let events = h.sync_timeline(&bob, &room).await;
    assert_eq!(events[1]["type"], "m.reaction");
    assert_eq!(events[1]["content"]["m.relates_to"]["key"], "👍");
    assert_eq!(events[2]["content"]["m.new_content"]["body"], "edited");
}

/// Regression test: encrypted DMs notify on the m.room.encrypted envelope, so
/// ement's notifications buffer showed nothing readable for them.
#[tokio::test]
async fn notifications_are_decrypted() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let plain_room = h.hs.create_room(&[ALICE, BOB], false);
    let encrypted_id = h.send_text(&alice, &room, "encrypted ping").await;
    let plain_id = h.send_text(&alice, &plain_room, "plain ping").await;
    // Deliver the room key to Bob.
    h.sync_timeline(&bob, &room).await;

    // ement uses r0; newer clients v3.
    for version in ["r0", "v3"] {
        let path = format!("/_matrix/client/{version}/notifications?limit=10");
        let (status, body) = h.get(&bob, &path).await;
        assert_eq!(status, 200);
        let notifications = body["notifications"].as_array().unwrap();
        assert_eq!(notifications.len(), 2);

        let encrypted = &notifications[0];
        assert_decrypted_text(&encrypted["event"], "encrypted ping");
        assert_eq!(encrypted["event"]["event_id"], encrypted_id.as_str());
        // The notification envelope is left alone.
        assert_eq!(encrypted["room_id"], room.as_str());
        assert_eq!(encrypted["read"], false);
        assert_eq!(encrypted["actions"][0], "notify");
        assert!(encrypted["ts"].is_number());

        // Unencrypted notifications pass through untouched.
        let plain = &notifications[1];
        assert_eq!(plain["event"]["event_id"], plain_id.as_str());
        assert_eq!(plain["event"]["content"]["body"], "plain ping");
        assert!(plain["event"]["unsigned"].get("ement_e2ee").is_none());
    }

    // The query string is forwarded as-is.
    let upstream = h.hs.requests_to("/notifications");
    assert!(upstream.iter().all(|r| r.query == "limit=10"));
}

#[tokio::test]
async fn notifications_without_keys_show_placeholder() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    h.hs.lock().drop_to_device = true;
    h.send_text(&alice, &room, "you will never read this").await;

    let (status, body) = h.get(&bob, "/_matrix/client/r0/notifications").await;
    assert_eq!(status, 200);
    assert_utd(&body["notifications"][0]["event"]);
    assert_eq!(body["notifications"][0]["room_id"], room.as_str());
}

#[tokio::test]
async fn notifications_tolerate_odd_bodies() {
    let (h, _room, _alice, bob) = alice_and_bob(true).await;
    // No notifications at all: relayed as-is.
    let (status, body) = h.get(&bob, "/_matrix/client/r0/notifications").await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({ "notifications": [] }));

    // Upstream errors are relayed verbatim.
    let (status, body) = h
        .get("bogus-token", "/_matrix/client/r0/notifications")
        .await;
    assert_eq!(status, 401);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

#[tokio::test]
async fn history_endpoints_are_decrypted() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let first = h.send_text(&alice, &room, "one").await;
    let second = h.send_text(&alice, &room, "two").await;
    h.send_text(&alice, &room, "three").await;
    h.sync_timeline(&bob, &room).await;
    let room_path = format!("/_matrix/client/r0/rooms/{}", enc(&room));

    let (status, body) = h
        .get(&bob, &format!("{room_path}/messages?dir=b&limit=10"))
        .await;
    assert_eq!(status, 200);
    let chunk = body["chunk"].as_array().unwrap();
    assert_decrypted_text(&chunk[0], "three");
    assert_decrypted_text(&chunk[1], "two");
    assert_decrypted_text(&chunk[2], "one");
    // Pagination tokens survive the rewrite.
    assert_eq!(body["start"], "s");
    assert_eq!(body["end"], "e");

    let (status, body) = h
        .get(&bob, &format!("{room_path}/context/{}", enc(&second)))
        .await;
    assert_eq!(status, 200);
    assert_decrypted_text(&body["event"], "two");
    assert_decrypted_text(&body["events_before"][0], "one");
    assert_decrypted_text(&body["events_after"][0], "three");

    let (status, body) = h
        .get(&bob, &format!("{room_path}/event/{}", enc(&first)))
        .await;
    assert_eq!(status, 200);
    assert_decrypted_text(&body, "one");
    assert_eq!(body["event_id"], first.as_str());

    // Upstream errors are relayed, not turned into proxy errors.
    let (status, body) = h.get(&bob, &format!("{room_path}/event/%24nope")).await;
    assert_eq!(status, 404);
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn missing_room_key_yields_placeholder_and_key_request() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    // The room key share gets lost in transit.
    h.hs.lock().drop_to_device = true;
    let event_id = h.send_text(&alice, &room, "lost").await;
    h.hs.lock().drop_to_device = false;

    let events = h.sync_timeline(&bob, &room).await;
    assert_utd(&events[0]);
    // Envelope fields survive so ement can still place the event.
    assert_eq!(events[0]["event_id"], event_id.as_str());
    assert_eq!(events[0]["sender"], ALICE);
    assert!(events[0]["origin_server_ts"].is_number());
    assert!(events[0]["unsigned"]["ement_e2ee"]["session_id"].is_string());

    // Bob's proxy asks for the key, exactly once however often the event is
    // seen again.
    wait_until("a room key request is sent", || {
        !h.hs
            .requests_to("/sendToDevice/m.room_key_request/")
            .is_empty()
    })
    .await;
    h.sync_timeline(&bob, &room).await;
    h.sync_timeline(&bob, &room).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let requests = h.hs.requests_to("/sendToDevice/m.room_key_request/");
    assert_eq!(requests.len(), 1);
    let body = requests[0].json().to_string();
    assert!(body.contains(&room), "request names the room: {body}");
}

#[tokio::test]
async fn unencrypted_room_passes_through_in_plain_text() {
    let (h, room, alice, bob) = alice_and_bob(false).await;
    let event_id = h.send_text(&alice, &room, "public hello").await;

    let stored = h.hs.event(&event_id);
    assert_eq!(stored["type"], "m.room.message");
    assert_eq!(stored["content"]["body"], "public hello");
    // The client's own path (version segment and all) is forwarded.
    let sends = h.hs.requests_to("/send/m.room.message/");
    assert_eq!(sends.len(), 1);
    assert!(sends[0].path.starts_with("/_matrix/client/r0/rooms/"));
    // No megolm session was set up for a room that is not encrypted.
    assert!(h.hs.requests_to("/sendToDevice/").is_empty());

    let events = h.sync_timeline(&bob, &room).await;
    assert_eq!(events[0]["content"]["body"], "public hello");
    assert!(events[0]["unsigned"].get("ement_e2ee").is_none());
}

#[tokio::test]
async fn encryption_learned_from_sync_state() {
    let (h, room, alice, _bob) = alice_and_bob(true).await;
    // alice_and_bob() synced once, which carried the m.room.encryption state
    // event: sending must not need to ask the homeserver again.
    h.send_text(&alice, &room, "first").await;
    assert!(h.hs.requests_to("/state/m.room.encryption").is_empty());
}

#[tokio::test]
async fn send_fails_closed_when_encryption_state_is_unknown() {
    let h = Harness::start().await;
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    // Not Alice's room: the homeserver refuses to reveal its state, so the
    // proxy cannot tell whether it is encrypted.
    let room = h.hs.create_room(&[BOB], true);
    let path = format!(
        "/_matrix/client/r0/rooms/{}/send/m.room.message/txn1",
        enc(&room)
    );
    let content = json!({ "msgtype": "m.text", "body": "must not leak" });
    let (status, body) = h.put(&alice, &path, &content).await;
    assert_eq!(status, 500, "body: {body}");
    assert!(
        h.hs.requests_to("/send/").is_empty(),
        "plaintext was forwarded without knowing the room's encryption state"
    );
}

#[tokio::test]
async fn encrypted_media_round_trip() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let image = b"\x89PNG\r\n\x1a\n not really a png, but private".to_vec();

    // ement uploads through the legacy media endpoint.
    let resp = h
        .http
        .post(format!(
            "{}/_matrix/media/r0/upload?filename=cat.png",
            h.url
        ))
        .bearer_auth(&alice)
        .header("content-type", "image/png")
        .body(image.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mxc = resp.json::<Value>().await.unwrap()["content_uri"]
        .as_str()
        .unwrap()
        .to_owned();

    // The homeserver holds ciphertext, with no telling metadata.
    let stored = h.hs.media(&mxc);
    assert_ne!(stored.bytes, image);
    assert_eq!(stored.bytes.len(), image.len());
    assert_eq!(
        stored.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(stored.filename, None);

    let content = json!({
        "msgtype": "m.image",
        "body": "cat.png",
        "url": mxc,
        "info": { "size": image.len() },
    });
    let event_id = h
        .send(&alice, &room, "m.room.message", "img1", &content)
        .await;
    assert_eq!(h.hs.event(&event_id)["type"], "m.room.encrypted");

    // Bob sees an ordinary `url` (ement knows nothing about `file`) ...
    let events = h.sync_timeline(&bob, &room).await;
    let content = &events[0]["content"];
    assert_eq!(content["msgtype"], "m.image");
    assert_eq!(content["url"], mxc.as_str());
    assert!(content.get("file").is_none());
    assert_eq!(content["info"]["mimetype"], "image/png");

    // ... and downloading it through the proxy yields the original bytes.
    let media_id = mxc.rsplit('/').next().unwrap();
    for token in [&bob, &alice] {
        let resp = h
            .http
            .get(format!(
                "{}/_matrix/client/v1/media/download/{SERVER_NAME}/{media_id}",
                h.url
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "image/png");
        assert_eq!(resp.bytes().await.unwrap().to_vec(), image);
    }
}

#[tokio::test]
async fn media_sent_to_unencrypted_room_is_reuploaded_in_plain_text() {
    let (h, room, alice, _bob) = alice_and_bob(false).await;
    let file = b"public document".to_vec();
    let resp = h
        .http
        .post(format!(
            "{}/_matrix/media/r0/upload?filename=notes.txt",
            h.url
        ))
        .bearer_auth(&alice)
        .header("content-type", "text/plain")
        .body(file.clone())
        .send()
        .await
        .unwrap();
    let encrypted_mxc = resp.json::<Value>().await.unwrap()["content_uri"]
        .as_str()
        .unwrap()
        .to_owned();

    let content = json!({ "msgtype": "m.file", "body": "notes.txt", "url": encrypted_mxc });
    let event_id = h
        .send(&alice, &room, "m.room.message", "file1", &content)
        .await;

    // The event points at a fresh, readable upload rather than at ciphertext
    // nobody else in the room could decrypt.
    let stored = h.hs.event(&event_id);
    let plain_mxc = stored["content"]["url"].as_str().unwrap();
    assert_ne!(plain_mxc, encrypted_mxc);
    let media = h.hs.media(plain_mxc);
    assert_eq!(media.bytes, file);
    assert_eq!(media.content_type.as_deref(), Some("text/plain"));
    assert_eq!(media.filename.as_deref(), Some("notes.txt"));
}

#[tokio::test]
async fn tokenless_legacy_download_borrows_session_credentials() {
    let h = Harness::start().await;
    let avatar = b"plain avatar bytes".to_vec();
    let mxc = h.hs.add_media("image/jpeg", &avatar);
    let media_id = mxc.rsplit('/').next().unwrap();
    let url = format!(
        "{}/_matrix/media/r0/download/{SERVER_NAME}/{media_id}",
        h.url
    );

    // Without any session there is nothing to borrow: plain passthrough.
    let resp = h.http.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404);

    // With one, ement's tokenless avatar fetch is served via the
    // authenticated endpoint.
    h.connect(ALICE, "ALICEDEVICE").await;
    let resp = h.http.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "image/jpeg");
    assert_eq!(resp.bytes().await.unwrap().to_vec(), avatar);
}

#[tokio::test]
async fn login_initializes_session_and_publishes_keys() {
    let h = Harness::start().await;
    h.hs.add_login(ALICE, "LOGINDEVICE", "login-token");

    let body = json!({
        "type": "m.login.password",
        "identifier": { "type": "m.id.user", "user": ALICE },
        "password": "hunter2",
    });
    let (status, response) = h.post(None, "/_matrix/client/r0/login", &body).await;
    assert_eq!(status, 200);
    // The response reaches ement unmodified ...
    assert_eq!(response["access_token"], "login-token");
    assert_eq!(response["device_id"], "LOGINDEVICE");
    // ... the password went upstream verbatim ...
    assert_eq!(h.hs.requests_to("/login")[0].json(), body);
    // ... and the device is set up before ement's first sync.
    assert!(h.state.sessions.get("login-token").await.is_some());
    wait_until("device keys are uploaded", || {
        h.hs.has_device_keys(ALICE, "LOGINDEVICE")
    })
    .await;

    // A failed login creates nothing and relays the homeserver's error.
    let body = json!({ "type": "m.login.password", "identifier": { "user": BOB } });
    let (status, response) = h.post(None, "/_matrix/client/r0/login", &body).await;
    assert_eq!(status, 403);
    assert_eq!(response["errcode"], "M_FORBIDDEN");
    assert_eq!(h.state.sessions.list().await.len(), 1);
}

#[tokio::test]
async fn invalidated_token_evicts_session() {
    let h = Harness::start().await;
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    assert_eq!(h.state.sessions.list().await.len(), 1);

    h.hs.revoke(&alice);
    let (status, body) = h.get(&alice, "/_matrix/client/r0/sync").await;
    // ement sees the homeserver's own error and can prompt for a new login.
    assert_eq!(status, 401);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    assert!(h.state.sessions.list().await.is_empty());
}

#[tokio::test]
async fn store_survives_proxy_restart() {
    let hs = FakeHomeserver::start().await;
    let room = hs.create_room(&[ALICE, BOB], true);
    let store_dir = tempfile::tempdir().unwrap();

    let first = Harness::builder()
        .homeserver(&hs)
        .store_dir(store_dir.path())
        .start()
        .await;
    let alice = first.connect(ALICE, "ALICEDEVICE").await;
    let bob = first.connect(BOB, "BOBDEVICE").await;
    let event_id = first.send_text(&alice, &room, "remember me").await;
    first.sync_timeline(&bob, &room).await;
    let identity_before = first
        .state
        .sessions
        .get(&bob)
        .await
        .unwrap()
        .olm
        .identity_keys();
    first.shutdown().await;

    // A new proxy process on the same store: same olm identity, and history
    // still decrypts without any new key exchange.
    let second = Harness::builder()
        .homeserver(&hs)
        .store_dir(store_dir.path())
        .start()
        .await;
    let path = format!(
        "/_matrix/client/r0/rooms/{}/event/{}",
        enc(&room),
        enc(&event_id)
    );
    let (status, body) = second.get(&bob, &path).await;
    assert_eq!(status, 200);
    assert_decrypted_text(&body, "remember me");
    let identity_after = second
        .state
        .sessions
        .get(&bob)
        .await
        .unwrap()
        .olm
        .identity_keys();
    assert_eq!(identity_before.ed25519, identity_after.ed25519);
    assert_eq!(identity_before.curve25519, identity_after.curve25519);
}

#[tokio::test]
async fn passthrough_relays_everything_else() {
    let h = Harness::start().await;

    // Unauthenticated, unintercepted GET.
    let (status, body) = h
        .request(Method::GET, "/_matrix/client/versions", None, None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["versions"][0], "v1.11");

    // An intercepted route with a token the homeserver rejects degrades to
    // passthrough, so the client gets the authoritative error.
    let (status, body) = h.get("bogus-token", "/_matrix/client/r0/sync").await;
    assert_eq!(status, 401);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    assert!(h.state.sessions.list().await.is_empty());

    // Method, path, query, headers and body all arrive upstream untouched.
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    let resp = h
        .http
        .put(format!(
            "{}/_matrix/client/r0/rooms/%21r%3Ahs.test/typing/%40alice%3Ahs.test?x=1",
            h.url
        ))
        .bearer_auth(&alice)
        .header("x-custom", "kept")
        .json(&json!({ "typing": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["errcode"],
        "M_FORBIDDEN"
    );
    let seen = h.hs.requests_to("/typing/").pop().unwrap();
    assert_eq!(seen.method, Method::PUT);
    assert_eq!(seen.headers["x-custom"], "kept");
    assert_eq!(
        seen.headers["authorization"],
        format!("Bearer {alice}").as_str()
    );
    // Host is rewritten for the homeserver, not copied from the client.
    assert_eq!(
        seen.headers["host"],
        h.hs.url.authority(),
        "Host header leaked through"
    );
    assert_eq!(
        seen.path,
        "/_matrix/client/r0/rooms/%21r%3Ahs.test/typing/%40alice%3Ahs.test"
    );
    assert_eq!(seen.query, "x=1");
    assert_eq!(seen.json(), json!({ "typing": true }));
}

#[tokio::test]
async fn admin_api_requires_token_when_configured() {
    let h = Harness::builder().admin_token("s3cret").start().await;

    let (status, body) = h.request(Method::GET, "/_ement/status", None, None).await;
    assert_eq!(status, 401);
    assert!(body["error"].as_str().unwrap().contains("admin token"));
    let (status, _) = h.get("wrong", "/_ement/status").await;
    assert_eq!(status, 401);

    let (status, body) = h.get("s3cret", "/_ement/status").await;
    assert_eq!(status, 200);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["sessions"], json!([]));

    // The guard covers the whole admin surface, not just status.
    let (status, _) = h
        .post(None, "/_ement/bootstrap", &json!({ "recovery_key": "x" }))
        .await;
    assert_eq!(status, 401);
    // Matrix traffic is unaffected by the admin token.
    let (status, _) = h
        .request(Method::GET, "/_matrix/client/versions", None, None)
        .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn admin_status_and_session_selection() {
    let h = Harness::start().await;

    // Nothing connected yet: commands that need a session say so.
    let (status, body) = h
        .post(None, "/_ement/keys/export", &json!({ "passphrase": "pw" }))
        .await;
    assert_eq!(status, 409);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("no active sessions")
    );

    h.connect(ALICE, "ALICEDEVICE").await;
    let (status, body) = h.request(Method::GET, "/_ement/status", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(body["homeserver"], h.hs.url.as_str());
    let session = &body["sessions"][0];
    assert_eq!(session["user_id"], ALICE);
    assert_eq!(session["device_id"], "ALICEDEVICE");
    // Fingerprints are printed the way Element shows them, so they can be
    // compared by eye; the homeserver has the same key on record.
    let published = h.hs.lock().device_keys(ALICE, "ALICEDEVICE");
    assert_eq!(
        session["identity_keys"]["ed25519"],
        published["keys"]["ed25519:ALICEDEVICE"]
    );
    assert_eq!(
        session["identity_keys"]["curve25519"],
        published["keys"]["curve25519:ALICEDEVICE"]
    );
    assert_eq!(session["cross_signing"]["has_master"], false);
    assert_eq!(session["backup"]["enabled"], false);

    // With two accounts the target must be named ...
    h.connect(BOB, "BOBDEVICE").await;
    let (status, body) = h
        .post(None, "/_ement/keys/export", &json!({ "passphrase": "pw" }))
        .await;
    assert_eq!(status, 409);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("multiple sessions")
    );
    // ... and naming it works.
    let (status, body) = h
        .post(
            None,
            "/_ement/keys/export",
            &json!({ "passphrase": "pw", "user_id": BOB }),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let (status, _) = h
        .post(
            None,
            "/_ement/keys/export",
            &json!({ "passphrase": "pw", "user_id": "@nobody:hs.test" }),
        )
        .await;
    assert_eq!(status, 404);

    // Unknown routes and malformed requests get clean errors.
    let (status, _) = h.request(Method::GET, "/_ement/nope", None, None).await;
    assert_eq!(status, 404);
    let (status, _) = h.post(None, "/_ement/keys/export", &json!({})).await;
    assert_eq!(status, 400);
}

/// The README's remedy for late keys: export on a device that has them,
/// import on the one that does not, refetch history.
#[tokio::test]
async fn key_export_import_restores_history() {
    let hs = FakeHomeserver::start().await;
    let room = hs.create_room(&[ALICE, BOB], true);
    let old = Harness::builder().homeserver(&hs).start().await;
    let alice = old.connect(ALICE, "ALICEDEVICE").await;
    let bob = old.connect(BOB, "BOBDEVICE").await;
    old.send_text(&alice, &room, "from the archive").await;
    old.sync_timeline(&bob, &room).await;

    let (status, export) = old
        .post(
            None,
            "/_ement/keys/export",
            &json!({ "passphrase": "correct horse", "user_id": BOB }),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(export["count"], 1);
    let blob = export["export"].as_str().unwrap();
    assert!(blob.starts_with("-----BEGIN MEGOLM SESSION DATA-----"));

    // Bob's brand-new device behind a second proxy has no keys.
    let new = Harness::builder().homeserver(&hs).start().await;
    let bob2 = new.connect(BOB, "BOBDEVICE2").await;
    let messages = format!("/_matrix/client/r0/rooms/{}/messages?dir=b", enc(&room));
    let (_, body) = new.get(&bob2, &messages).await;
    assert_utd(&body["chunk"][0]);

    // A wrong passphrase is rejected without importing anything.
    let (status, body) = new
        .post(
            None,
            "/_ement/keys/import",
            &json!({ "passphrase": "wrong", "data": blob }),
        )
        .await;
    assert_eq!(status, 400, "body: {body}");

    let (status, body) = new
        .post(
            None,
            "/_ement/keys/import",
            &json!({ "passphrase": "correct horse", "data": blob }),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["imported"], 1);
    assert_eq!(body["total"], 1);

    // Refetching history now decrypts.
    let (_, body) = new.get(&bob2, &messages).await;
    assert_decrypted_text(&body["chunk"][0], "from the archive");
}

#[tokio::test]
async fn malformed_encrypted_events_do_not_break_sync() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let garbage = json!({ "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": 42 });
    h.hs.inject_event(&room, ALICE, "m.room.encrypted", garbage.clone());
    let unknown = json!({ "algorithm": "org.example.rot13", "ciphertext": "uryyb" });
    h.hs.inject_event(&room, ALICE, "m.room.encrypted", unknown);
    h.send_text(&alice, &room, "still works").await;

    let events = h.sync_timeline(&bob, &room).await;
    assert_eq!(events.len(), 3);
    // Rendered as placeholders (ement silently drops m.room.encrypted), with
    // no key request since there is no session to ask for.
    assert_utd(&events[0]);
    assert_utd(&events[1]);
    assert!(events[0]["unsigned"]["ement_e2ee"]["session_id"].is_null());
    assert_decrypted_text(&events[2], "still works");
    assert!(
        h.hs.requests_to("/sendToDevice/m.room_key_request/")
            .is_empty()
    );
}

/// A client that is not behind the proxy (think Element): its own OlmMachine
/// talking straight to the homeserver.
struct DirectClient {
    olm: OlmMachine,
    token: String,
    hs: FakeHomeserver,
    http: reqwest::Client,
}

impl DirectClient {
    async fn new(hs: &FakeHomeserver, user: &str, device: &str) -> Self {
        let token = format!("token-{device}");
        hs.add_device(user, device, &token);
        let user_id = <&UserId>::try_from(user).unwrap();
        let olm = OlmMachineBuilder::new(user_id, device.into())
            .build()
            .await
            .unwrap();
        Self {
            olm,
            token,
            hs: hs.clone(),
            http: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: Method, path: &str, body: &Value) -> Value {
        let resp = self
            .http
            .request(method, self.hs.url.join(path).unwrap())
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{path}: {}", resp.status());
        resp.json().await.unwrap()
    }
}

/// The `ctl bootstrap` journey: an account with cross-signing, secret storage
/// and a key backup already set up elsewhere; ement joins it via the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_joins_existing_identity_and_restores_backup() {
    let h = Harness::start().await;
    let room = h.hs.create_room(&[BOB], true);
    let room_id = <&RoomId>::try_from(room.as_str()).unwrap();
    let bob = <&UserId>::try_from(BOB).unwrap();

    // Bob's existing client sets up cross-signing ...
    let element = DirectClient::new(&h.hs, BOB, "ELEMENT").await;
    let requests = element.olm.bootstrap_cross_signing(false).await.unwrap();
    let upload = requests.upload_keys_req.expect("device keys to upload");
    let AnyOutgoingRequest::KeysUpload(keys) = upload.request() else {
        panic!("expected a keys upload");
    };
    element
        .call(
            Method::POST,
            "/_matrix/client/v3/keys/upload",
            &json!({ "device_keys": keys.device_keys }),
        )
        .await;
    let signing_keys = &requests.upload_signing_keys_req;
    element
        .call(
            Method::POST,
            "/_matrix/client/v3/keys/device_signing/upload",
            &json!({
                "master_key": signing_keys.master_key,
                "self_signing_key": signing_keys.self_signing_key,
                "user_signing_key": signing_keys.user_signing_key,
            }),
        )
        .await;
    element
        .call(
            Method::POST,
            "/_matrix/client/v3/keys/signatures/upload",
            &serde_json::to_value(&requests.upload_signatures_req.signed_keys).unwrap(),
        )
        .await;

    // ... a key backup ...
    let backup_key = BackupDecryptionKey::new();
    let backup_public_key = backup_key.megolm_v1_public_key();
    backup_public_key.set_version("1".to_owned());
    let backups = element.olm.backup_machine();
    backups
        .save_decryption_key(Some(backup_key.clone()), Some("1".to_owned()))
        .await
        .unwrap();
    backups
        .enable_backup_v1(backup_public_key.clone())
        .await
        .unwrap();

    // ... and secret storage holding the private halves of all of it.
    let ssss = SecretStorageKey::new();
    let key_id = ssss.key_id().to_owned();
    let cross_signing = element
        .olm
        .export_cross_signing_keys()
        .await
        .unwrap()
        .expect("cross-signing keys");
    {
        let mut hs = h.hs.lock();
        hs.backup = Some(Backup {
            version: "1".to_owned(),
            auth_data: json!({ "public_key": backup_public_key.to_base64(), "signatures": {} }),
            rooms: Default::default(),
        });
        let mut account_data = |event_type: &str, content: Value| {
            hs.account_data
                .insert((BOB.to_owned(), event_type.to_owned()), content);
        };
        account_data("m.secret_storage.default_key", json!({ "key": key_id }));
        account_data(
            &format!("m.secret_storage.key.{key_id}"),
            serde_json::to_value(ssss.event_content()).unwrap(),
        );
        for (name, secret) in [
            (
                SecretName::CrossSigningMasterKey,
                cross_signing.master_key.clone(),
            ),
            (
                SecretName::CrossSigningSelfSigningKey,
                cross_signing.self_signing_key.clone(),
            ),
            (
                SecretName::CrossSigningUserSigningKey,
                cross_signing.user_signing_key.clone(),
            ),
            (SecretName::RecoveryKey, Some(backup_key.to_base64())),
        ] {
            let encrypted = ssss.encrypt(secret.unwrap().into_bytes(), &name);
            account_data(
                name.as_str(),
                json!({ "encrypted": { &key_id: encrypted } }),
            );
        }
    }

    // Long before ement, that client sent a message and backed its key up.
    element
        .olm
        .share_room_key(room_id, [bob].into_iter(), EncryptionSettings::default())
        .await
        .unwrap();
    let content: Raw<AnyMessageLikeEventContent> =
        serde_json::from_value(json!({ "msgtype": "m.text", "body": "from before ement" }))
            .unwrap();
    let encrypted = element
        .olm
        .encrypt_room_event_raw(room_id, "m.room.message", &content)
        .await
        .unwrap();
    element
        .call(
            Method::PUT,
            &format!(
                "/_matrix/client/v3/rooms/{}/send/m.room.encrypted/txn1",
                enc(&room)
            ),
            &serde_json::to_value(&encrypted.content).unwrap(),
        )
        .await;
    let (_, request) = backups.backup().await.unwrap().expect("a key to back up");
    element
        .call(
            Method::PUT,
            "/_matrix/client/v3/room_keys/keys?version=1",
            &json!({ "rooms": request.rooms }),
        )
        .await;

    // ement connects through the proxy as a brand-new device: no keys.
    let ement = h.connect(BOB, "EMENT").await;
    let messages = format!("/_matrix/client/r0/rooms/{}/messages?dir=b", enc(&room));
    let (_, body) = h.get(&ement, &messages).await;
    assert_utd(&body["chunk"][0]);

    // `ctl debug event` knows what would fix it: the key is in the backup.
    let event_id = body["chunk"][0]["event_id"].as_str().unwrap();
    let (status, diagnosis) = h
        .request(
            Method::GET,
            &format!("/_ement/debug/event/{}/{}", enc(&room), enc(event_id)),
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "diagnosis: {diagnosis}");
    assert_eq!(diagnosis["outcome"], "undecryptable");
    assert_eq!(diagnosis["room_key"]["held"], false);
    assert_eq!(diagnosis["key_in_server_backup"], true);
    assert!(
        diagnosis["hint"]
            .as_str()
            .unwrap()
            .contains("ctl bootstrap")
    );

    // A wrong recovery key is rejected and changes nothing.
    let wrong = json!({ "recovery_key": SecretStorageKey::new().to_base58() });
    let (status, body) = h.post(None, "/_ement/bootstrap", &wrong).await;
    assert_eq!(status, 500);
    assert!(
        body["error"].as_str().unwrap().contains("recovery key"),
        "error: {body}"
    );
    let (_, status) = h.request(Method::GET, "/_ement/status", None, None).await;
    assert_eq!(status["sessions"][0]["cross_signing"]["has_master"], false);

    // `ctl bootstrap` with the right one.
    let right = json!({ "recovery_key": ssss.to_base58() });
    let (status, report) = h.post(None, "/_ement/bootstrap", &right).await;
    assert_eq!(status, 200, "report: {report}");
    assert_eq!(
        report,
        json!({
            "imported_master_key": true,
            "imported_self_signing_key": true,
            "imported_user_signing_key": true,
            "own_device_signed": true,
            "backup": {
                "backup_version": "1",
                "enabled": true,
                "total_keys_in_backup": 1,
                "imported_keys": 1,
            },
        })
    );

    // History from before the device existed is readable ...
    let (_, body) = h.get(&ement, &messages).await;
    assert_decrypted_text(&body["chunk"][0], "from before ement");

    // ... the device is cross-signed (the green shield in other clients) ...
    let published = h.hs.lock().device_keys(BOB, "EMENT");
    assert_eq!(
        published["signatures"][BOB].as_object().unwrap().len(),
        2,
        "expected the device's own signature plus the self-signing key's: {published}"
    );

    // ... `ctl status` agrees ...
    let (_, status) = h.request(Method::GET, "/_ement/status", None, None).await;
    let session = &status["sessions"][0];
    assert_eq!(
        session["cross_signing"],
        json!({ "has_master": true, "has_self_signing": true, "has_user_signing": true })
    );
    assert_eq!(
        session["backup"],
        json!({ "enabled": true, "version": "1" })
    );

    // ... and room keys created from now on are backed up automatically.
    h.send_text(&ement, &room, "from ement").await;
    h.sync_timeline(&ement, &room).await;
    wait_until("the new room key is backed up", || {
        h.hs.lock().backup.as_ref().unwrap().rooms[&room].len() == 2
    })
    .await;
}

/// The `ctl verify` journey between two of Bob's devices, each behind its own
/// proxy, with the test playing ement's sync loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_verification_between_own_devices() {
    let hs = FakeHomeserver::start().await;
    let one = Harness::builder().homeserver(&hs).start().await;
    let two = Harness::builder().homeserver(&hs).start().await;
    let token_one = one.connect(BOB, "DEVICEONE").await;
    let token_two = two.connect(BOB, "DEVICETWO").await;
    let sync = async || {
        one.get(&token_one, "/_matrix/client/r0/sync").await;
        two.get(&token_two, "/_matrix/client/r0/sync").await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    let show = async |proxy: &Harness, flow: &str| {
        proxy
            .request(Method::GET, &format!("/_ement/verify/{flow}"), None, None)
            .await
            .1
    };

    // DEVICEONE learns about DEVICETWO from its device list, then requests
    // verification.
    let mut flow = None;
    for _ in 0..200 {
        sync().await;
        let (status, body) = one
            .post(
                None,
                "/_ement/verify/start",
                &json!({ "device_id": "DEVICETWO" }),
            )
            .await;
        if status == 200 {
            flow = body["flow_id"].as_str().map(ToOwned::to_owned);
            break;
        }
    }
    let flow = flow.expect("verification could be started");

    // DEVICETWO sees the request in `verify list` and accepts.
    sync().await;
    let (_, list) = two.request(Method::GET, "/_ement/verify", None, None).await;
    assert_eq!(list["requests"][0]["flow_id"], flow.as_str());
    assert_eq!(list["requests"][0]["we_started"], false);
    let (status, body) = two
        .post(None, &format!("/_ement/verify/{flow}/accept"), &json!({}))
        .await;
    assert_eq!(status, 200, "accept: {body}");

    // DEVICEONE starts emoji verification; DEVICETWO accepts it.
    sync().await;
    let (status, body) = one
        .post(
            None,
            &format!("/_ement/verify/{flow}/start-sas"),
            &json!({}),
        )
        .await;
    assert_eq!(status, 200, "start-sas: {body}");
    sync().await;
    let (status, body) = two
        .post(
            None,
            &format!("/_ement/verify/{flow}/sas-accept"),
            &json!({}),
        )
        .await;
    assert_eq!(status, 200, "sas-accept: {body}");

    // The key exchange takes a few sync round trips; then both sides show
    // the same seven emoji.
    let mut emoji = (Value::Null, Value::Null);
    for _ in 0..200 {
        sync().await;
        emoji = (
            show(&one, &flow).await["sas"]["emoji"]["symbols"].clone(),
            show(&two, &flow).await["sas"]["emoji"]["symbols"].clone(),
        );
        if emoji.0.is_array() && emoji.1.is_array() {
            break;
        }
    }
    assert_eq!(emoji.0.as_array().expect("emoji on DEVICEONE").len(), 7);
    assert_eq!(emoji.0, emoji.1);

    // Both confirm the match. The SDK forgets a finished flow on the next
    // sync, so completion is observed through the trust it leaves behind
    // rather than by polling `verify show`.
    for proxy in [&one, &two] {
        let (status, body) = proxy
            .post(None, &format!("/_ement/verify/{flow}/confirm"), &json!({}))
            .await;
        assert_eq!(status, 200, "confirm: {body}");
    }
    let bob = <&UserId>::try_from(BOB).unwrap();
    let trusts = async |proxy: &Harness, token: &str, other: &str| {
        let ctx = proxy.state.sessions.get(token).await.unwrap();
        let device = ctx.olm.get_device(bob, other.into(), None).await.unwrap();
        device.is_some_and(|device| device.is_verified())
    };
    let mut verified = false;
    for _ in 0..200 {
        sync().await;
        verified = trusts(&one, &token_one, "DEVICETWO").await
            && trusts(&two, &token_two, "DEVICEONE").await;
        if verified {
            break;
        }
    }
    assert!(verified, "each device ends up trusting the other");

    // Unknown flows and actions produce readable errors rather than panics.
    let (status, body) = one
        .post(None, "/_ement/verify/nonexistent/accept", &json!({}))
        .await;
    assert_eq!(status, 409);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("no verification flow")
    );
    let (status, _) = one
        .post(
            None,
            &format!("/_ement/verify/{flow}/frobnicate"),
            &json!({}),
        )
        .await;
    assert_eq!(status, 404);
}

// ---- Sync processing ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn to_device_events_seen_on_several_syncs_are_processed_once() {
    let h = Harness::start().await;
    let room = h.hs.create_room(&[ALICE, BOB], true);
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    let bob = h.connect(BOB, "BOBDEVICE").await;
    h.send_text(&alice, &room, "once").await;

    // None of these syncs passes `since`, so nothing acknowledges Alice's
    // room key and the homeserver delivers it every time, as it does to a
    // client that retries a sync whose response got lost.
    for _ in 0..3 {
        let events = h.sync_timeline(&bob, &room).await;
        assert_decrypted_text(&events[0], "once");
    }
    let stats = h.state.sessions.get(&bob).await.unwrap().sync.stats();
    assert_eq!(stats.to_device_events, 1);
    assert_eq!(stats.to_device_duplicates, 2);
    assert_eq!(stats.room_keys_received, 1);

    // The olm channel is unharmed: the conversation goes on in both
    // directions.
    h.send_text(&bob, &room, "reply").await;
    let events = h.sync_timeline(&alice, &room).await;
    assert_decrypted_text(&events[1], "reply");
    h.send_text(&alice, &room, "and again").await;
    let events = h.sync_timeline(&bob, &room).await;
    assert_decrypted_text(&events[2], "and again");
}

#[tokio::test]
async fn omitted_one_time_key_counts_do_not_trigger_uploads() {
    let h = Harness::start().await;
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    // Let start-up settle before taking the baseline: a sync answered just
    // before the first upload landed can cause one extra batch.
    h.sync(&alice).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let uploaded = h.hs.one_time_key_count(ALICE, "ALICEDEVICE");
    assert!(uploaded > 0);

    // A homeserver that says nothing about one-time keys when nothing
    // changed is not saying that there are none left. Publishing a fresh
    // batch on every such sync would push the still-unclaimed keys out of
    // the device's memory while the server keeps handing them out.
    h.hs.lock().omit_one_time_key_counts = true;
    let uploads = || h.hs.requests_to("/keys/upload").len();
    let before = uploads();
    for _ in 0..3 {
        h.sync(&alice).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(h.hs.one_time_key_count(ALICE, "ALICEDEVICE"), uploaded);
    assert_eq!(uploads(), before, "keys were uploaded again");
}

// ---- Placeholder repair ----

/// Alice sends a message whose room key does not reach Bob (yet); Bob syncs
/// and is shown a placeholder. Returns (event ID, Bob's next_batch).
async fn bob_sees_placeholder(h: &Harness, room: &str, alice: &str, bob: &str) -> (String, String) {
    let event_id = h.send_text(alice, room, "worth the wait").await;
    let sync = h.sync(bob).await;
    let events = &sync["rooms"]["join"][room]["timeline"]["events"];
    let placeholder = events.as_array().unwrap().last().unwrap();
    assert_utd(placeholder);
    assert_eq!(placeholder["event_id"], event_id.as_str());
    assert!(
        placeholder["content"]["body"]
            .as_str()
            .unwrap()
            .contains("update in place")
    );
    (event_id, sync["next_batch"].as_str().unwrap().to_owned())
}

fn assert_repair(event: &Value, original_id: &str, text: &str) {
    assert_eq!(event["type"], "m.room.message", "event: {event}");
    assert_eq!(
        event["content"]["m.relates_to"],
        json!({ "rel_type": "m.replace", "event_id": original_id }),
        "event: {event}"
    );
    assert_eq!(event["content"]["m.new_content"]["body"], text);
    assert_eq!(event["content"]["body"], text);
    assert_ne!(event["event_id"], original_id);
    assert_eq!(event["sender"], ALICE);
    assert_eq!(event["unsigned"]["ement_e2ee"]["repairs"], original_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_room_key_repairs_the_placeholder() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    h.hs.lock().hold_to_device = true;
    let (event_id, since) = bob_sees_placeholder(&h, &room, &alice, &bob).await;
    let original_ts = h.hs.event(&event_id)["origin_server_ts"].clone();

    // ement is long-polling: upstream has nothing for it.
    let poll = h.sync_since(&bob, &since, 30_000);
    tokio::pin!(poll);
    let early = tokio::time::timeout(std::time::Duration::from_millis(200), &mut poll).await;
    assert!(early.is_err(), "nothing to report yet");

    // The room key finally arrives. The pending sync returns promptly, well
    // before its 30 s timeout, carrying an edit that replaces the placeholder.
    h.hs.release_to_device();
    let sync = tokio::time::timeout(std::time::Duration::from_secs(5), poll)
        .await
        .expect("the long-poll is answered as soon as the repair is possible");
    let events = sync["rooms"]["join"][&room]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_repair(&events[0], &event_id, "worth the wait");
    // Same position in the timeline and same time as the original.
    assert_eq!(events[0]["origin_server_ts"], original_ts);
    // The homeserver had nothing to say about the room, so its entry is the
    // proxy's own: it repeats the unread counts ement was last given
    // instead of wiping them.
    assert_eq!(
        sync["rooms"]["join"][&room]["unread_notifications"],
        json!({ "notification_count": 1, "highlight_count": 0 })
    );

    // Repaired once: the next sync is an ordinary one.
    let since = sync["next_batch"].as_str().unwrap();
    let sync = h.sync_since(&bob, since, 0).await;
    assert!(sync["rooms"]["join"].get(&room).is_none(), "sync: {sync}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_keys_repair_placeholders() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    // The key share is lost for good.
    h.hs.lock().drop_to_device = true;
    let (event_id, since) = bob_sees_placeholder(&h, &room, &alice, &bob).await;
    h.hs.lock().drop_to_device = false;

    // ement is long-polling, and the homeserver has nothing for it.
    let poll = h.sync_since(&bob, &since, 30_000);
    tokio::pin!(poll);
    let early = tokio::time::timeout(std::time::Duration::from_millis(200), &mut poll).await;
    assert!(early.is_err(), "nothing to report yet");

    // Bob gets the key out of band: an export from a device that has it.
    let (_, export) = h
        .post(
            None,
            "/_ement/keys/export",
            &json!({ "passphrase": "pw", "user_id": ALICE }),
        )
        .await;
    let (status, body) = h
        .post(
            None,
            "/_ement/keys/import",
            &json!({ "passphrase": "pw", "data": export["export"], "user_id": BOB }),
        )
        .await;
    assert_eq!(status, 200, "import: {body}");

    // No need to reopen the room, nor to wait for the long-poll to time
    // out: the proxy answers it now, with the repair.
    let sync = tokio::time::timeout(std::time::Duration::from_secs(5), poll)
        .await
        .expect("the pending sync is answered when the import makes a repair possible");
    let events = &sync["rooms"]["join"][&room]["timeline"]["events"];
    assert_repair(&events[0], &event_id, "worth the wait");
    // Nothing from upstream was consumed on the client's behalf, so it is
    // handed its own position back and resumes from there.
    assert_eq!(sync["next_batch"], since.as_str());
    assert_eq!(
        sync["rooms"]["join"][&room]["unread_notifications"],
        json!({ "notification_count": 1, "highlight_count": 0 })
    );
}

#[tokio::test]
async fn events_redelivered_decrypted_are_not_repaired_again() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    h.hs.lock().hold_to_device = true;
    let (event_id, since) = bob_sees_placeholder(&h, &room, &alice, &bob).await;
    h.hs.release_to_device();

    // A full sync (ement restarted, say) delivers the key and the event
    // itself, now decrypted. An edit on top of that would only add noise.
    let events = h.sync_timeline(&bob, &room).await;
    assert_eq!(events.len(), 1);
    assert_decrypted_text(&events[0], "worth the wait");
    assert_eq!(events[0]["event_id"], event_id.as_str());
    let sync = h.sync_since(&bob, &since, 0).await;
    assert!(sync["rooms"]["join"].get(&room).is_none(), "sync: {sync}");
}

#[tokio::test]
async fn placeholders_in_history_and_other_rooms_are_repaired_too() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let other_room = h.hs.create_room(&[ALICE, BOB], true);
    h.hs.lock().hold_to_device = true;
    let first = h.send_text(&alice, &room, "first").await;
    let second = h.send_text(&alice, &other_room, "second").await;

    // Bob never saw these in a sync; ement fetched them as history.
    let since = h.sync(&bob).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    for room in [&room, &other_room] {
        let path = format!("/_matrix/client/r0/rooms/{}/messages?dir=b", enc(room));
        let (_, body) = h.get(&bob, &path).await;
        assert_utd(&body["chunk"][0]);
    }
    // Placeholders in the notifications buffer are not room timeline
    // entries; they are not tracked (and not double-counted).
    h.get(&bob, "/_matrix/client/r0/notifications").await;
    let ctx = h.state.sessions.get(&bob).await.unwrap();
    assert_eq!(ctx.repairs.pending().len(), 2);

    // The keys arrive with the next sync, which repairs both rooms at once.
    h.hs.release_to_device();
    let sync = h.sync_since(&bob, &since, 0).await;
    let repair_in = |room: &str| sync["rooms"]["join"][room]["timeline"]["events"][0].clone();
    assert_repair(&repair_in(&room), &first, "first");
    assert_repair(&repair_in(&other_room), &second, "second");
    assert!(ctx.repairs.pending().is_empty());
}

// ---- Interactive verification ----

/// A [`VerifyUi`] that answers the emoji question as scripted and keeps
/// what it was shown.
struct ScriptedUi {
    answer: Option<bool>,
    shown: Option<Value>,
    statuses: Vec<String>,
}

impl ScriptedUi {
    fn answering(answer: Option<bool>) -> Self {
        Self {
            answer,
            shown: None,
            statuses: Vec::new(),
        }
    }
}

impl VerifyUi for ScriptedUi {
    fn status(&mut self, message: &str) {
        self.statuses.push(message.to_owned());
    }

    fn confirm_match(&mut self, sas: &Value) -> anyhow::Result<bool> {
        self.shown = Some(sas.clone());
        self.answer.context("no answer (standard input is closed)")
    }
}

fn verify_options(device: Option<&str>) -> verify::Options {
    verify::Options {
        device: device.map(ToOwned::to_owned),
        user_id: None,
        with_user: None,
        timeout: std::time::Duration::from_secs(20),
        poll: std::time::Duration::from_millis(20),
    }
}

/// Two of Bob's devices, each behind its own proxy, that know of each other,
/// with ement connected and syncing on both machines (verification messages
/// only travel inside the client's syncs). Keep the returned sync loops
/// alive for as long as the exchange should go on.
async fn two_devices() -> (Harness, Harness, [SyncLoop; 2]) {
    let hs = FakeHomeserver::start().await;
    let one = Harness::builder().homeserver(&hs).start().await;
    let two = Harness::builder().homeserver(&hs).start().await;
    let token_one = one.connect(BOB, "DEVICEONE").await;
    let token_two = two.connect(BOB, "DEVICETWO").await;
    let syncing = [
        one.keep_syncing(&token_one).await,
        two.keep_syncing(&token_two).await,
    ];
    let bob = <&UserId>::try_from(BOB).unwrap();
    wait_for("DEVICEONE learns about DEVICETWO", async || {
        let ctx = one.state.sessions.get(&token_one).await.unwrap();
        let device = ctx.olm.get_device(bob, "DEVICETWO".into(), None).await;
        device.unwrap().is_some()
    })
    .await;
    (one, two, syncing)
}

/// `ctl verify --device DEVICETWO` on one machine and plain `ctl verify`
/// (waiting for a request) on the other, at the same time.
async fn verify_both(
    one: &Harness,
    two: &Harness,
    ui_one: &mut ScriptedUi,
    ui_two: &mut ScriptedUi,
) -> (anyhow::Result<Value>, anyhow::Result<Value>) {
    let (client_one, client_two) = (one.ctl(), two.ctl());
    let (starting, waiting) = (verify_options(Some("DEVICETWO")), verify_options(None));
    tokio::join!(
        verify::run(&client_one, ui_one, &starting),
        verify::run(&client_two, ui_two, &waiting),
    )
}

async fn trusts(proxy: &Harness, other: &str) -> bool {
    let bob = <&UserId>::try_from(BOB).unwrap();
    let ctx = proxy.state.sessions.list().await.remove(0);
    let device = ctx.olm.get_device(bob, other.into(), None).await.unwrap();
    device.is_some_and(|device| device.is_verified())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_verification_runs_start_to_finish() {
    let (one, two, _ement) = two_devices().await;
    let mut ui_one = ScriptedUi::answering(Some(true));
    let mut ui_two = ScriptedUi::answering(Some(true));

    let (first, second) = verify_both(&one, &two, &mut ui_one, &mut ui_two).await;
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_eq!(first["stage"], "done");
    assert_eq!(second["stage"], "done");
    assert_eq!(first["other_device"], "DEVICETWO");
    assert_eq!(second["other_device"], "DEVICEONE");

    // The one question each user was asked showed the same seven emoji.
    let shown_one = ui_one.shown.unwrap();
    let shown_two = ui_two.shown.unwrap();
    assert_eq!(shown_one["emoji"]["symbols"].as_array().unwrap().len(), 7);
    assert_eq!(shown_one["emoji"]["symbols"], shown_two["emoji"]["symbols"]);
    assert_eq!(shown_one["decimals"], shown_two["decimals"]);
    assert!(ui_one.statuses[0].contains("Accept it on DEVICETWO"));
    assert!(ui_two.statuses[0].contains("Waiting for a verification request"));

    assert!(trusts(&one, "DEVICETWO").await);
    assert!(trusts(&two, "DEVICEONE").await);

    // The SDK forgets a finished flow on the next sync; `verify show` and
    // `verify list` still report how it ended.
    let token_one = one.state.sessions.list().await[0].token.clone();
    one.sync(&token_one).await;
    one.sync(&token_one).await;
    let flow_id = first["flow_id"].as_str().unwrap();
    let (status, shown) = one
        .request(
            Method::GET,
            &format!("/_ement/verify/{flow_id}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "show: {shown}");
    assert_eq!(shown["stage"], "done");
    assert_eq!(shown["finished"], true);
    let (_, list) = one.request(Method::GET, "/_ement/verify", None, None).await;
    assert_eq!(list["requests"], json!([]));
    assert_eq!(list["finished"][0]["flow_id"], flow_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_verification_reports_a_mismatch() {
    let (one, two, _ement) = two_devices().await;
    // One user sees different emoji and says so.
    let mut ui_one = ScriptedUi::answering(Some(true));
    let mut ui_two = ScriptedUi::answering(Some(false));
    let (first, second) = verify_both(&one, &two, &mut ui_one, &mut ui_two).await;

    let said_no = second.unwrap_err().to_string();
    assert!(said_no.contains("did not match"), "{said_no}");
    // The other side is told why, rather than left waiting.
    let other = first.unwrap_err().to_string();
    assert!(other.contains("cancelled"), "{other}");
    assert!(other.to_lowercase().contains("match"), "{other}");
    assert!(!trusts(&one, "DEVICETWO").await);
    assert!(!trusts(&two, "DEVICEONE").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_verification_without_an_answer_cancels_quietly() {
    let (one, two, _ement) = two_devices().await;
    let mut ui_one = ScriptedUi::answering(Some(true));
    // Standard input is closed on this side (run from a script, say).
    let mut ui_two = ScriptedUi::answering(None);
    let (first, second) = verify_both(&one, &two, &mut ui_one, &mut ui_two).await;

    assert!(format!("{:#}", second.unwrap_err()).contains("no answer"));
    // An unanswered question is a cancellation, not a reported mismatch
    // (which would tell the other user they may be under attack).
    let other = first.unwrap_err().to_string();
    assert!(other.contains("cancelled"), "{other}");
    assert!(!other.to_lowercase().contains("match"), "{other}");
    assert!(!trusts(&one, "DEVICETWO").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_verification_times_out() {
    let (one, two, _ement) = two_devices().await;
    let short = |device: Option<&str>| verify::Options {
        timeout: std::time::Duration::from_millis(300),
        ..verify_options(device)
    };

    // Nobody starts a verification.
    let mut ui = ScriptedUi::answering(Some(true));
    let error = verify::run(&two.ctl(), &mut ui, &short(None))
        .await
        .unwrap_err();
    let error = error.to_string();
    assert!(error.contains("no verification request arrived"), "{error}");
    // The usual reason, spelled out.
    assert!(
        error.contains("while ement is connected and syncing"),
        "{error}"
    );

    // Nobody answers ours: it is cancelled, not left dangling on the
    // other device.
    let error = verify::run(&one.ctl(), &mut ui, &short(Some("DEVICETWO")))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("did not complete"), "{error}");
    let (_, list) = one.request(Method::GET, "/_ement/verify", None, None).await;
    assert_eq!(list["finished"][0]["stage"], "cancelled");

    // An unknown device is reported as such.
    let error = verify::run(&one.ctl(), &mut ui, &short(Some("NOSUCHDEVICE")))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("NOSUCHDEVICE"), "{error}");
}

// ---- ctl debug ----

async fn debug_get(h: &Harness, path: &str) -> (u16, Value) {
    h.request(Method::GET, &format!("/_ement/debug/{path}"), None, None)
        .await
}

/// The check with the given ID in a session's (or the proxy's) check list.
fn check_named<'a>(checks: &'a Value, id: &str) -> &'a Value {
    checks
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("no check {id} in {checks}"))
}

#[tokio::test]
async fn debug_check_reports_health_and_remedies() {
    let h = Harness::start().await;

    // Nothing connected yet.
    let (status, report) = debug_get(&h, "check").await;
    assert_eq!(status, 200);
    assert_eq!(check_named(&report["proxy"], "homeserver")["status"], "ok");
    assert_eq!(check_named(&report["proxy"], "clock")["status"], "ok");
    assert_eq!(check_named(&report["proxy"], "store")["status"], "ok");
    let sessions = check_named(&report["proxy"], "sessions");
    assert_eq!(sessions["status"], "warn");
    assert!(sessions["hint"].as_str().unwrap().contains("connect ement"));
    assert_eq!(report["sessions"], json!([]));
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));

    // A fresh device: everything works, but it has not joined the account's
    // cross-signing identity yet, and the report says how to.
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    let ctx = h.state.sessions.get(&alice).await.unwrap();
    wait_for("the device learns of itself", async || {
        let device = ctx.olm.get_device(&ctx.user_id, &ctx.device_id, None).await;
        device.unwrap().is_some()
    })
    .await;
    let (_, report) = debug_get(&h, "check").await;
    let session = &report["sessions"][0];
    assert_eq!(session["user_id"], ALICE);
    assert_eq!(session["device_id"], "ALICEDEVICE");
    let checks = &session["checks"];
    for id in [
        "token",
        "device_keys",
        "one_time_keys",
        "backup",
        "client_sync",
        "placeholders",
    ] {
        assert_eq!(check_named(checks, id)["status"], "ok", "{id}: {checks}");
    }
    for id in ["cross_signing", "device_verified"] {
        let check = check_named(checks, id);
        assert_eq!(check["status"], "warn", "{id}: {checks}");
        assert!(check["hint"].as_str().unwrap().contains("ctl bootstrap"));
    }
    assert_eq!(report["summary"]["fail"], 0);
    assert_eq!(report["summary"]["warn"], 2);
    let one_time_keys = check_named(checks, "one_time_keys")["detail"]
        .as_str()
        .unwrap();
    assert!(
        one_time_keys.ends_with(" on the homeserver"),
        "{one_time_keys}"
    );
}

#[tokio::test]
async fn debug_check_flags_what_is_broken() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let checks_for = |report: &Value, user: &str| {
        report["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|session| session["user_id"] == user)
            .unwrap_or_else(|| panic!("no session for {user} in {report}"))["checks"]
            .clone()
    };

    // A message Bob cannot read ...
    h.hs.lock().drop_to_device = true;
    bob_sees_placeholder(&h, &room, &alice, &bob).await;
    // ... and a session whose client never synced: logged in, nothing more.
    h.hs.add_login("@carol:hs.test", "CAROLDEVICE", "carol-token");
    let login = json!({ "type": "m.login.password", "identifier": { "user": "@carol:hs.test" } });
    h.post(None, "/_matrix/client/r0/login", &login).await;

    let (_, report) = debug_get(&h, "check").await;
    let placeholders = check_named(&checks_for(&report, BOB), "placeholders").clone();
    assert_eq!(placeholders["status"], "warn");
    assert!(
        placeholders["detail"]
            .as_str()
            .unwrap()
            .contains("1 message(s) in 1 room(s)")
    );
    assert!(
        placeholders["hint"]
            .as_str()
            .unwrap()
            .contains("ctl debug event")
    );
    let never_synced = check_named(&checks_for(&report, "@carol:hs.test"), "client_sync").clone();
    assert_eq!(never_synced["status"], "warn");
    assert!(
        never_synced["detail"]
            .as_str()
            .unwrap()
            .contains("has not synced")
    );
    assert!(
        never_synced["hint"]
            .as_str()
            .unwrap()
            .contains("only move while ement")
    );
    // Warnings only, so far.
    assert_eq!(report["summary"]["fail"], 0);

    // A dead token is a failure, and with it nothing else can be judged.
    h.hs.revoke(&alice);
    let (_, report) = debug_get(&h, "check").await;
    let checks = checks_for(&report, ALICE);
    assert_eq!(checks.as_array().unwrap().len(), 1, "{checks}");
    let token = check_named(&checks, "token");
    assert_eq!(token["status"], "fail");
    assert!(token["hint"].as_str().unwrap().contains("log in again"));
    assert_eq!(report["summary"]["fail"], 1);
}

#[tokio::test]
async fn debug_event_explains_each_outcome() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    let readable = h.send_text(&alice, &room, "readable").await;
    h.sync_timeline(&bob, &room).await;
    h.hs.lock().drop_to_device = true;
    h.hs.lock().requests.clear();
    // Rotate Alice's session so the next message needs a key Bob will not get.
    let ctx = h.state.sessions.get(&alice).await.unwrap();
    let room_id = <&RoomId>::try_from(room.as_str()).unwrap();
    ctx.olm.discard_room_key(room_id).await.unwrap();
    let (unreadable, _) = bob_sees_placeholder(&h, &room, &alice, &bob).await;
    let plain =
        h.hs.inject_event(&room, ALICE, "m.room.message", json!({ "body": "plain" }));
    let event = async |event_id: &str| {
        let query = format!(
            "event/{}/{}?user_id={}",
            enc(&room),
            enc(event_id),
            enc(BOB)
        );
        debug_get(&h, &query).await
    };

    let (status, report) = event(&readable).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["outcome"], "decrypted");
    assert_eq!(report["decrypted_type"], "m.room.message");
    assert_eq!(report["room_key"]["held"], true);
    assert_eq!(report["room_key"]["first_known_index"], 0);
    assert_eq!(report["sender"], ALICE);
    assert_eq!(report["algorithm"], "m.megolm.v1.aes-sha2");

    wait_until("Bob's key request is out", || {
        !h.hs
            .requests_to("/sendToDevice/m.room_key_request/")
            .is_empty()
    })
    .await;
    let (_, report) = event(&unreadable).await;
    assert_eq!(report["outcome"], "undecryptable");
    assert_eq!(report["room_key"]["held"], false);
    assert_eq!(report["key_requested"], true);
    // No backup on this account: the hint offers the remaining ways.
    assert!(report["key_in_server_backup"].is_null());
    assert!(
        report["explanation"]
            .as_str()
            .unwrap()
            .contains("never given the room key")
    );
    assert!(report["hint"].as_str().unwrap().contains("keys import"));

    let (_, report) = event(&plain).await;
    assert_eq!(report["outcome"], "not_encrypted");

    let (status, report) = event("$nonexistent").await;
    assert_eq!(status, 409);
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("does not hand out this event")
    );
    let (status, _) = debug_get(&h, &format!("event/not-a-room/x?user_id={}", enc(BOB))).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn debug_room_devices_and_session() {
    let (h, room, alice, bob) = alice_and_bob(true).await;
    h.send_text(&alice, &room, "hello").await;
    h.hs.lock().drop_to_device = true;
    let alice_ctx = h.state.sessions.get(&alice).await.unwrap();
    let room_id = <&RoomId>::try_from(room.as_str()).unwrap();
    alice_ctx.olm.discard_room_key(room_id).await.unwrap();
    let (unreadable, _) = bob_sees_placeholder(&h, &room, &alice, &bob).await;
    let bob_query = format!("user_id={}", enc(BOB));

    // Room, from Bob's side: settings and what is still unreadable.
    let (status, report) = debug_get(&h, &format!("room/{}?{bob_query}", enc(&room))).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["encryption"]["encrypted"], true);
    assert_eq!(report["encryption"]["algorithm"], "m.megolm.v1.aes-sha2");
    assert_eq!(report["joined_per_client_sync"], true);
    assert_eq!(
        report["pending_placeholders"][0]["event_id"],
        unreadable.as_str()
    );
    assert!(report["pending_placeholders"][0]["session_id"].is_string());
    // Bob has only ever received here, so his device has had no reason to
    // fetch Alice's device list: a message from him would first need one.
    assert_eq!(
        report["members"],
        json!([
            { "user_id": ALICE, "devices": 0, "verified_devices": 0 },
            { "user_id": BOB, "devices": 1, "verified_devices": 1 },
        ])
    );
    // Alice has sent: she knows who her messages are encrypted for.
    let alice_query = format!("user_id={}", enc(ALICE));
    let (_, report) = debug_get(&h, &format!("room/{}?{alice_query}", enc(&room))).await;
    assert_eq!(
        report["members"],
        json!([
            { "user_id": ALICE, "devices": 1, "verified_devices": 1 },
            { "user_id": BOB, "devices": 1, "verified_devices": 0 },
        ])
    );
    assert_eq!(report["pending_placeholders"], json!([]));
    let (status, _) = debug_get(&h, &format!("room/nonsense?{bob_query}")).await;
    assert_eq!(status, 400);

    // Devices: Bob's own by default, anyone's on request.
    let (_, own) = debug_get(&h, &format!("devices?{bob_query}")).await;
    assert_eq!(own["user_id"], BOB);
    assert_eq!(own["tracked"], true);
    assert_eq!(own["devices"][0]["device_id"], "BOBDEVICE");
    assert_eq!(own["devices"][0]["this_device"], true);
    assert_eq!(own["devices"][0]["cross_signed"], false);
    let published = h.hs.lock().device_keys(BOB, "BOBDEVICE");
    assert_eq!(
        own["devices"][0]["ed25519"],
        published["keys"]["ed25519:BOBDEVICE"]
    );
    let (_, theirs) = debug_get(&h, &format!("devices?{alice_query}&user={}", enc(BOB))).await;
    assert_eq!(theirs["tracked"], true);
    assert_eq!(theirs["devices"][0]["device_id"], "BOBDEVICE");
    assert_eq!(theirs["devices"][0]["this_device"], false);
    assert_eq!(theirs["devices"][0]["verified"], false);
    let (_, stranger) =
        debug_get(&h, &format!("devices?{bob_query}&user=%40nobody%3Ahs.test")).await;
    assert_eq!(stranger["tracked"], false);
    assert_eq!(stranger["devices"], json!([]));
    let (status, _) = debug_get(&h, &format!("devices?{bob_query}&user=nonsense")).await;
    assert_eq!(status, 400);

    // Session: the numbers behind the checks.
    let (_, session) = debug_get(&h, &format!("session?{bob_query}")).await;
    assert_eq!(session["device_id"], "BOBDEVICE");
    assert_eq!(
        session["identity_keys"]["ed25519"],
        published["keys"]["ed25519:BOBDEVICE"]
    );
    assert_eq!(session["pending_placeholders"], 1);
    assert_eq!(session["to_device"]["room_keys_received"], 1);
    assert!(session["client_sync"]["count"].as_u64().unwrap() >= 2);
    assert!(
        session["store"]
            .as_str()
            .unwrap()
            .ends_with("@bob:hs.test/BOBDEVICE")
    );

    // With two sessions the target must be named, as everywhere else.
    let (status, body) = debug_get(&h, "session").await;
    assert_eq!(status, 409);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("multiple sessions")
    );
}

#[tokio::test]
async fn debug_logs_report_and_log_level() {
    let h = Harness::start().await;
    let alice = h.connect(ALICE, "ALICEDEVICE").await;

    // The harness installs no log sink, so the tail is empty; the route and
    // its parameter checking are what is under test here.
    let (status, logs) = debug_get(&h, "logs?level=warn&limit=5").await;
    assert_eq!(status, 200);
    assert_eq!(logs, json!({ "lines": [] }));
    let (status, body) = debug_get(&h, "logs?level=loud").await;
    assert_eq!(status, 400);
    assert!(body["error"].as_str().unwrap().contains("not a log level"));

    // Likewise it does not own the process's logging.
    let (status, body) = h
        .post(
            None,
            "/_ement/debug/log-level",
            &json!({ "filter": "debug" }),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    let (status, _) = h.post(None, "/_ement/debug/log-level", &json!({})).await;
    assert_eq!(status, 400);

    // The report bundles everything and leaks no credentials.
    let (status, report) = debug_get(&h, "report").await;
    assert_eq!(status, 200);
    assert!(report["generated_at"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(report["check"]["sessions"][0]["user_id"], ALICE);
    assert_eq!(report["sessions"][0]["session"]["device_id"], "ALICEDEVICE");
    assert_eq!(report["sessions"][0]["devices"]["user_id"], ALICE);
    assert!(report["logs"]["lines"].is_array());
    assert!(
        !report.to_string().contains(&alice),
        "the access token leaked"
    );

    let (status, _) = debug_get(&h, "nope").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn debug_api_honours_the_admin_token() {
    let h = Harness::builder().admin_token("s3cret").start().await;
    let (status, _) = debug_get(&h, "check").await;
    assert_eq!(status, 401);
    let (status, _) = debug_get(&h, "report").await;
    assert_eq!(status, 401);
    let (status, _) = h.get("s3cret", "/_ement/debug/check").await;
    assert_eq!(status, 200);
    // `ctl` sends the token it found in the config.
    let report = h.ctl().get("debug/check").await.unwrap();
    assert_eq!(report["summary"]["fail"], 0);
}

/// Run `ement-e2ee ctl ARGS...` against a harness proxy, as the command
/// line would (output goes to the test's captured stdout).
async fn ctl(h: &Harness, args: &[&str]) -> anyhow::Result<()> {
    use clap::Parser as _;
    let cli = crate::Cli::try_parse_from(["ement-e2ee", "ctl"].iter().chain(args)).unwrap();
    let Some(crate::Command::Ctl(args)) = cli.command else {
        panic!("not a ctl command");
    };
    crate::admin::ctl::run_command(&h.ctl(), args.command).await
}

#[tokio::test]
async fn debug_cli_succeeds_when_healthy_and_fails_when_not() {
    let h = Harness::start().await;
    let room = h.hs.create_room(&[ALICE], true);
    let alice = h.connect(ALICE, "ALICEDEVICE").await;
    let event_id = h.send_text(&alice, &room, "hello").await;

    // Warnings (no cross-signing yet) do not fail the command ...
    ctl(&h, &["debug", "check"]).await.unwrap();
    ctl(&h, &["debug", "check", "--json"]).await.unwrap();
    // ... and every inspector renders what the proxy answers.
    ctl(&h, &["status"]).await.unwrap();
    ctl(&h, &["debug", "session"]).await.unwrap();
    ctl(&h, &["debug", "devices"]).await.unwrap();
    ctl(&h, &["debug", "devices", BOB]).await.unwrap();
    ctl(&h, &["debug", "room", &room]).await.unwrap();
    ctl(&h, &["debug", "event", &room, &event_id])
        .await
        .unwrap();
    ctl(&h, &["debug", "event", &room, &event_id, "--json"])
        .await
        .unwrap();
    ctl(&h, &["debug", "logs", "--level", "warn"])
        .await
        .unwrap();
    ctl(&h, &["debug", "report"]).await.unwrap();
    ctl(&h, &["verify", "list"]).await.unwrap();

    // Errors from the proxy come back as errors, with its explanation.
    let error = ctl(&h, &["debug", "event", &room, "$nope"])
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("does not hand out this event"),
        "{error}"
    );
    let error = ctl(&h, &["debug", "session", "--user-id", BOB])
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no active session for @bob:hs.test"),
        "{error}"
    );
    let error = ctl(&h, &["debug", "log-level", "debug"]).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not control its own logging"),
        "{error}"
    );

    // A failed check fails the command.
    h.hs.revoke(&alice);
    let error = ctl(&h, &["debug", "check"]).await.unwrap_err();
    assert_eq!(error.to_string(), "1 check(s) failed");
}
