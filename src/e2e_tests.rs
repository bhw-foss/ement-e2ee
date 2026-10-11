//! End-to-end tests: real matrix-sdk-crypto machines on both ends, a fake
//! homeserver in the middle, everything driven over HTTP through the proxy
//! the way ement drives it.

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

use crate::crypto::machine::enc;
use crate::testutil::{ALICE, BOB, Backup, FakeHomeserver, Harness, SERVER_NAME, wait_until};

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

#[tokio::test]
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

    let first = Harness::start_in(hs.clone(), None, store_dir.path()).await;
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
    drop(first);

    // A new proxy process on the same store: same olm identity, and history
    // still decrypts without any new key exchange.
    let second = Harness::start_in(hs, None, store_dir.path()).await;
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
    let h = Harness::start_with(FakeHomeserver::start().await, Some("s3cret")).await;

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
    let old = Harness::start_with(hs.clone(), None).await;
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
    let new = Harness::start_with(hs, None).await;
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
#[tokio::test]
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
#[tokio::test]
async fn sas_verification_between_own_devices() {
    let hs = FakeHomeserver::start().await;
    let one = Harness::start_with(hs.clone(), None).await;
    let two = Harness::start_with(hs, None).await;
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
