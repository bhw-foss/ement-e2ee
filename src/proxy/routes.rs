use axum::http::Method;
use percent_encoding::percent_decode_str;

/// Classification of an incoming request path. Matching is agnostic to the
/// Matrix version segment (r0 | v1 | v3 | v5 | unstable) because ement mixes
/// r0, v3, and v1 endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Login,
    Sync,
    Send {
        room_id: String,
        event_type: String,
        txn_id: String,
    },
    Messages {
        room_id: String,
    },
    Context {
        room_id: String,
    },
    RoomEvent {
        room_id: String,
    },
    /// GET /notifications: events from any room, each tagged with its room_id.
    Notifications,
    MediaUpload,
    MediaDownload {
        server: String,
        media_id: String,
        /// true for /_matrix/client/v1/media/download (Bearer present),
        /// false for legacy /_matrix/media/*/download (no Bearer).
        authenticated: bool,
    },
    Admin(String),
    Passthrough,
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub fn classify(method: &Method, path: &str) -> Route {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    if let Some(rest) = path.strip_prefix("/_ement/") {
        return Route::Admin(rest.to_owned());
    }
    if path == "/_ement" {
        return Route::Admin(String::new());
    }

    match segments.as_slice() {
        ["_matrix", "client", _v, "login"] if method == Method::POST => Route::Login,
        ["_matrix", "client", _v, "sync"] if method == Method::GET => Route::Sync,
        ["_matrix", "client", _v, "rooms", room, "send", event_type, txn]
            if method == Method::PUT =>
        {
            Route::Send {
                room_id: dec(room),
                event_type: dec(event_type),
                txn_id: dec(txn),
            }
        }
        ["_matrix", "client", _v, "rooms", room, "messages"] if method == Method::GET => {
            Route::Messages { room_id: dec(room) }
        }
        ["_matrix", "client", _v, "rooms", room, "context", _event] if method == Method::GET => {
            Route::Context { room_id: dec(room) }
        }
        ["_matrix", "client", _v, "rooms", room, "event", _event] if method == Method::GET => {
            Route::RoomEvent { room_id: dec(room) }
        }
        ["_matrix", "client", _v, "notifications"] if method == Method::GET => {
            Route::Notifications
        }
        ["_matrix", "media", _v, "upload"] if method == Method::POST => Route::MediaUpload,
        ["_matrix", "client", _v, "media", "download", server, media_id, ..]
            if method == Method::GET =>
        {
            Route::MediaDownload {
                server: dec(server),
                media_id: dec(media_id),
                authenticated: true,
            }
        }
        ["_matrix", "media", _v, "download", server, media_id, ..] if method == Method::GET => {
            Route::MediaDownload {
                server: dec(server),
                media_id: dec(media_id),
                authenticated: false,
            }
        }
        _ => Route::Passthrough,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_core_routes() {
        assert_eq!(
            classify(&Method::POST, "/_matrix/client/r0/login"),
            Route::Login
        );
        assert_eq!(
            classify(&Method::GET, "/_matrix/client/v3/sync"),
            Route::Sync
        );
        assert_eq!(
            classify(
                &Method::PUT,
                "/_matrix/client/r0/rooms/!abc%3Aexample.org/send/m.room.message/1-123"
            ),
            Route::Send {
                room_id: "!abc:example.org".into(),
                event_type: "m.room.message".into(),
                txn_id: "1-123".into(),
            }
        );
        assert_eq!(
            classify(
                &Method::GET,
                "/_matrix/client/v1/media/download/example.org/abcd/file.jpg"
            ),
            Route::MediaDownload {
                server: "example.org".into(),
                media_id: "abcd".into(),
                authenticated: true,
            }
        );
        assert_eq!(
            classify(&Method::GET, "/_matrix/media/r0/download/example.org/abcd"),
            Route::MediaDownload {
                server: "example.org".into(),
                media_id: "abcd".into(),
                authenticated: false,
            }
        );
        // GET /login (flows) is NOT intercepted.
        assert_eq!(
            classify(&Method::GET, "/_matrix/client/r0/login"),
            Route::Passthrough
        );
        assert_eq!(
            classify(&Method::GET, "/_matrix/client/versions"),
            Route::Passthrough
        );
    }

    #[test]
    fn classify_event_fetching_routes() {
        let room = "!abc:example.org".to_owned();
        assert_eq!(
            classify(
                &Method::GET,
                "/_matrix/client/r0/rooms/!abc%3Aexample.org/messages"
            ),
            Route::Messages { room_id: room.clone() }
        );
        assert_eq!(
            classify(
                &Method::GET,
                "/_matrix/client/v3/rooms/%21abc%3Aexample.org/context/%24event"
            ),
            Route::Context { room_id: room.clone() }
        );
        assert_eq!(
            classify(
                &Method::GET,
                "/_matrix/client/v3/rooms/%21abc%3Aexample.org/event/%24event"
            ),
            Route::RoomEvent { room_id: room }
        );
        // ement asks for r0; the endpoint exists as v3 too.
        for version in ["r0", "v3"] {
            assert_eq!(
                classify(
                    &Method::GET,
                    &format!("/_matrix/client/{version}/notifications")
                ),
                Route::Notifications
            );
        }
    }

    #[test]
    fn classify_is_method_sensitive() {
        // The same paths with other methods are different endpoints (or
        // nothing at all) and must pass through untouched.
        for (method, path) in [
            (Method::POST, "/_matrix/client/v3/sync"),
            (Method::POST, "/_matrix/client/r0/notifications"),
            (Method::GET, "/_matrix/client/r0/rooms/!a%3Ab/send/m.room.message/1"),
            (Method::POST, "/_matrix/client/r0/rooms/!a%3Ab/messages"),
            (Method::GET, "/_matrix/media/r0/upload"),
            (Method::POST, "/_matrix/client/v1/media/download/example.org/abcd"),
        ] {
            assert_eq!(classify(&method, path), Route::Passthrough, "{method} {path}");
        }
    }

    #[test]
    fn classify_media_and_admin_routes() {
        for version in ["r0", "v3"] {
            assert_eq!(
                classify(&Method::POST, &format!("/_matrix/media/{version}/upload")),
                Route::MediaUpload
            );
        }
        // A trailing file name on a download does not change the media ID.
        assert_eq!(
            classify(
                &Method::GET,
                "/_matrix/media/v3/download/example.org/abcd/cat%20pic.png"
            ),
            Route::MediaDownload {
                server: "example.org".into(),
                media_id: "abcd".into(),
                authenticated: false,
            }
        );
        // Thumbnails and incomplete download paths are not intercepted.
        for path in [
            "/_matrix/media/r0/thumbnail/example.org/abcd",
            "/_matrix/client/v1/media/thumbnail/example.org/abcd",
            "/_matrix/client/v1/media/download/example.org",
        ] {
            assert_eq!(classify(&Method::GET, path), Route::Passthrough, "{path}");
        }

        assert_eq!(
            classify(&Method::GET, "/_ement/status"),
            Route::Admin("status".into())
        );
        assert_eq!(
            classify(&Method::POST, "/_ement/verify/abc/confirm"),
            Route::Admin("verify/abc/confirm".into())
        );
        assert_eq!(classify(&Method::GET, "/_ement"), Route::Admin(String::new()));
        // Only the exact prefix is the admin API.
        assert_eq!(classify(&Method::GET, "/_ementx/status"), Route::Passthrough);
    }

    #[test]
    fn classify_unrelated_paths() {
        for path in [
            "/",
            "",
            "/_matrix/client/r0/rooms/!a%3Ab/state/m.room.topic",
            "/_matrix/client/r0/rooms/!a%3Ab/send/m.room.message",
            "/_matrix/client/r0/sync/extra",
            "/_matrix/federation/v1/version",
            "/.well-known/matrix/client",
        ] {
            for method in [Method::GET, Method::PUT, Method::POST] {
                assert_eq!(classify(&method, path), Route::Passthrough, "{method} {path}");
            }
        }
    }
}
