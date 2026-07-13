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
}
