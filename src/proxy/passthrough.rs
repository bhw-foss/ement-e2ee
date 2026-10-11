use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, header};
use axum::response::Response;

use crate::error::ProxyError;
use crate::proxy::AppState;

/// Headers that must not be forwarded in either direction.
const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(name) || name.as_str() == "keep-alive" || name.as_str() == "proxy-connection"
}

fn copy_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    for (name, value) in src {
        if !is_hop_by_hop(name) && name != header::HOST {
            dst.append(name.clone(), value.clone());
        }
    }
}

/// Forward a request to the homeserver verbatim, streaming both bodies.
/// Bytes are not touched, so upstream Content-Length/Content-Encoding stay valid.
pub async fn passthrough(state: &AppState, req: Request) -> Result<Response, ProxyError> {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = state.upstream.url(path_and_query);

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|_| ProxyError::BadRequest("unsupported method".into()))?;

    let mut upstream_req = state.upstream.http.request(method, url);
    {
        // reqwest and axum both use the `http` crate, so headers convert 1:1.
        let mut headers = HeaderMap::new();
        copy_headers(&parts.headers, &mut headers);
        upstream_req = upstream_req.headers(headers);
    }
    let body_stream = body.into_data_stream();
    upstream_req = upstream_req.body(reqwest::Body::wrap_stream(body_stream));

    let upstream_resp = upstream_req.send().await?;

    let mut builder = Response::builder().status(upstream_resp.status().as_u16());
    if let Some(headers) = builder.headers_mut() {
        copy_headers(upstream_resp.headers(), headers);
    }
    let resp = builder
        .body(Body::from_stream(upstream_resp.bytes_stream()))
        .map_err(|e| ProxyError::Internal(e.into()))?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn hop_by_hop_and_host_headers_are_not_forwarded() {
        let mut src = HeaderMap::new();
        for (name, value) in [
            ("host", "localhost:8009"),
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("authorization", "Bearer token"),
            ("content-type", "application/json"),
            ("x-custom", "kept"),
        ] {
            src.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        let mut dst = HeaderMap::new();
        copy_headers(&src, &mut dst);

        let mut forwarded: Vec<&str> = dst.keys().map(HeaderName::as_str).collect();
        forwarded.sort();
        assert_eq!(forwarded, ["authorization", "content-type", "x-custom"]);
    }

    #[test]
    fn repeated_headers_are_all_forwarded() {
        let mut src = HeaderMap::new();
        src.append("set-cookie", HeaderValue::from_static("a=1"));
        src.append("set-cookie", HeaderValue::from_static("b=2"));
        let mut dst = HeaderMap::new();
        copy_headers(&src, &mut dst);
        assert_eq!(dst.get_all("set-cookie").iter().count(), 2);
    }
}
