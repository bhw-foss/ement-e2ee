//! Interactive (SAS/emoji) verification, driven from `ement-e2ee ctl verify`.
//! To-device verification events reach the OlmMachine automatically via
//! receive_sync_changes; decrypted in-room ones are fed from decrypt.rs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use anyhow::Context as _;
use matrix_sdk_crypto::types::requests::OutgoingVerificationRequest;
use matrix_sdk_crypto::{
    Sas, Verification, VerificationRequest, VerificationRequestState, format_emojis,
};
use ruma::events::key::verification::cancel::CancelCode;
use ruma::{OwnedUserId, UserId};
use serde_json::{Value, json};

use crate::crypto::machine;
use crate::session::AccountContext;

/// How many finished flows to remember per account.
const MAX_FINISHED: usize = 32;

/// Outcomes of recently finished flows. The SDK forgets a flow on the first
/// sync after it ends, which is exactly when the user asks how it went.
#[derive(Default)]
pub struct VerificationLog {
    inner: Mutex<LogInner>,
}

#[derive(Default)]
struct LogInner {
    /// Users (other than our own) that flows were started or looked up with.
    users: HashSet<OwnedUserId>,
    finished: HashMap<String, Value>,
    order: VecDeque<String>,
}

impl VerificationLog {
    fn watch(&self, user: &UserId) {
        self.inner.lock().unwrap().users.insert(user.to_owned());
    }

    fn record(&self, flow_id: &str, summary: Value) {
        let mut inner = self.inner.lock().unwrap();
        if inner.finished.insert(flow_id.to_owned(), summary).is_none() {
            inner.order.push_back(flow_id.to_owned());
            if inner.order.len() > MAX_FINISHED
                && let Some(oldest) = inner.order.pop_front()
            {
                inner.finished.remove(&oldest);
            }
        }
    }

    fn get(&self, flow_id: &str) -> Option<Value> {
        self.inner.lock().unwrap().finished.get(flow_id).cloned()
    }

    fn all(&self) -> Vec<Value> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .filter_map(|flow_id| inner.finished.get(flow_id).cloned())
            .collect()
    }
}

/// Note down every flow that has just ended. The SDK drops an ended flow at
/// the start of the next sync it processes, which can be at any moment while
/// the client is syncing: call this after each processed sync, and in admin
/// actions right after the call that may end a flow, with sync processing
/// paused across the two.
pub fn record_finished(ctx: &AccountContext) {
    let mut users: Vec<OwnedUserId> = ctx
        .verifications
        .inner
        .lock()
        .unwrap()
        .users
        .iter()
        .cloned()
        .collect();
    users.push(ctx.user_id.clone());
    for user in users {
        for request in ctx.olm.get_verification_requests(&user) {
            if request.is_done() || request.is_cancelled() {
                let mut summary = flow_summary(ctx, &request);
                summary["finished"] = true.into();
                ctx.verifications.record(request.flow_id().as_str(), summary);
            }
        }
    }
}

/// Send one verification-flow request produced by the SAS state machine.
/// In-room variants are encrypted when the room is encrypted (matrix-sdk does
/// the same via its room send path).
pub async fn send_verification_request(
    ctx: &std::sync::Arc<AccountContext>,
    request: OutgoingVerificationRequest,
) -> anyhow::Result<()> {
    match request {
        OutgoingVerificationRequest::ToDevice(r) => machine::send_to_device(ctx, &r).await,
        OutgoingVerificationRequest::InRoom(r) => {
            crate::crypto::encrypt::send_room_message_request(ctx, &r).await
        }
    }
}

fn request_summary(request: &VerificationRequest) -> Value {
    json!({
        "flow_id": request.flow_id().as_str(),
        "other_user": request.other_user().as_str(),
        "other_device": request.other_device_id(),
        "we_started": request.we_started(),
        "is_ready": request.is_ready(),
        "is_done": request.is_done(),
        "is_passive": request.is_passive(),
        "is_cancelled": request.is_cancelled(),
        "cancel_info": request.cancel_info().map(|info| cancel_summary(&info)),
        "their_methods": request.their_supported_methods()
            .map(|m| m.iter().map(ToString::to_string).collect::<Vec<_>>()),
        "state": format!("{:?}", request.state()),
    })
}

fn cancel_summary(info: &matrix_sdk_crypto::CancelInfo) -> Value {
    json!({
        "reason": info.reason(),
        "code": info.cancel_code().as_str(),
        "cancelled_by_us": info.cancelled_by_us(),
    })
}

fn sas_summary(sas: &Sas) -> Value {
    let emoji = sas.emoji().map(|emoji| {
        json!({
            "symbols": emoji.iter().map(|e| e.symbol).collect::<Vec<_>>(),
            "descriptions": emoji.iter().map(|e| e.description).collect::<Vec<_>>(),
            "formatted": format_emojis(emoji),
        })
    });
    json!({
        "emoji": emoji,
        "decimals": sas.decimals(),
        "other_device": sas.other_device_id(),
        "we_started": sas.we_started(),
        "has_been_accepted": sas.has_been_accepted(),
        "have_we_confirmed": sas.have_we_confirmed(),
        "is_done": sas.is_done(),
        "is_cancelled": sas.is_cancelled(),
        "can_be_presented": sas.can_be_presented(),
        "cancel_info": sas.cancel_info().map(|info| cancel_summary(&info)),
    })
}

/// Where a flow stands, as one word a front end can act on.
fn stage(request: &VerificationRequest, sas: Option<&Sas>) -> &'static str {
    if request.is_cancelled() || sas.is_some_and(Sas::is_cancelled) {
        return "cancelled";
    }
    if request.is_done() || sas.is_some_and(Sas::is_done) {
        return "done";
    }
    match sas {
        // The other side started emoji verification; we have yet to agree.
        Some(sas) if !sas.we_started() && !sas.has_been_accepted() => "sas_incoming",
        Some(sas) if sas.have_we_confirmed() => "confirmed",
        Some(sas) if sas.can_be_presented() => "compare",
        Some(_) => "key_exchange",
        None if request.is_ready() => "ready",
        None if request.we_started() => "outgoing",
        None => "incoming",
    }
}

fn active_sas(ctx: &AccountContext, request: &VerificationRequest) -> Option<Sas> {
    match ctx
        .olm
        .get_verification(request.other_user(), request.flow_id().as_str())
    {
        Some(Verification::SasV1(sas)) => Some(*sas),
        _ => None,
    }
}

/// Everything about one flow: the request, its SAS if any, and the stage.
fn flow_summary(ctx: &AccountContext, request: &VerificationRequest) -> Value {
    let sas = active_sas(ctx, request);
    let mut summary = request_summary(request);
    summary["stage"] = stage(request, sas.as_ref()).into();
    if let Some(sas) = &sas {
        summary["sas"] = sas_summary(sas);
        // The request no longer names its peer once it is done or cancelled.
        if summary["other_device"].is_null() {
            summary["other_device"] = sas.other_device_id().as_str().into();
        }
    }
    summary
}

fn get_request(
    ctx: &AccountContext,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<VerificationRequest> {
    ctx.olm
        .get_verification_request(with_user, flow_id)
        .with_context(|| format!("no verification flow {flow_id} with {with_user}"))
}

fn get_sas(ctx: &AccountContext, with_user: &UserId, flow_id: &str) -> anyhow::Result<Sas> {
    match ctx.olm.get_verification(with_user, flow_id) {
        Some(Verification::SasV1(sas)) => Ok(*sas),
        Some(_) => anyhow::bail!("flow {flow_id} is not a SAS verification"),
        None => anyhow::bail!(
            "flow {flow_id} has no active SAS yet (accept it first, then start-sas — \
             or wait for the other side to choose emoji verification)"
        ),
    }
}

/// GET /_ement/verify — list verification requests with a user (default: own
/// user, i.e. own-device verification), plus recently finished flows.
pub async fn list(ctx: &AccountContext, with_user: &UserId) -> Value {
    ctx.verifications.watch(with_user);
    record_finished(ctx);
    let requests: Vec<Value> = ctx
        .olm
        .get_verification_requests(with_user)
        .iter()
        .map(|request| flow_summary(ctx, request))
        .collect();
    json!({ "requests": requests, "finished": ctx.verifications.all() })
}

/// POST /_ement/verify/start — request verification of one of our own other
/// devices.
pub async fn start(
    ctx: &std::sync::Arc<AccountContext>,
    device_id: &str,
) -> anyhow::Result<Value> {
    let device = ctx
        .olm
        .get_device(&ctx.user_id, device_id.into(), None)
        .await?
        .with_context(|| format!("device {device_id} not found (has it queried keys yet?)"))?;
    let (request, outgoing) = device.request_verification();
    send_verification_request(ctx, outgoing).await?;
    tracing::info!(device_id, flow_id = request.flow_id().as_str(), "verification requested");
    Ok(flow_summary(ctx, &request))
}

/// GET /_ement/verify/{flow} — full state of one flow, including emoji.
/// A flow that has ended is answered from the log of finished flows.
pub async fn show(ctx: &AccountContext, with_user: &UserId, flow_id: &str) -> anyhow::Result<Value> {
    ctx.verifications.watch(with_user);
    record_finished(ctx);
    let summary = match ctx.olm.get_verification_request(with_user, flow_id) {
        Some(request) => flow_summary(ctx, &request),
        None => ctx
            .verifications
            .get(flow_id)
            .with_context(|| format!("no verification flow {flow_id} with {with_user}"))?,
    };
    settle(ctx, with_user, &summary).await;
    Ok(summary)
}

/// A flow reads as done a moment before its effect, the other device marked
/// as trusted, is in the store. Hold a "done" answer back until it is, so
/// that whoever is told "verified" finds it true. Bounded: a flow whose
/// outcome cannot be observed this way is still reported.
async fn settle(ctx: &AccountContext, with_user: &UserId, summary: &Value) {
    if summary["stage"] != "done" {
        return;
    }
    let Some(device_id) = summary["other_device"].as_str() else {
        return;
    };
    for _ in 0..40 {
        if let Ok(Some(device)) = ctx.olm.get_device(with_user, device_id.into(), None).await
            && (device.is_locally_trusted() || device.is_verified())
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tracing::warn!(%with_user, device_id, "verification finished but the device is not marked as trusted");
}

/// POST /_ement/verify/{flow}/advance — take whichever step needs no human:
/// accept an incoming request, start emoji verification, accept one the
/// other side started. Returns the flow, whose `stage` says what is next.
/// `start_sas` lets the side that did not send the request start SAS too
/// (for peers that wait for us to choose a method).
pub async fn advance(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
    start_sas: bool,
) -> anyhow::Result<Value> {
    ctx.verifications.watch(with_user);
    let Some(request) = ctx.olm.get_verification_request(with_user, flow_id) else {
        return show(ctx, with_user, flow_id).await;
    };
    let sas = active_sas(ctx, &request);
    match stage(&request, sas.as_ref()) {
        "incoming" => {
            if matches!(request.state(), VerificationRequestState::Requested { .. })
                && let Some(outgoing) = request.accept()
            {
                send_verification_request(ctx, outgoing).await?;
            }
        }
        "ready" if request.we_started() || start_sas => {
            if let Some((_, outgoing)) = request.start_sas().await? {
                send_verification_request(ctx, outgoing).await?;
            }
        }
        "sas_incoming" => {
            if let Some(outgoing) = sas.as_ref().and_then(Sas::accept) {
                send_verification_request(ctx, outgoing).await?;
            }
        }
        _ => {}
    }
    record_finished(ctx);
    show(ctx, with_user, flow_id).await
}

/// POST /_ement/verify/{flow}/accept — accept an incoming request (e.g. one
/// started from Element).
pub async fn accept(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let request = get_request(ctx, with_user, flow_id)?;
    let outgoing = request
        .accept()
        .context("flow cannot be accepted in its current state")?;
    send_verification_request(ctx, outgoing).await?;
    Ok(flow_summary(ctx, &request))
}

/// POST /_ement/verify/{flow}/start-sas — transition an accepted/ready flow
/// into SAS.
pub async fn start_sas(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let request = get_request(ctx, with_user, flow_id)?;
    let (_, outgoing) = request
        .start_sas()
        .await?
        .context("flow is not ready for SAS (accept it on both sides first)")?;
    send_verification_request(ctx, outgoing).await?;
    Ok(flow_summary(ctx, &request))
}

/// POST /_ement/verify/{flow}/sas-accept — accept a SAS started by the other
/// side; emoji become available after their next message.
pub async fn sas_accept(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let sas = get_sas(ctx, with_user, flow_id)?;
    if let Some(outgoing) = sas.accept() {
        send_verification_request(ctx, outgoing).await?;
    }
    show(ctx, with_user, flow_id).await
}

/// POST /_ement/verify/{flow}/confirm — the emoji matched.
pub async fn confirm(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let sas = get_sas(ctx, with_user, flow_id)?;
    let (outgoing_requests, signature_upload) = {
        let _pause = ctx.sync.pause().await;
        let confirmed = sas.confirm().await?;
        // Done already if the other side confirmed first.
        record_finished(ctx);
        confirmed
    };
    for outgoing in outgoing_requests {
        send_verification_request(ctx, outgoing).await?;
    }
    if let Some(signature_upload) = signature_upload {
        let (status, body) = ctx
            .upstream
            .json_request(
                reqwest::Method::POST,
                "/_matrix/client/v3/keys/signatures/upload",
                &ctx.token,
                Some(&serde_json::to_value(&signature_upload.signed_keys)?),
            )
            .await?;
        if !status.is_success() {
            anyhow::bail!("signature upload after verification failed: {status} {body}");
        }
    }
    machine::pump(ctx).await;
    record_finished(ctx);
    show(ctx, with_user, flow_id).await
}

/// POST /_ement/verify/{flow}/mismatch — the emoji did not match. Tells the
/// other device why, which a plain cancel would not.
pub async fn mismatch(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let sas = get_sas(ctx, with_user, flow_id)?;
    let outgoing = {
        let _pause = ctx.sync.pause().await;
        let outgoing = sas.cancel_with_code(CancelCode::MismatchedSas);
        record_finished(ctx);
        outgoing
    };
    if let Some(outgoing) = outgoing {
        send_verification_request(ctx, outgoing).await?;
    }
    show(ctx, with_user, flow_id).await
}

/// POST /_ement/verify/{flow}/cancel
pub async fn cancel(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let request = get_request(ctx, with_user, flow_id)?;
    let outgoing = {
        let _pause = ctx.sync.pause().await;
        let outgoing = request.cancel();
        record_finished(ctx);
        outgoing
    };
    if let Some(outgoing) = outgoing {
        send_verification_request(ctx, outgoing).await?;
    }
    show(ctx, with_user, flow_id).await
}
