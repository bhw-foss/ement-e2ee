//! Interactive (SAS/emoji) verification, driven from `ement-e2ee ctl verify`.
//! To-device verification events reach the OlmMachine automatically via
//! receive_sync_changes; decrypted in-room ones are fed from decrypt.rs.

use anyhow::Context as _;
use matrix_sdk_crypto::types::requests::OutgoingVerificationRequest;
use matrix_sdk_crypto::{Sas, Verification, VerificationRequest, format_emojis};
use ruma::UserId;
use serde_json::{Value, json};

use crate::crypto::machine;
use crate::session::AccountContext;

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
        "we_started": request.we_started(),
        "is_ready": request.is_ready(),
        "is_done": request.is_done(),
        "is_passive": request.is_passive(),
        "is_cancelled": request.is_cancelled(),
        "their_methods": request.their_supported_methods()
            .map(|m| m.iter().map(ToString::to_string).collect::<Vec<_>>()),
        "state": format!("{:?}", request.state()),
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
        "is_done": sas.is_done(),
        "can_be_presented": sas.can_be_presented(),
        "cancel_info": sas.cancel_info().map(|i| format!("{:?}", i.cancel_code())),
    })
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
/// user, i.e. own-device verification).
pub async fn list(ctx: &AccountContext, with_user: &UserId) -> Value {
    let requests: Vec<Value> = ctx
        .olm
        .get_verification_requests(with_user)
        .iter()
        .map(request_summary)
        .collect();
    json!({ "requests": requests })
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
    Ok(request_summary(&request))
}

/// GET /_ement/verify/{flow} — full state of one flow, including emoji.
pub async fn show(ctx: &AccountContext, with_user: &UserId, flow_id: &str) -> anyhow::Result<Value> {
    let request = get_request(ctx, with_user, flow_id)?;
    let mut out = request_summary(&request);
    if let Some(Verification::SasV1(sas)) = ctx.olm.get_verification(with_user, flow_id) {
        out["sas"] = sas_summary(&sas);
    }
    Ok(out)
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
    Ok(request_summary(&request))
}

/// POST /_ement/verify/{flow}/start-sas — transition an accepted/ready flow
/// into SAS.
pub async fn start_sas(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let request = get_request(ctx, with_user, flow_id)?;
    let (sas, outgoing) = request
        .start_sas()
        .await?
        .context("flow is not ready for SAS (accept it on both sides first)")?;
    send_verification_request(ctx, outgoing).await?;
    Ok(sas_summary(&sas))
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
    Ok(sas_summary(&sas))
}

/// POST /_ement/verify/{flow}/confirm — the emoji matched.
pub async fn confirm(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let sas = get_sas(ctx, with_user, flow_id)?;
    let (outgoing_requests, signature_upload) = sas.confirm().await?;
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
    Ok(sas_summary(&sas))
}

/// POST /_ement/verify/{flow}/cancel
pub async fn cancel(
    ctx: &std::sync::Arc<AccountContext>,
    with_user: &UserId,
    flow_id: &str,
) -> anyhow::Result<Value> {
    let request = get_request(ctx, with_user, flow_id)?;
    if let Some(outgoing) = request.cancel() {
        send_verification_request(ctx, outgoing).await?;
    }
    Ok(request_summary(&request))
}
