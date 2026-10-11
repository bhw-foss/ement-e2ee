//! `ctl verify` without a subcommand: walk one emoji verification from
//! request to result, asking the user only whether the emoji match.

use std::io::Write as _;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde_json::{Value, json};

use crate::admin::ctl::Client;

/// How long the side that did not send the request waits for the other to
/// pick emoji verification before starting it itself.
const START_SAS_AFTER: Duration = Duration::from_secs(5);

/// Appended to timeout errors: the usual reason nothing arrives.
const NEEDS_SYNC: &str = " (verification messages only travel while ement is connected and \
                          syncing through the proxy)";

/// What the flow needs from its surroundings. The terminal implements it
/// with stdout and a y/N prompt; tests script it.
pub trait VerifyUi {
    /// Progress worth telling the user about.
    fn status(&mut self, message: &str);
    /// Show the emoji (or numbers) and ask whether the other device shows
    /// the same. An error means no answer could be obtained.
    fn confirm_match(&mut self, sas: &Value) -> anyhow::Result<bool>;
}

pub struct Options {
    /// Start a verification with this device; None waits for a request.
    pub device: Option<String>,
    /// The session to act on (needed only with multiple accounts).
    pub user_id: Option<String>,
    /// The other user (default: our own, i.e. one of our own devices).
    pub with_user: Option<String>,
    /// Give up, cancelling the flow, after this long.
    pub timeout: Duration,
    pub poll: Duration,
}

impl Options {
    fn params(&self) -> Value {
        let mut params = json!({});
        if let Some(user_id) = &self.user_id {
            params["user_id"] = user_id.clone().into();
        }
        if let Some(with_user) = &self.with_user {
            params["with_user"] = with_user.clone().into();
        }
        params
    }

    fn query(&self) -> String {
        let pairs: Vec<String> = [("user_id", &self.user_id), ("with_user", &self.with_user)]
            .into_iter()
            .filter_map(|(key, value)| Some(format!("{key}={}", value.as_ref()?)))
            .collect();
        if pairs.is_empty() {
            String::new()
        } else {
            format!("?{}", pairs.join("&"))
        }
    }
}

fn other_device(flow: &Value) -> &str {
    flow.get("other_device")
        .and_then(Value::as_str)
        .unwrap_or("the other device")
}

/// Run one verification to its end. Returns the finished flow on success;
/// every other ending (cancelled, emoji mismatch, timeout) is an error.
pub async fn run(
    client: &Client,
    ui: &mut dyn VerifyUi,
    options: &Options,
) -> anyhow::Result<Value> {
    let params = options.params();
    let deadline = Instant::now() + options.timeout;

    let flow_id = match &options.device {
        Some(device) => {
            let mut body = params.clone();
            body["device_id"] = device.clone().into();
            let flow = client.post("verify/start", &body).await?;
            ui.status(&format!(
                "Verification requested. Accept it on {device} and choose emoji verification."
            ));
            flow["flow_id"]
                .as_str()
                .context("the proxy returned no flow ID")?
                .to_owned()
        }
        None => {
            ui.status(
                "Waiting for a verification request. Start one from your other device \
                 (in Element: Settings → Sessions → this session → Verify).",
            );
            loop {
                let list = client.get(&format!("verify{}", options.query())).await?;
                let incoming = list["requests"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|flow| !matches!(flow["stage"].as_str(), Some("done" | "cancelled")));
                if let Some(flow_id) = incoming.and_then(|flow| flow["flow_id"].as_str()) {
                    break flow_id.to_owned();
                }
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "no verification request arrived within {} s{NEEDS_SYNC}",
                        options.timeout.as_secs()
                    );
                }
                tokio::time::sleep(options.poll).await;
            }
        }
    };

    let mut last_stage = String::new();
    let mut ready_since: Option<Instant> = None;
    loop {
        let mut body = params.clone();
        body["start_sas"] = ready_since
            .is_some_and(|since| since.elapsed() >= START_SAS_AFTER)
            .into();
        let flow = client
            .post(&format!("verify/{flow_id}/advance"), &body)
            .await?;
        let stage = flow["stage"].as_str().unwrap_or_default().to_owned();
        let stage_changed = stage != last_stage;
        last_stage.clone_from(&stage);

        match stage.as_str() {
            "done" => return Ok(flow),
            "cancelled" => {
                let reason = flow
                    .pointer("/cancel_info/reason")
                    .or_else(|| flow.pointer("/sas/cancel_info/reason"))
                    .and_then(Value::as_str)
                    .unwrap_or("no reason given");
                anyhow::bail!("verification was cancelled: {reason}");
            }
            "compare" => {
                let cancel = format!("verify/{flow_id}/cancel");
                match ui.confirm_match(&flow["sas"]) {
                    Ok(true) => {
                        client
                            .post(&format!("verify/{flow_id}/confirm"), &params)
                            .await?;
                    }
                    Ok(false) => {
                        client
                            .post(&format!("verify/{flow_id}/mismatch"), &params)
                            .await?;
                        anyhow::bail!(
                            "the emoji did not match, so nothing was verified. If you compared \
                             carefully, someone may be interfering with the connection."
                        );
                    }
                    Err(e) => {
                        let _ = client.post(&cancel, &params).await;
                        return Err(e.context("verification cancelled"));
                    }
                }
                // Straight on to see whether the other side already confirmed.
                continue;
            }
            "incoming" if stage_changed => ui.status(&format!(
                "Accepting the request from {}…",
                other_device(&flow)
            )),
            "ready" => {
                ready_since.get_or_insert_with(Instant::now);
                if stage_changed {
                    ui.status("Both devices are ready; starting emoji verification…");
                }
            }
            "sas_incoming" | "key_exchange" if stage_changed => ui.status("Exchanging keys…"),
            "confirmed" if stage_changed => {
                ui.status("Confirmed here. Waiting for the other device to confirm…");
            }
            _ => {}
        }

        if Instant::now() >= deadline {
            let _ = client
                .post(&format!("verify/{flow_id}/cancel"), &params)
                .await;
            anyhow::bail!(
                "verification did not complete within {} s and was cancelled{NEEDS_SYNC}",
                options.timeout.as_secs()
            );
        }
        tokio::time::sleep(options.poll).await;
    }
}

/// The real thing: stdout and a y/N question on stdin.
pub struct TerminalUi;

impl VerifyUi for TerminalUi {
    fn status(&mut self, message: &str) {
        println!("{message}");
    }

    fn confirm_match(&mut self, sas: &Value) -> anyhow::Result<bool> {
        println!("\n{}\n", render_sas(sas)?);
        print!("Does the other device show exactly the same? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        let read = std::io::stdin().read_line(&mut answer)?;
        // A closed stdin is not a "no": that would report a mismatch (a
        // possible attack) to the other device.
        anyhow::ensure!(read > 0, "no answer (standard input is closed)");
        Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
    }
}

/// The short authentication string as text: emoji with their names, or the
/// three numbers when the other device only does decimals.
pub fn render_sas(sas: &Value) -> anyhow::Result<String> {
    if let Some(formatted) = sas.pointer("/emoji/formatted").and_then(Value::as_str) {
        return Ok(formatted.to_owned());
    }
    let decimals: Vec<String> = sas["decimals"]
        .as_array()
        .into_iter()
        .flatten()
        .map(ToString::to_string)
        .collect();
    anyhow::ensure!(decimals.len() == 3, "the proxy offered nothing to compare");
    Ok(decimals.join("   "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_renders_emoji_or_falls_back_to_decimals() {
        let emoji = json!({ "emoji": { "formatted": "🐶  🔑\nDog Key" }, "decimals": [1, 2, 3] });
        assert_eq!(render_sas(&emoji).unwrap(), "🐶  🔑\nDog Key");
        // Emoji were not negotiated: only the numbers may be shown.
        let decimals = json!({ "emoji": null, "decimals": [1234, 5678, 9012] });
        assert_eq!(render_sas(&decimals).unwrap(), "1234   5678   9012");
        assert!(render_sas(&json!({ "emoji": null, "decimals": null })).is_err());
    }

    #[test]
    fn options_name_the_session_and_peer_only_when_given() {
        let mut options = Options {
            device: None,
            user_id: None,
            with_user: None,
            timeout: Duration::from_secs(1),
            poll: Duration::from_millis(1),
        };
        assert_eq!(options.query(), "");
        assert_eq!(options.params(), json!({}));
        options.user_id = Some("@me:example.org".to_owned());
        options.with_user = Some("@you:example.org".to_owned());
        assert_eq!(
            options.query(),
            "?user_id=@me:example.org&with_user=@you:example.org"
        );
        assert_eq!(
            options.params(),
            json!({ "user_id": "@me:example.org", "with_user": "@you:example.org" })
        );
    }
}
