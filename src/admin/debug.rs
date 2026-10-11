//! `ement-e2ee ctl debug`: ask the running proxy what is wrong. Every
//! subcommand prints a readable summary, or the proxy's raw JSON answer with
//! `--json`.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::Subcommand;
use serde_json::{Value, json};

use crate::admin::ctl::Client;
use crate::crypto::machine::enc;

#[derive(clap::Args)]
pub struct DebugArgs {
    /// Print the proxy's JSON answer instead of the readable summary.
    #[arg(long, global = true)]
    json: bool,
    /// Act on this user's session (needed only with multiple accounts).
    #[arg(long, global = true)]
    user_id: Option<String>,
    #[command(subcommand)]
    command: DebugCommand,
}

#[derive(Subcommand)]
pub enum DebugCommand {
    /// Run every health check and say what to do about each problem. Exits
    /// non-zero if a check fails. Start here.
    Check,
    /// One session in detail: identity, sync activity, pending work.
    Session,
    /// The devices of a user (default: you) and how far each is trusted.
    Devices {
        /// A Matrix user ID.
        user: Option<String>,
    },
    /// A room's encryption settings, who a message would be encrypted for,
    /// and which of its messages are waiting for keys.
    Room { room_id: String },
    /// Why one event can or cannot be decrypted, and what would fix it.
    Event { room_id: String, event_id: String },
    /// Recent log lines, kept in memory by the proxy whatever its log level.
    Logs {
        /// Least severe level to show: error, warn or info.
        #[arg(long, default_value = "info")]
        level: String,
        /// How many lines, counting back from the newest.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Change what the proxy logs to stdout, without restarting it (which
    /// would lose in-flight verifications): `debug`, `ement_e2ee=trace`, ...
    LogLevel { filter: String },
    /// All of the above in one JSON document, to attach to a bug report.
    /// Contains Matrix IDs and public keys; no tokens or private keys.
    Report {
        /// Write to this file instead of standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

pub async fn run(client: &Client, args: DebugArgs) -> anyhow::Result<()> {
    let user_id = args.user_id.as_deref();
    // Query string selecting the session, plus any further parameters.
    let query = |extra: &[(&str, &str)]| {
        let pairs: Vec<String> = user_id
            .map(|user_id| ("user_id", user_id))
            .into_iter()
            .chain(extra.iter().copied())
            .map(|(key, value)| format!("{key}={}", enc(value)))
            .collect();
        if pairs.is_empty() {
            String::new()
        } else {
            format!("?{}", pairs.join("&"))
        }
    };
    let show = |answer: &Value, render: fn(&Value) -> String| {
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(answer).unwrap_or_default()
            );
        } else {
            print!("{}", render(answer));
        }
    };

    match &args.command {
        DebugCommand::Check => {
            let report = client.get("debug/check").await?;
            show(&report, render_check);
            let failed = report["summary"]["fail"].as_u64().unwrap_or(0);
            anyhow::ensure!(failed == 0, "{failed} check(s) failed");
        }
        DebugCommand::Session => {
            let session = client.get(&format!("debug/session{}", query(&[]))).await?;
            show(&session, render_tree);
        }
        DebugCommand::Devices { user } => {
            let extra: Vec<(&str, &str)> =
                user.iter().map(|user| ("user", user.as_str())).collect();
            let devices = client
                .get(&format!("debug/devices{}", query(&extra)))
                .await?;
            show(&devices, render_devices);
        }
        DebugCommand::Room { room_id } => {
            let room = client
                .get(&format!("debug/room/{}{}", enc(room_id), query(&[])))
                .await?;
            show(&room, render_tree);
        }
        DebugCommand::Event { room_id, event_id } => {
            let event = client
                .get(&format!(
                    "debug/event/{}/{}{}",
                    enc(room_id),
                    enc(event_id),
                    query(&[])
                ))
                .await?;
            show(&event, render_event);
        }
        DebugCommand::Logs { level, limit } => {
            let limit = limit.to_string();
            let logs = client
                .get(&format!("debug/logs?level={}&limit={limit}", enc(level)))
                .await?;
            show(&logs, render_logs);
        }
        DebugCommand::LogLevel { filter } => {
            let answer = client
                .post("debug/log-level", &json!({ "filter": filter }))
                .await?;
            show(&answer, |answer| {
                format!(
                    "The proxy now logs at: {}\n(until it restarts; set `log_level` in the config to keep it)\n",
                    answer["filter"].as_str().unwrap_or_default()
                )
            });
        }
        DebugCommand::Report { output } => {
            let report = client.get("debug/report").await?;
            let text = serde_json::to_string_pretty(&report)?;
            match output {
                Some(path) => {
                    std::fs::write(path, text)
                        .with_context(|| format!("failed to write {}", path.display()))?;
                    println!(
                        "Wrote {} (contains Matrix IDs and public keys; no tokens or private keys).",
                        path.display()
                    );
                }
                None => println!("{text}"),
            }
        }
    }
    Ok(())
}

fn human_duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs / 60),
        3600..86_400 => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
        _ => format!("{} d {} h", secs / 86_400, secs % 86_400 / 3600),
    }
}

fn plural(count: u64, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

/// `ctl debug check`: one line per check, the remedy under each problem.
pub fn render_check(report: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ement-e2ee {} — up {}, listening on {}\n",
        report["version"].as_str().unwrap_or("?"),
        human_duration(report["uptime_secs"].as_u64().unwrap_or(0)),
        report["listen"].as_str().unwrap_or("?"),
    );

    let section = |out: &mut String, title: &str, checks: &Value| {
        let _ = writeln!(out, "{title}");
        for check in checks.as_array().into_iter().flatten() {
            let mark = match check["status"].as_str() {
                Some("ok") => '✓',
                Some("warn") => '!',
                _ => '✗',
            };
            let label = check["id"].as_str().unwrap_or("?").replace('_', " ");
            let _ = writeln!(
                out,
                "  {mark} {label:<16} {}",
                check["detail"].as_str().unwrap_or_default()
            );
            if let Some(hint) = check["hint"].as_str() {
                let _ = writeln!(out, "    {:<16} → {hint}", "");
            }
        }
        out.push('\n');
    };
    section(&mut out, "Proxy", &report["proxy"]);
    for session in report["sessions"].as_array().into_iter().flatten() {
        let title = format!(
            "{} ({})",
            session["user_id"].as_str().unwrap_or("?"),
            session["device_id"].as_str().unwrap_or("?")
        );
        section(&mut out, &title, &session["checks"]);
    }

    let count = |key: &str| report["summary"][key].as_u64().unwrap_or(0);
    let _ = writeln!(
        out,
        "{} ok, {}, {}",
        count("ok"),
        plural(count("warn"), "warning"),
        plural(count("fail"), "failure")
    );
    out
}

/// `ctl debug devices`: one row per device.
pub fn render_devices(answer: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Devices of {}",
        answer["user_id"].as_str().unwrap_or("?")
    );
    if answer["tracked"] == false {
        out.push_str(
            "  (not tracked: this device shares no encrypted room with them, so it has not \
             asked for their device list)\n",
        );
    }
    let devices: Vec<&Value> = answer["devices"].as_array().into_iter().flatten().collect();
    if devices.is_empty() {
        out.push_str("  none known\n");
        return out;
    }
    let width = devices
        .iter()
        .filter_map(|device| device["device_id"].as_str())
        .map(|id| id.chars().count())
        .max()
        .unwrap_or(0);
    for device in devices {
        let trust = if device["blacklisted"] == true {
            "blacklisted"
        } else if device["cross_signed"] == true {
            "verified (cross-signed)"
        } else if device["verified"] == true {
            "verified (locally)"
        } else {
            "unverified"
        };
        let _ = writeln!(
            out,
            "  {} {:<width$}  {:<23}  {}  {}",
            if device["this_device"] == true {
                '*'
            } else {
                ' '
            },
            device["device_id"].as_str().unwrap_or("?"),
            trust,
            device["ed25519"].as_str().unwrap_or("(no key)"),
            device["display_name"].as_str().unwrap_or_default(),
        );
    }
    out.push_str("\n  * this device\n");
    out
}

/// `ctl debug event`: the facts, then the explanation and the remedy.
pub fn render_event(report: &Value) -> String {
    let text = |key: &str| report[key].as_str().unwrap_or("–").to_owned();
    let mut out = String::new();
    let _ = writeln!(out, "{} in {}", text("event_id"), text("room_id"));
    let mut row = |label: &str, value: String| {
        let _ = writeln!(out, "  {label:<10} {value}");
    };
    row(
        "sender",
        match report["sender_device"].as_str() {
            Some(device) => format!("{} (device {device})", text("sender")),
            None => text("sender"),
        },
    );
    row(
        "type",
        match report["algorithm"].as_str() {
            Some(algorithm) => format!("{} ({algorithm})", text("type")),
            None => text("type"),
        },
    );
    if report.get("session_id").is_some() {
        row("session", text("session_id"));
    }
    if let Some(key) = report.get("room_key") {
        row(
            "room key",
            if key["held"] == true {
                let origin = if key["imported"] == true {
                    "imported"
                } else {
                    "received directly"
                };
                format!(
                    "held from message index {} on ({origin})",
                    key["first_known_index"].as_u64().unwrap_or(0)
                )
            } else {
                "not held".to_owned()
            },
        );
    }
    if let Some(in_backup) = report["key_in_server_backup"].as_bool() {
        row(
            "backup",
            if in_backup {
                "has the key"
            } else {
                "does not have the key"
            }
            .to_owned(),
        );
    }
    row(
        "outcome",
        match (report["outcome"].as_str(), report["reason"].as_str()) {
            (Some(outcome), Some(reason)) => format!("{outcome}: {reason}"),
            (Some("decrypted"), None) => format!("decrypted ({})", text("decrypted_type")),
            (outcome, _) => outcome.unwrap_or("?").replace('_', " "),
        },
    );

    if let Some(explanation) = report["explanation"].as_str() {
        let mut explanation = explanation.to_owned();
        if let Some(first) = explanation.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        let _ = writeln!(out, "\n{explanation}.");
    }
    if let Some(hint) = report["hint"].as_str() {
        let _ = writeln!(out, "→ {hint}");
    }
    out
}

/// `ctl debug logs`: age, level, source, message.
pub fn render_logs(answer: &Value) -> String {
    let lines: Vec<&Value> = answer["lines"].as_array().into_iter().flatten().collect();
    if lines.is_empty() {
        return "No log lines at this level since the proxy started.\n".to_owned();
    }
    let mut out = String::new();
    for line in lines {
        let _ = writeln!(
            out,
            "{:>10} ago  {:<5} {}: {}",
            human_duration(line["secs_ago"].as_u64().unwrap_or(0)),
            line["level"].as_str().unwrap_or("?"),
            line["target"].as_str().unwrap_or("?"),
            line["message"].as_str().unwrap_or_default(),
        );
    }
    out
}

/// Any JSON answer as an indented outline.
pub fn render_tree(value: &Value) -> String {
    let mut out = String::new();
    write_tree(&mut out, value, 0);
    out
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("–".to_owned()),
        Value::Bool(true) => Some("yes".to_owned()),
        Value::Bool(false) => Some("no".to_owned()),
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => Some(text.clone()),
        Value::Array(items) if items.is_empty() => Some("none".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn write_tree(out: &mut String, value: &Value, depth: usize) {
    let indent = "  ".repeat(depth);
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let label = key.replace('_', " ");
                match scalar(value) {
                    Some(text) => {
                        let _ = writeln!(out, "{indent}{label}: {text}");
                    }
                    None => {
                        let _ = writeln!(out, "{indent}{label}:");
                        write_tree(out, value, depth + 1);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    // One line per entry: `- key: value, key: value`.
                    Value::Object(map) if map.values().all(|v| scalar(v).is_some()) => {
                        let fields: Vec<String> = map
                            .iter()
                            .filter_map(|(key, value)| {
                                Some(format!("{}: {}", key.replace('_', " "), scalar(value)?))
                            })
                            .collect();
                        let _ = writeln!(out, "{indent}- {}", fields.join(", "));
                    }
                    _ => match scalar(item) {
                        Some(text) => {
                            let _ = writeln!(out, "{indent}- {text}");
                        }
                        None => {
                            let _ = writeln!(out, "{indent}-");
                            write_tree(out, item, depth + 1);
                        }
                    },
                }
            }
        }
        other => {
            let _ = writeln!(out, "{indent}{}", scalar(other).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(0), "0 s");
        assert_eq!(human_duration(59), "59 s");
        assert_eq!(human_duration(60), "1 min");
        assert_eq!(human_duration(3599), "59 min");
        assert_eq!(human_duration(3600 * 3 + 12 * 60), "3 h 12 min");
        assert_eq!(human_duration(86_400 * 2 + 3600 * 5), "2 d 5 h");
    }

    #[test]
    fn check_report_lists_problems_with_their_remedies() {
        let report = json!({
            "version": "0.1.0",
            "listen": "127.0.0.1:8009",
            "uptime_secs": 3725,
            "proxy": [
                { "id": "homeserver", "status": "ok", "detail": "answers in 40 ms" },
            ],
            "sessions": [{
                "user_id": "@ben:example.org",
                "device_id": "ABCDEF",
                "checks": [
                    { "id": "token", "status": "ok", "detail": "access token is valid" },
                    { "id": "cross_signing", "status": "warn",
                      "detail": "this device has no cross-signing keys",
                      "hint": "run `ement-e2ee ctl bootstrap`" },
                    { "id": "device_keys", "status": "fail",
                      "detail": "this device's keys are not on the homeserver",
                      "hint": "see the logs" },
                ],
            }],
            "summary": { "ok": 2, "warn": 1, "fail": 1 },
        });
        let text = render_check(&report);
        assert!(text.starts_with("ement-e2ee 0.1.0 — up 1 h 2 min, listening on 127.0.0.1:8009\n"));
        assert!(text.contains("\nProxy\n  ✓ homeserver       answers in 40 ms\n"));
        assert!(text.contains("\n@ben:example.org (ABCDEF)\n  ✓ token "));
        assert!(text.contains("  ! cross signing    this device has no cross-signing keys\n"));
        assert!(text.contains(" → run `ement-e2ee ctl bootstrap`\n"));
        assert!(
            text.contains("  ✗ device keys      this device's keys are not on the homeserver\n")
        );
        assert!(text.ends_with("2 ok, 1 warning, 1 failure\n"));

        // Nothing connected: still a complete, readable report.
        let empty = json!({ "proxy": [], "sessions": [], "summary": {} });
        assert!(render_check(&empty).ends_with("0 ok, 0 warnings, 0 failures\n"));
    }

    #[test]
    fn devices_table_marks_trust_and_this_device() {
        let answer = json!({
            "user_id": "@ben:example.org",
            "tracked": true,
            "devices": [
                { "device_id": "EMENT", "ed25519": "abc", "this_device": true,
                  "verified": true, "cross_signed": true, "display_name": "ement" },
                { "device_id": "PHONE1234", "ed25519": "def", "this_device": false,
                  "verified": true, "cross_signed": false },
                { "device_id": "OLD", "ed25519": null, "verified": false, "cross_signed": false },
                { "device_id": "BAD", "ed25519": "xyz", "blacklisted": true, "verified": false },
            ],
        });
        let text = render_devices(&answer);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "Devices of @ben:example.org");
        assert_eq!(
            lines[1],
            "  * EMENT      verified (cross-signed)  abc  ement"
        );
        assert!(lines[2].starts_with("    PHONE1234  verified (locally)       def"));
        assert!(lines[3].starts_with("    OLD        unverified               (no key)"));
        assert!(lines[4].contains("blacklisted"));

        let untracked = json!({ "user_id": "@x:example.org", "tracked": false, "devices": [] });
        let text = render_devices(&untracked);
        assert!(text.contains("not tracked"));
        assert!(text.contains("none known"));
    }

    #[test]
    fn event_report_explains_and_advises() {
        let report = json!({
            "room_id": "!room:example.org",
            "event_id": "$event",
            "sender": "@alice:example.org",
            "sender_device": "ALICEDEVICE",
            "type": "m.room.encrypted",
            "algorithm": "m.megolm.v1.aes-sha2",
            "session_id": "SESSION",
            "room_key": { "held": false },
            "key_in_server_backup": true,
            "outcome": "undecryptable",
            "reason": "MissingMegolmSession",
            "explanation": "this device was never given the room key, but the key is in your server-side backup",
            "hint": "run `ement-e2ee ctl bootstrap`",
        });
        let text = render_event(&report);
        assert!(text.starts_with("$event in !room:example.org\n"));
        assert!(text.contains("  sender     @alice:example.org (device ALICEDEVICE)\n"));
        assert!(text.contains("  type       m.room.encrypted (m.megolm.v1.aes-sha2)\n"));
        assert!(text.contains("  room key   not held\n"));
        assert!(text.contains("  backup     has the key\n"));
        assert!(text.contains("  outcome    undecryptable: MissingMegolmSession\n"));
        assert!(text.contains("\nThis device was never given the room key, but"));
        assert!(text.ends_with("→ run `ement-e2ee ctl bootstrap`\n"));

        let decrypted = json!({
            "room_id": "!r:hs", "event_id": "$e", "sender": "@a:hs", "type": "m.room.encrypted",
            "room_key": { "held": true, "first_known_index": 3, "imported": true },
            "outcome": "decrypted", "decrypted_type": "m.room.message",
            "explanation": "the event decrypts",
        });
        let text = render_event(&decrypted);
        assert!(text.contains("  room key   held from message index 3 on (imported)\n"));
        assert!(text.contains("  outcome    decrypted (m.room.message)\n"));

        let plain = json!({
            "room_id": "!r:hs", "event_id": "$e", "sender": "@a:hs", "type": "m.room.message",
            "outcome": "not_encrypted", "explanation": "this event was sent in the clear",
        });
        assert!(render_event(&plain).contains("  outcome    not encrypted\n"));
    }

    #[test]
    fn logs_show_age_level_and_source() {
        let answer = json!({ "lines": [
            { "secs_ago": 125, "level": "WARN", "target": "ement_e2ee::crypto::machine",
              "message": "outgoing crypto request failed" },
            { "secs_ago": 3, "level": "INFO", "target": "ement_e2ee::session",
              "message": "session initialized" },
        ] });
        let text = render_logs(&answer);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "     2 min ago  WARN  ement_e2ee::crypto::machine: outgoing crypto request failed"
        );
        assert_eq!(
            lines[1],
            "       3 s ago  INFO  ement_e2ee::session: session initialized"
        );
        assert!(render_logs(&json!({ "lines": [] })).starts_with("No log lines"));
    }

    #[test]
    fn tree_renders_any_answer() {
        let value = json!({
            "user_id": "@ben:example.org",
            "backup": { "enabled": true, "version": null, "room_keys": 12 },
            "members": [
                { "user_id": "@a:hs", "devices": 2 },
                { "user_id": "@b:hs", "devices": 0 },
            ],
            "tags": ["x", "y"],
            "empty": [],
        });
        let text = render_tree(&value);
        assert!(text.contains("user id: @ben:example.org\n"));
        assert!(text.contains("backup:\n  enabled: yes\n  room keys: 12\n  version: –\n"));
        assert!(text.contains(
            "members:\n  - devices: 2, user id: @a:hs\n  - devices: 0, user id: @b:hs\n"
        ));
        assert!(text.contains("tags:\n  - x\n  - y\n"));
        assert!(text.contains("empty: none\n"));
    }
}
