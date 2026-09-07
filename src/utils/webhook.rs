use std::path::Path;
use serde_json::json;
use tracing::{info, warn};
use crate::utils::mime::compute_sha256;

/// Dispatch a JSON webhook notification to Discord, Slack, or custom URL.
pub fn send_webhook(
    webhook_url: &str,
    rule_name: &str,
    action_name: &str,
    file_path: &Path,
    message: Option<&str>,
) {
    let filename = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown");
    let sha256 = compute_sha256(file_path).unwrap_or_else(|_| "N/A".to_string());
    let default_msg = format!("Jugglr triggered rule '{}' with action '{}' on file: {}", rule_name, action_name, filename);
    let text = message.unwrap_or(&default_msg);

    // Discord / Slack compatible payload
    let payload = json!({
        "content": text,
        "username": "Jugglr Daemon",
        "embeds": [
            {
                "title": format!("Jugglr Action: {}", action_name),
                "description": text,
                "color": 3447003,
                "fields": [
                    { "name": "File", "value": filename, "inline": true },
                    { "name": "Rule", "value": rule_name, "inline": true },
                    { "name": "SHA-256", "value": sha256.chars().take(16).collect::<String>(), "inline": false }
                ]
            }
        ]
    });

    let json_body = payload.to_string();
    let url = webhook_url.to_string();

    std::thread::spawn(move || {
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&json_body);

        match resp {
            Ok(r) => {
                info!("Webhook dispatched successfully (Status: {})", r.status());
            }
            Err(e) => {
                warn!("Failed to dispatch webhook: {}", e);
            }
        }
    });
}
