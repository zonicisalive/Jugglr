use notify_rust::{Notification, Urgency};
use tracing::{info, warn};

/// Send a desktop notification using notify-rust with graceful fallback.
pub fn send_notification(summary: &str, body: &str, urgency_str: Option<&str>) {
    let urgency = match urgency_str.map(|s| s.to_lowercase()).as_deref() {
        Some("critical") => Urgency::Critical,
        Some("low") => Urgency::Low,
        _ => Urgency::Normal,
    };

    let result = Notification::new()
        .appname("Jugglr")
        .summary(summary)
        .body(body)
        .icon("dialog-information")
        .urgency(urgency)
        .timeout(5000)
        .show();

    match result {
        Ok(_) => {
            info!("Desktop notification dispatched: '{}' - '{}'", summary, body);
        }
        Err(e) => {
            warn!("Could not send desktop notification (headless or no notification daemon): {}", e);
        }
    }
}
