use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use tracing::{debug, trace};

pub struct Debouncer;

impl Debouncer {
    /// Create a new debouncer that sends settled paths to `out_sender`.
    /// Returns the input sender to feed inotify events into.
    pub fn start(
        debounce_duration: Duration,
        out_sender: mpsc::Sender<PathBuf>,
    ) -> mpsc::Sender<PathBuf> {
        let (in_sender, mut in_receiver) = mpsc::channel::<PathBuf>(1024);

        tokio::spawn(async move {
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
            let check_interval = Duration::from_millis(50);
            let mut interval = time::interval(check_interval);

            loop {
                tokio::select! {
                    Some(path) = in_receiver.recv() => {
                        trace!("Debouncer registered event for {}", path.display());
                        pending.insert(path, Instant::now());
                    }
                    _ = interval.tick() => {
                        let now = Instant::now();
                        let mut settled = Vec::new();

                        for (path, last_seen) in &pending {
                            if now.duration_since(*last_seen) >= debounce_duration {
                                settled.push(path.clone());
                            }
                        }

                        for path in settled {
                            pending.remove(&path);
                            if path.exists() {
                                debug!("File debounced and ready: {}", path.display());
                                if let Err(e) = out_sender.send(path).await {
                                    trace!("Output channel closed: {}", e);
                                    return;
                                }
                            } else {
                                trace!("Debounced file disappeared before processing: {}", path.display());
                            }
                        }
                    }
                    else => {
                        break;
                    }
                }
            }
        });

        in_sender
    }
}
