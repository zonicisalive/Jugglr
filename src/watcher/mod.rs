pub mod debouncer;

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::config::expand_path;
use crate::engine::RuleEngine;
use debouncer::Debouncer;

pub struct WatcherService {
    engine: Arc<RwLock<RuleEngine>>,
}

impl WatcherService {
    pub fn new(engine: Arc<RwLock<RuleEngine>>) -> Self {
        Self { engine }
    }

    /// Run the native Linux inotify event loop.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let inotify = Inotify::init()?;
        let (settled_tx, mut settled_rx) = mpsc::channel::<PathBuf>(1024);

        // Get debounce duration from global config
        let debounce_ms = {
            let eng = self.engine.read().await;
            eng.config().global.debounce_ms
        };

        let debouncer_tx = Debouncer::start(Duration::from_millis(debounce_ms), settled_tx);

        // Setup watched directories from initial config
        let mut watched_dirs = HashSet::new();
        {
            let eng = self.engine.read().await;
            for rule in &eng.config().rules {
                if rule.enabled {
                    let dir = expand_path(&rule.watch_dir);
                    if !dir.exists() {
                        let _ = fs::create_dir_all(&dir);
                    }
                    if dir.is_dir() {
                        watched_dirs.insert(dir);
                    }
                }
            }
        }

        for dir in &watched_dirs {
            let mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO;
            match inotify.watches().add(dir, mask) {
                Ok(wd) => {
                    info!("👀 Inotify watching: {} (wd: {:?})", dir.display(), wd);
                }
                Err(e) => {
                    warn!("Failed to add inotify watch on {}: {}", dir.display(), e);
                }
            }
        }

        if watched_dirs.is_empty() {
            warn!("No active watch directories found in rules configuration!");
        }

        // Spawn async worker task to process debounced files through the rule engine
        let engine_clone = Arc::clone(&self.engine);
        tokio::spawn(async move {
            while let Some(file_path) = settled_rx.recv().await {
                let eng = engine_clone.read().await;
                eng.process_file(&file_path);
            }
        });

        // Buffer for reading inotify events
        let mut buffer = [0u8; 4096];
        let mut event_stream = inotify.into_event_stream(&mut buffer)?;

        info!("🚀 Jugglr watcher event loop active and ready");

        while let Some(event_or_err) = event_stream.next().await {
            match event_or_err {
                Ok(event) => {
                    if let Some(name) = event.name {
                        let filename_str = name.to_string_lossy();
                        // Ignore hidden temporary download files (e.g. .crdownload, .part, .tmp)
                        if filename_str.starts_with('.') || filename_str.ends_with(".crdownload") || filename_str.ends_with(".part") {
                            continue;
                        }

                        // Reconstruct full path for the event
                        // Find matching watch directory
                        for dir in &watched_dirs {
                            let candidate = dir.join(&*filename_str);
                            if candidate.exists() {
                                let _ = debouncer_tx.send(candidate).await;
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Inotify event stream error: {}", e);
                }
            }
        }

        Ok(())
    }
}
