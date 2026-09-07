pub mod debouncer;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

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

        // Keep the watch descriptor for each directory: inotify reports only the bare filename,
        // so the descriptor is the only reliable way to know which watched directory it is in.
        let mut dir_by_wd = HashMap::new();
        for dir in &watched_dirs {
            let mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO;
            match inotify.watches().add(dir, mask) {
                Ok(wd) => {
                    info!("👀 Inotify watching: {} (wd: {:?})", dir.display(), wd);
                    dir_by_wd.insert(wd, dir.clone());
                }
                Err(e) => {
                    warn!("Failed to add inotify watch on {}: {}", dir.display(), e);
                }
            }
        }

        if watched_dirs.is_empty() {
            warn!("No active watch directories found in rules configuration!");
        }

        // Spawn worker task to process debounced files without blocking Tokio async executor.
        //
        // Paths already being processed are skipped. The debouncer only dedups paths still
        // waiting to settle: once a path is handed over, a fresh event for it settles again and
        // would start a second task on the same file. Two concurrent runs both find the
        // destination free, both resolve to the same target, and then both write to it —
        // producing a duplicate move and a corrupt destination.
        let engine_clone = Arc::clone(&self.engine);
        let in_flight: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
        tokio::spawn(async move {
            while let Some(file_path) = settled_rx.recv().await {
                match in_flight.lock() {
                    Ok(mut set) => {
                        if !set.insert(file_path.clone()) {
                            debug!("Already processing {}, skipping duplicate event", file_path.display());
                            continue;
                        }
                    }
                    Err(_) => {
                        error!("In-flight tracking lock poisoned; refusing to process concurrently");
                        continue;
                    }
                }

                let eng_arc = Arc::clone(&engine_clone);
                let done = Arc::clone(&in_flight);
                let path_for_task = file_path.clone();
                tokio::task::spawn_blocking(move || {
                    let eng = eng_arc.blocking_read();
                    eng.process_file(&path_for_task);
                    drop(eng);
                    if let Ok(mut set) = done.lock() {
                        set.remove(&path_for_task);
                    }
                });
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

                        // Reconstruct the full path from the directory this event came from.
                        // Matching by filename against every watched directory would attribute
                        // the event to whichever directory happens to hold a same-named file.
                        if let Some(dir) = dir_by_wd.get(&event.wd) {
                            let candidate = dir.join(&*filename_str);
                            if candidate.exists() {
                                let _ = debouncer_tx.send(candidate).await;
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
