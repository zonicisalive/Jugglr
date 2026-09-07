use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use tracing::{debug, trace};

/// A file waiting to settle: when it was last seen changing, and how big it was then.
struct PendingFile {
    last_activity: Instant,
    last_size: u64,
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Whether any process still holds `path` open.
///
/// Size stability alone is not enough. A downloader creates the file, closes it once at
/// 0 bytes (which is a CLOSE_WRITE event), and only then starts transferring. The size sits
/// unchanged at 0 across every poll, looks settled, and the empty placeholder gets acted on
/// while the real download is still arriving. Asking who has the file open answers the actual
/// question — "is anyone still writing this?" — instead of inferring it.
///
/// This process is deliberately not excluded: if jugglr itself still has the file open, an
/// action is already under way on it and a second one must not start.
///
/// ponytail: walks /proc on each poll, O(processes x open fds). Only runs while files are
/// pending; if that ever shows up in a profile, switch to inotify IN_CLOSE_WRITE bookkeeping
/// or fanotify.
fn is_open_by_any_process(path: &Path) -> bool {
    let target = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let procs = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return false, // No /proc: fall back to the size check alone.
    };

    for proc_entry in procs.flatten() {
        // Numeric entries only; the rest of /proc is not a process.
        if proc_entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()).is_none() {
            continue;
        }
        // Unreadable for processes owned by other users; the writer we care about is ours.
        let fds = match fs::read_dir(proc_entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds.flatten() {
            if fs::read_link(fd.path()).is_ok_and(|link| link == target) {
                return true;
            }
        }
    }

    false
}

pub struct Debouncer;

impl Debouncer {
    /// Create a new debouncer that sends settled paths to `out_sender`.
    /// Returns the input sender to feed inotify events into.
    /// Pure event-driven: sleeps completely when no file events are pending.
    pub fn start(
        debounce_duration: Duration,
        out_sender: mpsc::Sender<PathBuf>,
    ) -> mpsc::Sender<PathBuf> {
        let (in_sender, mut in_receiver) = mpsc::channel::<PathBuf>(1024);

        tokio::spawn(async move {
            let mut pending: HashMap<PathBuf, PendingFile> = HashMap::new();
            let check_interval = Duration::from_millis(50);
            let mut interval = time::interval(check_interval);
            // The tick branch is disabled while nothing is pending, so by default tokio would
            // replay every tick missed during idle in one burst the moment a file arrives.
            // Delay skips the backlog and simply waits a fresh interval.
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

            loop {
                let has_pending = !pending.is_empty();

                tokio::select! {
                    Some(path) = in_receiver.recv() => {
                        trace!("Debouncer registered event for {}", path.display());
                        let size = file_size(&path);
                        let entry = pending.entry(path).or_insert(PendingFile {
                            last_activity: Instant::now(),
                            last_size: size,
                        });
                        entry.last_activity = Instant::now();
                        entry.last_size = size;
                    }
                    _ = interval.tick(), if has_pending => {
                        let now = Instant::now();
                        let mut settled = Vec::new();

                        for (path, state) in pending.iter_mut() {
                            // A quiet inotify stream does not mean the writer is finished.
                            // CLOSE_WRITE fires on every close of a writable descriptor, and
                            // downloaders that write straight to the final name (wget, curl,
                            // aria2c) never touch a .part/.crdownload name the filter could
                            // catch. A stall longer than the debounce would otherwise release a
                            // half-written file — fatal for archives, whose index is at the end.
                            // So a file is only settled once its size has stopped changing.
                            let size = match fs::metadata(path) {
                                Ok(meta) => meta.len(),
                                // Gone: settle it so the existence check below discards it.
                                Err(_) => {
                                    settled.push(path.clone());
                                    continue;
                                }
                            };

                            if size != state.last_size {
                                trace!(
                                    "{} still growing ({} -> {} bytes), waiting",
                                    path.display(),
                                    state.last_size,
                                    size
                                );
                                state.last_size = size;
                                state.last_activity = now;
                                continue;
                            }

                            if is_open_by_any_process(path) {
                                trace!("{} is still open by a writer, waiting", path.display());
                                state.last_activity = now;
                                continue;
                            }

                            if now.duration_since(state.last_activity) >= debounce_duration {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A file that is still being written must not be released, however quiet inotify goes.
    #[tokio::test]
    async fn does_not_release_a_file_that_is_still_growing() {
        let dir = std::env::temp_dir().join(format!("jugglr_debounce_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download.zip");
        std::fs::write(&path, b"start").unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(16);
        let debounce = Duration::from_millis(150);
        let input = Debouncer::start(debounce, out_tx);

        // One event, as a downloader's first CLOSE_WRITE would produce.
        input.send(path.clone()).await.unwrap();

        // Keep appending for well over the debounce window without any further events.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[0u8; 1024]).unwrap();
        }

        assert!(
            out_rx.try_recv().is_err(),
            "released a file that was still being written"
        );

        // Writing stops: it must now settle.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(out_rx.try_recv().ok(), Some(path), "never released the finished file");

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod open_file_tests {
    use super::*;

    /// The exact shape of the observed corruption: a file created and closed at zero bytes,
    /// still held open by the downloader, which then keeps writing.
    #[tokio::test]
    async fn does_not_release_an_empty_file_a_writer_still_holds_open() {
        let dir = std::env::temp_dir().join(format!("jugglr_open_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download.zip");

        // Created, and still held open, with nothing written yet.
        let handle = std::fs::File::create(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

        let (out_tx, mut out_rx) = mpsc::channel(16);
        let input = Debouncer::start(Duration::from_millis(100), out_tx);
        input.send(path.clone()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            out_rx.try_recv().is_err(),
            "released a 0-byte file that a writer still had open"
        );

        // Writer finishes and closes.
        drop(handle);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(out_rx.try_recv().ok(), Some(path), "never released the closed file");

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod cross_process_tests {
    use super::*;

    /// The production shape: the writer is a *different* process, as a browser or wget is.
    #[tokio::test]
    async fn detects_a_separate_process_holding_the_file_open() {
        let dir = std::env::temp_dir().join(format!("jugglr_xproc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download.zip");
        std::fs::write(&path, b"").unwrap();

        assert!(!is_open_by_any_process(&path), "nobody holds it yet");

        // A separate process creates the file, holds it open, writes nothing for a while.
        let mut child = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("exec 3>> '{}'; sleep 2", path.display()))
            .spawn()
            .unwrap();

        // Give the shell a moment to open the descriptor.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            is_open_by_any_process(&path),
            "failed to notice another process writing the file"
        );

        child.wait().unwrap();
        assert!(!is_open_by_any_process(&path), "should be free once the writer exits");

        std::fs::remove_dir_all(&dir).ok();
    }
}
