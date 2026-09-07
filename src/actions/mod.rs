pub mod notify;
pub mod security;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn, error};

use crate::config::expand_path;
use crate::config::schema::{ActionConfig, ActionType, ConflictResolution};
use crate::engine::variables::ContextVariables;
use crate::utils::archive::extract_archive;
use crate::utils::trash::move_to_trash;
use crate::utils::webhook::send_webhook;
use notify::send_notification;
use security::{neutralize_permissions, quarantine_file};

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub success: bool,
    pub source_path: PathBuf,
    pub target_path: Option<PathBuf>,
    pub action_type: ActionType,
    pub message: String,
    /// Rule that produced this outcome. Stamped by `ActionExecutor::execute`; the private
    /// per-action helpers leave it empty because they do not know it.
    pub rule_name: String,
}

pub struct ActionExecutor;

impl ActionExecutor {
    /// Execute actions configured for a rule on the target file.
    pub fn execute(
        action_cfg: &ActionConfig,
        source_path: &Path,
        context: &ContextVariables,
        quarantine_dir: &str,
        rule_name: &str,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        if !source_path.exists() {
            return Ok(ExecutionOutcome {
                success: false,
                source_path: source_path.to_path_buf(),
                target_path: None,
                rule_name: rule_name.to_string(),
                action_type: action_cfg.action,
                message: format!("Source file '{}' no longer exists", source_path.display()),
            });
        }

        // 1. Strip executable permissions if requested
        if action_cfg.strip_executable {
            let _ = neutralize_permissions(source_path, dry_run);
        }

        // 2. Secret audit warning if flagged
        if action_cfg.secret_audit {
            if let Some(secret_type) = crate::engine::conditions::scan_for_secrets(source_path) {
                warn!("⚠️ Secret audit triggered on {}: Detected {}", source_path.display(), secret_type);
                if action_cfg.notify {
                    send_notification(
                        "Jugglr Security Alert: Secret Detected",
                        &format!("Found {} in {}", secret_type, source_path.display()),
                        Some("critical"),
                    );
                }
            }
        }

        // 3. Dispatch primary action
        let mut outcome = match action_cfg.action {
            ActionType::Move => Self::execute_move_or_copy(action_cfg, source_path, context, true, dry_run)?,
            ActionType::Copy => Self::execute_move_or_copy(action_cfg, source_path, context, false, dry_run)?,
            ActionType::Rename => Self::execute_rename(action_cfg, source_path, context, dry_run)?,
            ActionType::Delete => Self::execute_delete(source_path, dry_run)?,
            ActionType::Trash => Self::execute_trash(source_path, dry_run)?,
            ActionType::Extract => Self::execute_extract(action_cfg, source_path, context, dry_run)?,
            ActionType::Symlink => Self::execute_link(action_cfg, source_path, context, true, dry_run)?,
            ActionType::Hardlink => Self::execute_link(action_cfg, source_path, context, false, dry_run)?,
            ActionType::Quarantine => Self::execute_quarantine(action_cfg, source_path, quarantine_dir, dry_run)?,
            ActionType::Script => Self::execute_script(action_cfg, source_path, context, rule_name, dry_run)?,
            ActionType::None => ExecutionOutcome {
                success: true,
                source_path: source_path.to_path_buf(),
                target_path: Some(source_path.to_path_buf()),
                rule_name: String::new(),
                action_type: ActionType::None,
                message: "No action performed".to_string(),
            },
        };

        outcome.rule_name = rule_name.to_string();

        // 4. Send desktop notification if configured (skip if dry_run)
        if !dry_run && action_cfg.notify && outcome.success {
            let summary = format!("Jugglr: {}", rule_name);
            let default_body = format!(
                "{:?} on {}",
                action_cfg.action,
                source_path.file_name().and_then(|s| s.to_str()).unwrap_or("")
            );
            let body = if let Some(ref msg_tpl) = action_cfg.notify_message {
                context.interpolate(msg_tpl)
            } else {
                default_body
            };
            send_notification(&summary, &body, action_cfg.alert_urgency.as_deref());
        }

        // 5. Send Webhook notification if configured (skip if dry_run)
        if !dry_run {
            if let Some(ref wh_url) = action_cfg.webhook_url {
                if outcome.success {
                    let msg = action_cfg.notify_message.as_deref().map(|tpl| context.interpolate(tpl));
                    send_webhook(wh_url, rule_name, &format!("{:?}", action_cfg.action), source_path, msg.as_deref());
                }
            }
        }

        Ok(outcome)
    }

    fn execute_move_or_copy(
        action_cfg: &ActionConfig,
        source: &Path,
        context: &ContextVariables,
        is_move: bool,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        let dest_str = match action_cfg.destination {
            Some(ref d) => context.interpolate_path(d),
            None => {
                return Ok(ExecutionOutcome {
                    success: false,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: if is_move { ActionType::Move } else { ActionType::Copy },
                    message: "Destination path not specified".to_string(),
                })
            }
        };

        let raw_target = expand_path(&dest_str);
        let target_path = resolve_target_path(source, &raw_target, action_cfg.conflict_resolution);

        let target = match target_path {
            Some(t) => t,
            None => {
                info!("Skipping {:?} for {} due to conflict resolution policy", if is_move { "move" } else { "copy" }, source.display());
                return Ok(ExecutionOutcome {
                    success: true,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: if is_move { ActionType::Move } else { ActionType::Copy },
                    message: "Skipped due to destination conflict".to_string(),
                });
            }
        };

        let action_name = if is_move { "Move" } else { "Copy" };

        if dry_run {
            info!("[DRY-RUN] Would {} {} -> {}", action_name, source.display(), target.display());
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: Some(target.clone()),
                rule_name: String::new(),
                action_type: if is_move { ActionType::Move } else { ActionType::Copy },
                message: format!("[DRY-RUN] Would {} to {}", action_name, target.display()),
            });
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        if is_move {
            move_file_atomic(source, &target)?;
            info!("Moved {} -> {}", source.display(), target.display());
        } else {
            copy_file_atomic(source, &target)?;
            info!("Copied {} -> {}", source.display(), target.display());
        }

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: Some(target.clone()),
            rule_name: String::new(),
            action_type: if is_move { ActionType::Move } else { ActionType::Copy },
            message: format!("Successfully {}d to {}", action_name.to_lowercase(), target.display()),
        })
    }

    fn execute_trash(source: &Path, dry_run: bool) -> io::Result<ExecutionOutcome> {
        if dry_run {
            info!("[DRY-RUN] Would move to trash: {}", source.display());
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: None,
                rule_name: String::new(),
                action_type: ActionType::Trash,
                message: "[DRY-RUN] Move to trash planned".to_string(),
            });
        }

        move_to_trash(source)?;
        info!("Moved to trash: {}", source.display());

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: None,
            rule_name: String::new(),
            action_type: ActionType::Trash,
            message: "Moved to trash".to_string(),
        })
    }

    fn execute_extract(
        action_cfg: &ActionConfig,
        source: &Path,
        context: &ContextVariables,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        let dest_str = match action_cfg.destination {
            Some(ref d) => context.interpolate_path(d),
            None => {
                let stem = source.file_stem().and_then(|s| s.to_str()).unwrap_or("extracted");
                let parent = source.parent().unwrap_or_else(|| Path::new("."));
                parent.join(stem).to_string_lossy().to_string()
            }
        };

        let target_dir = expand_path(&dest_str);

        if dry_run {
            info!("[DRY-RUN] Would extract {} -> {}", source.display(), target_dir.display());
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: Some(target_dir),
                rule_name: String::new(),
                action_type: ActionType::Extract,
                message: "[DRY-RUN] Extraction planned".to_string(),
            });
        }

        extract_archive(source, &target_dir)?;
        info!("Extracted archive {} -> {}", source.display(), target_dir.display());

        if action_cfg.delete_archive_after_extract {
            let _ = move_to_trash(source);
        }

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: Some(target_dir.clone()),
            rule_name: String::new(),
            action_type: ActionType::Extract,
            message: format!("Extracted to {}", target_dir.display()),
        })
    }

    fn execute_link(
        action_cfg: &ActionConfig,
        source: &Path,
        context: &ContextVariables,
        is_symlink: bool,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        let dest_str = match action_cfg.destination {
            Some(ref d) => context.interpolate_path(d),
            None => {
                return Ok(ExecutionOutcome {
                    success: false,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: if is_symlink { ActionType::Symlink } else { ActionType::Hardlink },
                    message: "Link destination path missing".to_string(),
                })
            }
        };

        let raw_target = expand_path(&dest_str);
        let target_path = resolve_target_path(source, &raw_target, action_cfg.conflict_resolution);

        let target = match target_path {
            Some(t) => t,
            None => {
                return Ok(ExecutionOutcome {
                    success: true,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: if is_symlink { ActionType::Symlink } else { ActionType::Hardlink },
                    message: "Link creation skipped due to conflict".to_string(),
                });
            }
        };

        let link_type = if is_symlink { "Symlink" } else { "Hardlink" };

        if dry_run {
            info!("[DRY-RUN] Would create {} {} -> {}", link_type, target.display(), source.display());
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: Some(target),
                rule_name: String::new(),
                action_type: if is_symlink { ActionType::Symlink } else { ActionType::Hardlink },
                message: format!("[DRY-RUN] {} planned", link_type),
            });
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        if is_symlink {
            std::os::unix::fs::symlink(source, &target)?;
        } else {
            fs::hard_link(source, &target)?;
        }

        info!("Created {} {} -> {}", link_type, target.display(), source.display());

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: Some(target.clone()),
            rule_name: String::new(),
            action_type: if is_symlink { ActionType::Symlink } else { ActionType::Hardlink },
            message: format!("Created {} at {}", link_type, target.display()),
        })
    }

    fn execute_rename(
        action_cfg: &ActionConfig,
        source: &Path,
        context: &ContextVariables,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        let new_name_template = match action_cfg.destination {
            Some(ref d) => context.interpolate_path(d),
            None => {
                return Ok(ExecutionOutcome {
                    success: false,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: ActionType::Rename,
                    message: "Rename destination template missing".to_string(),
                })
            }
        };

        // A rename produces a new name in the same directory, never a new location: keep only
        // the final component so an absolute or `../` template cannot relocate the file.
        let new_name = match Path::new(&new_name_template).file_name() {
            Some(name) => name.to_owned(),
            None => {
                return Ok(ExecutionOutcome {
                    success: false,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: ActionType::Rename,
                    message: format!("Rename template '{}' does not produce a filename", new_name_template),
                })
            }
        };

        let parent = source.parent().unwrap_or_else(|| Path::new("."));
        let target_raw = parent.join(new_name);
        // Rename targets a file by name, so the directory heuristic in `resolve_target_path`
        // must not apply: `report` is a new name, not a folder to move the file into.
        let target = match resolve_conflict(&target_raw, action_cfg.conflict_resolution) {
            Some(t) => t,
            None => {
                return Ok(ExecutionOutcome {
                    success: true,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: ActionType::Rename,
                    message: "Rename skipped due to conflict".to_string(),
                })
            }
        };

        if dry_run {
            info!("[DRY-RUN] Would rename {} -> {}", source.display(), target.display());
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: Some(target),
                rule_name: String::new(),
                action_type: ActionType::Rename,
                message: "[DRY-RUN] Rename planned".to_string(),
            });
        }

        fs::rename(source, &target)?;
        info!("Renamed {} -> {}", source.display(), target.display());

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: Some(target.clone()),
            rule_name: String::new(),
            action_type: ActionType::Rename,
            message: format!("Renamed to {}", target.display()),
        })
    }

    fn execute_delete(source: &Path, dry_run: bool) -> io::Result<ExecutionOutcome> {
        if dry_run {
            info!("[DRY-RUN] Would delete {}", source.display());
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: None,
                rule_name: String::new(),
                action_type: ActionType::Delete,
                message: "[DRY-RUN] Delete planned".to_string(),
            });
        }

        fs::remove_file(source)?;
        info!("Deleted {}", source.display());

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: None,
            rule_name: String::new(),
            action_type: ActionType::Delete,
            message: "File deleted".to_string(),
        })
    }

    fn execute_quarantine(
        action_cfg: &ActionConfig,
        source: &Path,
        quarantine_dir: &str,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        let q_path = if let Some(ref custom_q) = action_cfg.destination {
            expand_path(custom_q)
        } else {
            expand_path(quarantine_dir)
        };

        let target = quarantine_file(source, &q_path, "Security rule triggered", dry_run)?;

        Ok(ExecutionOutcome {
            success: true,
            source_path: source.to_path_buf(),
            target_path: Some(target.clone()),
            rule_name: String::new(),
            action_type: ActionType::Quarantine,
            message: format!("Quarantined to {}", target.display()),
        })
    }

    fn execute_script(
        action_cfg: &ActionConfig,
        source: &Path,
        context: &ContextVariables,
        rule_name: &str,
        dry_run: bool,
    ) -> io::Result<ExecutionOutcome> {
        let script_cmd = match action_cfg.script {
            Some(ref s) => context.interpolate_shell(s),
            None => {
                return Ok(ExecutionOutcome {
                    success: false,
                    source_path: source.to_path_buf(),
                    target_path: None,
                    rule_name: String::new(),
                    action_type: ActionType::Script,
                    message: "Script command is missing".to_string(),
                })
            }
        };

        if dry_run {
            info!("[DRY-RUN] Would execute script: '{}'", script_cmd);
            return Ok(ExecutionOutcome {
                success: true,
                source_path: source.to_path_buf(),
                target_path: None,
                rule_name: String::new(),
                action_type: ActionType::Script,
                message: "[DRY-RUN] Script execution planned".to_string(),
            });
        }

        info!("Executing shell command: '{}'", script_cmd);

        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(&script_cmd);
        cmd.env("JUGGLR_FILE", source.to_string_lossy().as_ref());
        cmd.env("JUGGLR_RULE", rule_name);

        for (k, v) in &context.values {
            cmd.env(format!("JUGGLR_VAR_{}", k.to_uppercase()), v);
        }

        let output = cmd.output()?;
        let success = output.status.success();

        if success {
            info!("Script executed successfully");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Script failed with exit code {:?}: {}", output.status.code(), stderr);
        }

        Ok(ExecutionOutcome {
            success,
            source_path: source.to_path_buf(),
            target_path: None,
            rule_name: String::new(),
            action_type: ActionType::Script,
            message: format!("Script finished with status {:?}", output.status.code()),
        })
    }
}

/// Upper bound on the `file (n).ext` search before giving up.
const MAX_CONFLICT_CANDIDATES: u32 = 10_000;

/// Counter making concurrent temp filenames distinct within one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary name in `dir`, hidden so the watcher's dotfile filter ignores it.
fn temp_path_in(dir: &Path) -> PathBuf {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".jugglr-tmp-{}-{}", std::process::id(), n))
}

/// Copy `source` to `target` so that `target` never exists in a partially written state.
///
/// `fs::copy` writes straight into the destination name, so an interrupted copy (disk full,
/// source truncated, two rules racing on one file) leaves a corrupt file sitting at the
/// destination under its real name. Copying to a temporary name in the same directory and
/// renaming into place makes the final step atomic: the destination either does not exist yet
/// or is complete.
pub fn copy_file_atomic(source: &Path, target: &Path) -> io::Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp = temp_path_in(dir);

    match fs::copy(source, &tmp).and_then(|_| fs::rename(&tmp, target)) {
        Ok(_) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Move `source` onto `target`, crossing filesystems when necessary.
///
/// `fs::rename` is atomic but only within one filesystem; ~/Downloads and the destination are
/// frequently on different mounts. The fallback copies through a temporary name and only
/// removes the source once the destination is complete and in place, so a failure anywhere
/// leaves the original untouched rather than destroying it alongside a truncated copy.
pub fn move_file_atomic(source: &Path, target: &Path) -> io::Result<()> {
    if fs::rename(source, target).is_ok() {
        return Ok(());
    }

    copy_file_atomic(source, target)?;

    if let Err(e) = fs::remove_file(source) {
        warn!(
            "Copied {} to {} but could not remove the original: {}",
            source.display(),
            target.display(),
            e
        );
    }

    Ok(())
}

/// Resolves target path, handling directory vs file targets and conflict resolution policies.
pub fn resolve_target_path(
    source: &Path,
    target: &Path,
    conflict_resolution: ConflictResolution,
) -> Option<PathBuf> {
    let target_str = target.to_string_lossy();
    let is_dir_target = target.is_dir()
        || target_str.ends_with('/')
        || target_str.ends_with(std::path::MAIN_SEPARATOR)
        || (target.extension().is_none() && source.extension().is_some());

    let final_dest = if is_dir_target {
        let filename = source.file_name()?;
        target.join(filename)
    } else {
        target.to_path_buf()
    };

    // Moving or linking a file onto itself is a no-op, not a conflict. Left to the conflict
    // policy, `RenameWithCounter` would instead produce `file (1).ext` beside it, whose own
    // MOVED_TO event re-enters the engine and yields `file (1) (1).ext`, and so on without end.
    if is_same_file(source, &final_dest) {
        return None;
    }

    resolve_conflict(&final_dest, conflict_resolution)
}

/// Whether two paths refer to the same existing file, comparing resolved locations rather than
/// spelling (`dir/f` and `dir/./f` are the same file).
fn is_same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Apply a conflict resolution policy to an already-resolved destination file path.
///
/// Uses `symlink_metadata` rather than `exists()`: a dangling symlink at the destination is
/// still an occupied name, and `exists()` follows the link and reports it as free.
pub fn resolve_conflict(final_dest: &Path, conflict_resolution: ConflictResolution) -> Option<PathBuf> {
    if fs::symlink_metadata(final_dest).is_err() {
        return Some(final_dest.to_path_buf());
    }

    match conflict_resolution {
        ConflictResolution::Overwrite => Some(final_dest.to_path_buf()),
        ConflictResolution::Skip => None,
        ConflictResolution::RenameWithCounter => {
            let parent = final_dest.parent().unwrap_or_else(|| Path::new("."));
            let stem = final_dest.file_stem()?.to_string_lossy();
            let ext = final_dest.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();

            // Bounded: an unbounded search would spin forever if every candidate kept
            // appearing to exist.
            for counter in 1..=MAX_CONFLICT_CANDIDATES {
                let candidate_name = format!("{} ({}){}", stem, counter, ext);
                let candidate_path = parent.join(candidate_name);
                if fs::symlink_metadata(&candidate_path).is_err() {
                    return Some(candidate_path);
                }
            }

            warn!(
                "Giving up on a free name for {} after {} attempts",
                final_dest.display(),
                MAX_CONFLICT_CANDIDATES
            );
            None
        }
    }
}
