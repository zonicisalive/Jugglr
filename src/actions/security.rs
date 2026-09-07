use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use chrono::Local;
use serde_json::json;
use tracing::{info, warn};

use crate::utils::mime::compute_sha256;

/// Strips executable permissions (chmod -x / 0o644) from a file.
pub fn neutralize_permissions(path: &Path, dry_run: bool) -> io::Result<bool> {
    let metadata = fs::metadata(path)?;
    let current_mode = metadata.permissions().mode();
    let is_exec = (current_mode & 0o111) != 0;

    if is_exec {
        let safe_mode = current_mode & !0o111; // Strip execute bits
        if dry_run {
            info!("[DRY-RUN] Would neutralize permissions for {} from {:o} to {:o}", path.display(), current_mode, safe_mode);
        } else {
            fs::set_permissions(path, Permissions::from_mode(safe_mode))?;
            info!("Neutralized executable permissions on {} (mode {:o} -> {:o})", path.display(), current_mode, safe_mode);
        }
        return Ok(true);
    }

    Ok(false)
}

/// Moves a suspicious file into the quarantine directory with restrictive permissions (0o600) and an audit log entry.
pub fn quarantine_file(
    source_path: &Path,
    quarantine_dir: &Path,
    reason: &str,
    dry_run: bool,
) -> io::Result<PathBuf> {
    let filename = source_path.file_name().and_then(|s| s.to_str()).unwrap_or("quarantined_file");
    let sha256 = compute_sha256(source_path).unwrap_or_else(|_| "unknown_sha256".to_string());
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();

    let target_filename = format!("{}_{}", timestamp, filename);
    let target_path = quarantine_dir.join(&target_filename);

    if dry_run {
        info!("[DRY-RUN] Would quarantine {} -> {} [Reason: {}]", source_path.display(), target_path.display(), reason);
        return Ok(target_path);
    }

    // Ensure quarantine directory exists with private permissions (0o700)
    fs::create_dir_all(quarantine_dir)?;
    let _ = fs::set_permissions(quarantine_dir, Permissions::from_mode(0o700));

    // Move into quarantine without ever leaving a partially written file behind: a truncated
    // copy of a malicious file under its quarantine name is both a corrupt artifact and a
    // misleading audit record.
    super::move_file_atomic(source_path, &target_path)?;

    // Restrict permissions on quarantined file to 0o600 (owner read/write only, no exec)
    let _ = fs::set_permissions(&target_path, Permissions::from_mode(0o600));

    // Append to quarantine audit log
    let audit_log_path = quarantine_dir.join("quarantine_audit.jsonl");
    let entry = json!({
        "timestamp": Local::now().to_rfc3339(),
        "original_path": source_path.to_string_lossy(),
        "quarantined_path": target_path.to_string_lossy(),
        "sha256": sha256,
        "reason": reason,
    });

    if let Ok(mut log_file) = OpenOptions::new().create(true).append(true).open(&audit_log_path) {
        let _ = writeln!(log_file, "{}", entry);
    }

    warn!("🚨 Quarantined file: {} -> {} (Reason: {}, SHA-256: {})", source_path.display(), target_path.display(), reason, sha256);
    Ok(target_path)
}
