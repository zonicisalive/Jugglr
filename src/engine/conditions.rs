use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;
use glob::Pattern;
use regex::Regex;

use crate::config::schema::{ConditionGroup, MatchMode};
use crate::utils::audio::extract_audio_tags;
use crate::utils::exif::extract_exif;
use crate::utils::mime::{detect_mime, is_binary};

/// Evaluation result containing whether conditions matched and extracted regex variables.
#[derive(Debug, Clone, Default)]
pub struct EvaluationResult {
    pub matched: bool,
    pub captures: HashMap<String, String>,
    pub mime_type: Option<String>,
    pub secret_found: Option<String>,
    pub is_double_ext: bool,
    pub has_dangerous_perms: bool,
    pub is_suspicious_desktop: bool,
}

pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluate a condition group against a file at `path`.
    pub fn evaluate(group: &ConditionGroup, path: &Path) -> io::Result<EvaluationResult> {
        let mut captures = HashMap::new();
        let mut secret_found = None;
        let mut is_double_ext = false;
        let mut has_dangerous_perms = false;
        let mut is_suspicious_desktop = false;

        // Fetch file metadata
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_e) => return Ok(EvaluationResult { matched: false, ..Default::default() }),
        };

        let file_size = metadata.len();
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

        // Lazy evaluated mime
        let mut cached_mime: Option<String> = None;

        let mut condition_results = Vec::new();

        // 1. Extensions check
        if let Some(ref exts) = group.extensions {
            let matched = exts.iter().any(|ext| ext.trim_start_matches('.').eq_ignore_ascii_case(&extension));
            condition_results.push(matched);
        }

        // 2. Name regex match & capture extraction
        if let Some(ref regex_str) = group.name_regex {
            if let Ok(re) = Regex::new(regex_str) {
                if let Some(caps) = re.captures(filename) {
                    condition_results.push(true);
                    for (i, cap) in caps.iter().enumerate() {
                        if let Some(m) = cap {
                            captures.insert(format!("regex_match_{}", i), m.as_str().to_string());
                        }
                    }
                    for name in re.capture_names().flatten() {
                        if let Some(m) = caps.name(name) {
                            captures.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                } else {
                    condition_results.push(false);
                }
            } else {
                condition_results.push(false);
            }
        }

        // 3. Name glob match
        if let Some(ref glob_str) = group.name_glob {
            if let Ok(pattern) = Pattern::new(glob_str) {
                condition_results.push(pattern.matches(filename));
            } else {
                condition_results.push(false);
            }
        }

        // 4. Min size check
        if let Some(min_size) = group.min_size_bytes {
            condition_results.push(file_size >= min_size);
        }

        // 5. Max size check
        if let Some(max_size) = group.max_size_bytes {
            condition_results.push(file_size <= max_size);
        }

        // 6. MIME types check
        if let Some(ref expected_mimes) = group.mime_types {
            if cached_mime.is_none() {
                cached_mime = detect_mime(path).ok();
            }
            if let Some(ref actual_mime) = cached_mime {
                let matched = expected_mimes.iter().any(|expected| {
                    if expected.ends_with("/*") {
                        let prefix = expected.trim_end_matches("/*");
                        actual_mime.starts_with(prefix)
                    } else {
                        expected.eq_ignore_ascii_case(actual_mime)
                    }
                });
                condition_results.push(matched);
            } else {
                condition_results.push(false);
            }
        }

        // 7. Content contains (plaintext keywords)
        if let Some(ref keywords) = group.content_contains {
            if !keywords.is_empty() {
                let matched = match read_file_prefix_or_content(path, 1024 * 1024) {
                    Ok(content) => keywords.iter().any(|kw| content.contains(kw)),
                    Err(_) => false,
                };
                condition_results.push(matched);
            }
        }

        // 8. Content regex match
        if let Some(ref content_re_str) = group.content_regex {
            let matched = match Regex::new(content_re_str) {
                Ok(re) => {
                    match read_file_prefix_or_content(path, 1024 * 1024) {
                        Ok(content) => {
                            if let Some(caps) = re.captures(&content) {
                                for (i, cap) in caps.iter().enumerate() {
                                    if let Some(m) = cap {
                                        captures.insert(format!("content_match_{}", i), m.as_str().to_string());
                                    }
                                }
                                for name in re.capture_names().flatten() {
                                    if let Some(m) = caps.name(name) {
                                        captures.insert(name.to_string(), m.as_str().to_string());
                                    }
                                }
                                true
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            };
            condition_results.push(matched);
        }

        // 9. Double extension check
        if let Some(require_double_ext) = group.double_extension {
            let detected = is_suspicious_double_extension(filename);
            is_double_ext = detected;
            condition_results.push(detected == require_double_ext);
        }

        // 10. Dangerous permissions check
        if let Some(require_dangerous_perms) = group.dangerous_permissions {
            let perms = metadata.permissions().mode();
            let is_exec = (perms & 0o111) != 0;
            let binary = is_binary(path).unwrap_or(false);
            let dangerous = is_exec && (!binary || is_suspicious_double_extension(filename));
            has_dangerous_perms = dangerous;
            condition_results.push(dangerous == require_dangerous_perms);
        }

        // 11. Contains secrets check
        if let Some(require_secrets) = group.contains_secrets {
            let found_secret = scan_for_secrets(path);
            let has_secret = found_secret.is_some();
            if has_secret {
                secret_found = found_secret;
            }
            condition_results.push(has_secret == require_secrets);
        }

        // 12. Suspicious .desktop file check
        if let Some(require_suspicious_desktop) = group.suspicious_desktop_file {
            let detected = is_suspicious_desktop_file(path);
            is_suspicious_desktop = detected;
            condition_results.push(detected == require_suspicious_desktop);
        }

        // 13. File age checks (older_than_days, newer_than_days, older_than_secs, newer_than_secs)
        let file_time = match group.date_type.as_deref() {
            Some("created") => metadata.created().unwrap_or_else(|_| metadata.modified().unwrap_or(SystemTime::now())),
            Some("accessed") => metadata.accessed().unwrap_or_else(|_| metadata.modified().unwrap_or(SystemTime::now())),
            _ => metadata.modified().unwrap_or(SystemTime::now()),
        };

        let file_age_secs = SystemTime::now().duration_since(file_time).map(|d| d.as_secs()).unwrap_or(0);
        let file_age_days = (file_age_secs / 86400) as u32;

        if let Some(min_days) = group.older_than_days {
            condition_results.push(file_age_days >= min_days);
        }
        if let Some(max_days) = group.newer_than_days {
            condition_results.push(file_age_days <= max_days);
        }
        if let Some(min_secs) = group.older_than_secs {
            condition_results.push(file_age_secs >= min_secs);
        }
        if let Some(max_secs) = group.newer_than_secs {
            condition_results.push(file_age_secs <= max_secs);
        }

        // 14. EXIF and Audio tag presence checks
        if let Some(require_exif) = group.has_exif {
            let has = extract_exif(path).is_some();
            condition_results.push(has == require_exif);
        }
        if let Some(require_audio) = group.has_audio_tags {
            let has = extract_audio_tags(path).is_some();
            condition_results.push(has == require_audio);
        }

        // 15. Subgroups evaluation
        if let Some(ref subgroups) = group.subgroups {
            for sub in subgroups {
                let sub_res = Self::evaluate(sub, path)?;
                for (k, v) in sub_res.captures {
                    captures.insert(k, v);
                }
                if sub_res.secret_found.is_some() && secret_found.is_none() {
                    secret_found = sub_res.secret_found;
                }
                if sub_res.is_double_ext {
                    is_double_ext = true;
                }
                if sub_res.has_dangerous_perms {
                    has_dangerous_perms = true;
                }
                if sub_res.is_suspicious_desktop {
                    is_suspicious_desktop = true;
                }
                condition_results.push(sub_res.matched);
            }
        }

        // Determine final boolean outcome based on MatchMode
        let matched = if condition_results.is_empty() {
            true
        } else {
            match group.match_mode {
                MatchMode::All => condition_results.iter().all(|&r| r),
                MatchMode::Any => condition_results.iter().any(|&r| r),
                MatchMode::None => condition_results.iter().all(|&r| !r),
            }
        };

        if cached_mime.is_none() {
            cached_mime = detect_mime(path).ok();
        }

        Ok(EvaluationResult {
            matched,
            captures,
            mime_type: cached_mime,
            secret_found,
            is_double_ext,
            has_dangerous_perms,
            is_suspicious_desktop,
        })
    }
}

/// Helper to read text content up to max_bytes.
fn read_file_prefix_or_content(path: &Path, max_bytes: usize) -> io::Result<String> {
    let file = File::open(path)?;
    let mut buffer = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut buffer)?;
    String::from_utf8(buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Detects deceptive double extensions like `resume.pdf.sh`, `invoice.docx.py`, `doc.pdf.exe`.
pub fn is_suspicious_double_extension(filename: &str) -> bool {
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() < 3 {
        return false;
    }

    let ext = parts.last().unwrap().to_lowercase();
    let second_ext = parts[parts.len() - 2].to_lowercase();

    // Legitimate multi-part archives
    if second_ext == "tar" && matches!(ext.as_str(), "gz" | "bz2" | "xz" | "zst" | "z" | "lzma") {
        return false;
    }

    let executable_or_script_exts = [
        "sh", "bash", "zsh", "py", "elf", "bin", "exe", "bat", "cmd", "ps1", "vbs", "js", "mjs", "jar", "run"
    ];

    let deceptive_base_exts = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp4", "zip"
    ];

    let is_final_exec = executable_or_script_exts.contains(&ext.as_str());
    let is_inner_doc = deceptive_base_exts.contains(&second_ext.as_str());

    is_final_exec && is_inner_doc
}

/// Detects deceptive/phishing .desktop launcher files (e.g. disguised as PDF/Doc with hidden shell scripts).
pub fn is_suspicious_desktop_file(path: &Path) -> bool {
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    if !filename.ends_with(".desktop") {
        return false;
    }

    // Disguised naming (e.g., invoice.pdf.desktop)
    if filename.contains(".pdf.") || filename.contains(".docx.") || filename.contains(".jpg.") || filename.contains(".png.") {
        return true;
    }

    // Inspect content for dangerous shell commands inside Exec=
    if let Ok(content) = read_file_prefix_or_content(path, 64 * 1024) {
        let content_lower = content.to_lowercase();
        if content_lower.contains("exec=bash -c")
            || content_lower.contains("exec=sh -c")
            || content_lower.contains("curl ")
            || content_lower.contains("wget ")
            || content_lower.contains("nc -e")
            || content_lower.contains("chmod +x")
        {
            return true;
        }
    }

    false
}

/// Scans file content for common leaked secrets (AWS, Private Keys, GitHub tokens, Slack tokens, generic API keys).
pub fn scan_for_secrets(path: &Path) -> Option<String> {
    let content = match read_file_prefix_or_content(path, 256 * 1024) {
        Ok(c) => c,
        Err(_) => return None,
    };

    // AWS Access Key ID
    if let Ok(re) = Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}") {
        if re.is_match(&content) {
            return Some("AWS Access Key ID".to_string());
        }
    }

    // Private Key
    if content.contains("-----BEGIN PRIVATE KEY-----")
        || content.contains("-----BEGIN RSA PRIVATE KEY-----")
        || content.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || content.contains("-----BEGIN EC PRIVATE KEY-----")
    {
        return Some("Cryptographic Private Key".to_string());
    }

    // GitHub Personal Access Token
    if let Ok(re) = Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,255}") {
        if re.is_match(&content) {
            return Some("GitHub Personal Access Token".to_string());
        }
    }

    // Slack API Token
    if let Ok(re) = Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*") {
        if re.is_match(&content) {
            return Some("Slack API Token".to_string());
        }
    }

    // Generic API Key assignment in .env or config
    if let Ok(re) = Regex::new(r#"(?i)(?:api_key|apikey|secret_key|app_secret|auth_token)\s*=\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#) {
        if re.is_match(&content) {
            return Some("Generic API / Secret Key".to_string());
        }
    }

    None
}
