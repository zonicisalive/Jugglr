use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::LazyLock;
use std::time::SystemTime;
use glob::Pattern;
use regex::Regex;

use crate::config::schema::{ConditionGroup, MatchMode};
use crate::utils::audio::extract_audio_tags;
use crate::utils::exif::extract_exif;
use crate::utils::invisible_threats::{detect_forkbomb, detect_homoglyphs, detect_invisible_unicode, detect_polyglot_payload, detect_zipbomb};
use crate::utils::mime::{compute_sha256, detect_mime, detect_mime_spoofing, is_binary};
use crate::utils::signatures::scan_malware_signatures;
use crate::utils::virustotal::lookup_hash;

/// Evaluation result containing whether conditions matched and extracted regex variables.
#[derive(Debug, Clone, Default)]
pub struct EvaluationResult {
    pub matched: bool,
    pub captures: HashMap<String, String>,
    pub mime_type: Option<String>,
    pub secret_found: Option<String>,
    pub malware_found: Option<String>,
    pub virustotal_detections: Option<u32>,
    pub is_double_ext: bool,
    pub has_dangerous_perms: bool,
    pub is_suspicious_desktop: bool,
    pub is_mime_spoofed: bool,
}

pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluate a condition group against a file at `path`.
    pub fn evaluate(group: &ConditionGroup, path: &Path) -> io::Result<EvaluationResult> {
        Self::evaluate_with_vt(group, path, None)
    }

    /// Evaluate a condition group against a file at `path` with optional VirusTotal API key.
    /// Uses tiered short-circuit evaluation for maximum performance on low-end hardware.
    pub fn evaluate_with_vt(group: &ConditionGroup, path: &Path, vt_api_key: Option<&str>) -> io::Result<EvaluationResult> {
        let mut captures = HashMap::new();
        let mut secret_found = None;
        let mut malware_found = None;
        let mut virustotal_detections = None;
        let mut is_double_ext = false;
        let mut has_dangerous_perms = false;
        let mut is_suspicious_desktop = false;
        let mut is_mime_spoofed = false;

        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

        let mut condition_results = Vec::new();

        // =========================================================================
        // PHASE 1: Fast In-Memory String & Filename Checks (Zero Disk I/O)
        // =========================================================================

        // 1. Extension check
        if let Some(ref exts) = group.extensions {
            let matched = exts.iter().any(|ext| matches_extension(filename, &extension, ext));
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 2. Name Glob pattern
        if let Some(ref glob_str) = group.name_glob {
            let matched = if let Ok(pattern) = Pattern::new(glob_str) {
                pattern.matches(filename)
            } else {
                false
            };
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 3. Name Regex match & capture extraction
        if let Some(ref regex_str) = group.name_regex {
            let mut matched = false;
            if let Ok(re) = Regex::new(regex_str) {
                if let Some(caps) = re.captures(filename) {
                    matched = true;
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
                }
            }
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 4. Deceptive Double extension & RTLO check
        if let Some(require_double_ext) = group.double_extension {
            let detected = is_suspicious_double_extension(filename);
            is_double_ext = detected;
            let matched = detected == require_double_ext;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 5. Homoglyph / Lookalike character check
        if let Some(require_homoglyph) = group.homoglyph_detector {
            let found = detect_homoglyphs(filename);
            let has_homoglyph = found.is_some();
            if has_homoglyph {
                malware_found = found;
            }
            let matched = has_homoglyph == require_homoglyph;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // =========================================================================
        // PHASE 2: Fast Filesystem Metadata Checks (No Content Reading)
        // =========================================================================
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(EvaluationResult { matched: false, ..Default::default() }),
        };

        let file_size = metadata.len();

        // 6. Min size check
        if let Some(min_size) = group.min_size_bytes {
            let matched = file_size >= min_size;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 7. Max size check
        if let Some(max_size) = group.max_size_bytes {
            let matched = file_size <= max_size;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 8. Dangerous permissions check
        if let Some(require_dangerous_perms) = group.dangerous_permissions {
            let perms = metadata.permissions().mode();
            let is_exec = (perms & 0o111) != 0;
            let binary = is_binary(path).unwrap_or(false);
            let dangerous = is_exec && (!binary || is_suspicious_double_extension(filename));
            has_dangerous_perms = dangerous;
            let matched = dangerous == require_dangerous_perms;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 9. File age checks
        let file_time = match group.date_type.as_deref() {
            Some("created") => metadata.created().unwrap_or_else(|_| metadata.modified().unwrap_or(SystemTime::now())),
            Some("accessed") => metadata.accessed().unwrap_or_else(|_| metadata.modified().unwrap_or(SystemTime::now())),
            _ => metadata.modified().unwrap_or(SystemTime::now()),
        };

        let file_age_secs = SystemTime::now().duration_since(file_time).map(|d| d.as_secs()).unwrap_or(0);
        let file_age_days = (file_age_secs / 86400) as u32;

        if let Some(min_days) = group.older_than_days {
            let matched = file_age_days >= min_days;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }
        if let Some(max_days) = group.newer_than_days {
            let matched = file_age_days <= max_days;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }
        if let Some(min_secs) = group.older_than_secs {
            let matched = file_age_secs >= min_secs;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }
        if let Some(max_secs) = group.newer_than_secs {
            let matched = file_age_secs <= max_secs;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // =========================================================================
        // PHASE 3: Deep File Inspection (Only runs if prior checks haven't failed)
        // =========================================================================
        let mut cached_mime: Option<String> = None;

        // 10. MIME types check
        if let Some(ref expected_mimes) = group.mime_types {
            if cached_mime.is_none() {
                cached_mime = detect_mime(path).ok();
            }
            let matched = if let Some(ref actual_mime) = cached_mime {
                expected_mimes.iter().any(|expected| {
                    if expected.ends_with("/*") {
                        let prefix = expected.trim_end_matches("/*");
                        actual_mime.starts_with(prefix)
                    } else {
                        expected.eq_ignore_ascii_case(actual_mime)
                    }
                })
            } else {
                false
            };
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 11. Content contains (plaintext keywords)
        if let Some(ref keywords) = group.content_contains {
            if !keywords.is_empty() {
                let matched = match read_file_prefix_or_content(path, 256 * 1024) {
                    Ok(content) => keywords.iter().any(|kw| content.contains(kw)),
                    Err(_) => false,
                };
                if group.match_mode == MatchMode::All && !matched {
                    return Ok(EvaluationResult { matched: false, ..Default::default() });
                }
                condition_results.push(matched);
            }
        }

        // 12. Content regex match
        if let Some(ref content_re_str) = group.content_regex {
            let matched = match Regex::new(content_re_str) {
                Ok(re) => {
                    match read_file_prefix_or_content(path, 256 * 1024) {
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
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 13. Contains secrets check
        if let Some(require_secrets) = group.contains_secrets {
            let found_secret = scan_for_secrets(path);
            let has_secret = found_secret.is_some();
            if has_secret {
                secret_found = found_secret;
            }
            let matched = has_secret == require_secrets;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 14. Suspicious .desktop launcher file check
        if let Some(require_suspicious_desktop) = group.suspicious_desktop_file {
            let detected = is_suspicious_desktop_file(path);
            is_suspicious_desktop = detected;
            let matched = detected == require_suspicious_desktop;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 15. MIME Spoofing check
        if let Some(require_mime_spoof) = group.mime_spoofing {
            let detected = detect_mime_spoofing(path).is_some();
            is_mime_spoofed = detected;
            let matched = detected == require_mime_spoof;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 16. Malware & Web Shell Signature Pattern Detection
        if let Some(require_malware) = group.malware_signature {
            let found = scan_malware_signatures(path);
            let has_malware = found.is_some();
            if has_malware {
                malware_found = found;
            }
            let matched = has_malware == require_malware;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 17. Fork Bomb Detector
        if let Some(require_forkbomb) = group.forkbomb_detector {
            let found = detect_forkbomb(path);
            let has_fork = found.is_some();
            if has_fork {
                malware_found = found;
            }
            let matched = has_fork == require_forkbomb;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 18. Zip Bomb / Decompression Bomb Detector
        if let Some(require_zipbomb) = group.zipbomb_detector {
            let found = detect_zipbomb(path);
            let has_zipbomb = found.is_some();
            if has_zipbomb {
                malware_found = found;
            }
            let matched = has_zipbomb == require_zipbomb;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 19. Invisible Zero-Width Unicode Detector
        if let Some(require_invisible_unicode) = group.invisible_unicode_detector {
            let found = detect_invisible_unicode(filename, Some(path));
            let has_invisible = found.is_some();
            if has_invisible {
                malware_found = found;
            }
            let matched = has_invisible == require_invisible_unicode;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 20. Polyglot Stego Image Payload Detector
        if let Some(require_polyglot) = group.polyglot_payload_detector {
            let found = detect_polyglot_payload(path);
            let has_polyglot = found.is_some();
            if has_polyglot {
                malware_found = found;
            }
            let matched = has_polyglot == require_polyglot;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 21. VirusTotal SHA-256 Hash Reputation Check
        if let Some(min_positives) = group.virustotal_min_positives {
            let mut is_flagged = false;
            if let Some(api_key) = vt_api_key {
                if let Ok(hash) = compute_sha256(path) {
                    if let Some(report) = lookup_hash(api_key, &hash) {
                        let total_pos = report.malicious_count + report.suspicious_count;
                        virustotal_detections = Some(total_pos);
                        if total_pos >= min_positives {
                            is_flagged = true;
                            if let Some(threat) = report.popular_threat_name {
                                malware_found = Some(format!("VirusTotal Detection: {} ({}/{} engines)", threat, total_pos, report.total_engines));
                            } else {
                                malware_found = Some(format!("VirusTotal Flagged ({}/{} engines)", total_pos, report.total_engines));
                            }
                        }
                    }
                }
            }
            if group.match_mode == MatchMode::All && !is_flagged {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(is_flagged);
        }

        // 22. EXIF and Audio tag presence checks
        if let Some(require_exif) = group.has_exif {
            let has = extract_exif(path).is_some();
            let matched = has == require_exif;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }
        if let Some(require_audio) = group.has_audio_tags {
            let has = extract_audio_tags(path).is_some();
            let matched = has == require_audio;
            if group.match_mode == MatchMode::All && !matched {
                return Ok(EvaluationResult { matched: false, ..Default::default() });
            }
            condition_results.push(matched);
        }

        // 23. Subgroups evaluation
        if let Some(ref subgroups) = group.subgroups {
            for sub in subgroups {
                let sub_res = Self::evaluate_with_vt(sub, path, vt_api_key)?;
                for (k, v) in sub_res.captures {
                    captures.insert(k, v);
                }
                if sub_res.secret_found.is_some() && secret_found.is_none() {
                    secret_found = sub_res.secret_found;
                }
                if sub_res.malware_found.is_some() && malware_found.is_none() {
                    malware_found = sub_res.malware_found;
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
                if sub_res.is_mime_spoofed {
                    is_mime_spoofed = true;
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

        // Only pay for magic-byte detection when the caller will actually use the result;
        // this runs for every file in a watched directory.
        if matched && cached_mime.is_none() {
            cached_mime = detect_mime(path).ok();
        }

        Ok(EvaluationResult {
            matched,
            captures,
            mime_type: cached_mime,
            secret_found,
            malware_found,
            virustotal_detections,
            is_double_ext,
            has_dangerous_perms,
            is_suspicious_desktop,
            is_mime_spoofed,
        })
    }
}

/// Helper to read text content up to max_bytes.
///
/// Decoded lossily on purpose. A strict UTF-8 decode fails on any binary file and on any text
/// file whose `max_bytes` cut lands mid-codepoint, which would silently disable every
/// content-based check (secrets, keywords, malware strings) exactly on the files most worth
/// scanning.
fn read_file_prefix_or_content(path: &Path, max_bytes: usize) -> io::Result<String> {
    let file = File::open(path)?;
    let mut buffer = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// Match one configured extension against a filename.
///
/// `Path::extension` only ever yields the final segment, so a configured `tar.gz` would never
/// match `backup.tar.gz`. Compound suffixes are matched against the filename tail instead.
fn matches_extension(filename: &str, final_extension: &str, configured: &str) -> bool {
    let want = configured.trim_start_matches('.');
    if want.is_empty() {
        return false;
    }
    if want.eq_ignore_ascii_case(final_extension) {
        return true;
    }
    let suffix = format!(".{}", want.to_lowercase());
    filename.to_lowercase().ends_with(&suffix)
}

/// Detects deceptive double extensions like `resume.pdf.sh`, `invoice.docx.py`, `doc.pdf.exe`,
/// and Unicode Right-to-Left Override (RTLO) spoofing attacks.
pub fn is_suspicious_double_extension(filename: &str) -> bool {
    if filename.contains('\u{202E}')
        || filename.contains('\u{202D}')
        || filename.contains('\u{202C}')
        || filename.contains('\u{202B}')
        || filename.contains('\u{202A}')
    {
        return true;
    }

    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() < 3 {
        return false;
    }

    let ext = parts.last().unwrap().to_lowercase();
    let second_ext = parts[parts.len() - 2].to_lowercase();

    // Legitimate multi-part archives whitelist
    if second_ext == "tar" && matches!(ext.as_str(), "gz" | "bz2" | "xz" | "zst" | "z" | "lzma" | "lz4") {
        return false;
    }
    if second_ext == "deb" || second_ext == "rpm" || second_ext == "pkg" {
        return false;
    }

    let executable_or_script_exts = [
        "sh", "bash", "zsh", "fish", "csh", "ksh", "py", "pyw", "pyc", "elf", "bin",
        "exe", "bat", "cmd", "ps1", "ps2", "vbs", "vbe", "js", "mjs", "jse", "jar",
        "run", "msi", "appimage", "deb", "rpm", "pkg", "dmg", "wsf", "hta", "scr",
        "cpl", "pif", "wsh", "action", "command", "pl", "rb", "php", "lua", "tcl",
        "awk", "out", "so", "dylib", "dll"
    ];

    let deceptive_base_exts = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
        "rtf", "txt", "csv", "tsv", "md", "epub", "jpg", "jpeg", "png", "gif",
        "webp", "svg", "bmp", "tiff", "heic", "avif", "mp4", "mkv", "avi", "mov",
        "webm", "mp3", "wav", "flac", "m4a", "ogg", "zip", "7z", "rar", "iso", "tar"
    ];

    let is_final_exec = executable_or_script_exts.contains(&ext.as_str());
    let is_inner_doc = deceptive_base_exts.contains(&second_ext.as_str());

    is_final_exec && is_inner_doc
}

/// Detects deceptive/phishing .desktop, .service, .timer, and autostart files.
pub fn is_suspicious_desktop_file(path: &Path) -> bool {
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let is_launcher = filename.ends_with(".desktop")
        || filename.ends_with(".service")
        || filename.ends_with(".timer")
        || filename.ends_with(".path")
        || filename.ends_with(".autostart");

    if !is_launcher {
        return false;
    }

    if filename.contains(".pdf.") || filename.contains(".docx.") || filename.contains(".xlsx.")
        || filename.contains(".jpg.") || filename.contains(".png.") || filename.contains(".mp4.")
    {
        return true;
    }

    if let Ok(content) = read_file_prefix_or_content(path, 64 * 1024) {
        let content_lower = content.to_lowercase();
        let dangerous_signatures = [
            "exec=bash -c", "exec=sh -c", "exec=zsh -c", "exec=python -c",
            "execstart=bash -c", "execstart=sh -c",
            "curl ", "wget ", "fetch ", "aria2c ",
            "nc -e", "ncat -e", "socat ", "/dev/tcp/",
            "base64 -d", "base64 --decode",
            "chmod +x", "chmod 777", "nohup ",
            "systemctl --user enable",
        ];

        for sig in dangerous_signatures {
            if content_lower.contains(sig) {
                return true;
            }
        }
    }

    false
}

/// Compiled once: these run on every file a `contains_secrets` rule inspects, and rebuilding
/// a dozen regexes per file is the single hottest cost in the scanner.
static SECRET_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let sources: [(&str, &str); 9] = [
        (r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "AWS Access Key ID"),
        (r"AIza[0-9A-Za-z_-]{35}", "Google Cloud / Firebase API Key"),
        (r"gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}", "GitHub Personal Access Token"),
        (r"glpat-[0-9a-zA-Z_-]{20,}", "GitLab Personal Access Token"),
        (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/[0-9A-Za-z]+", "Slack API Token / Webhook"),
        (r"sk-ant-[a-zA-Z0-9_\-]{32,}", "Anthropic API Key"),
        (r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}", "OpenAI API Key"),
        (r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
        (r"(?i)(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^:\s]+:[^@\s]+@[^/\s]+", "Database Connection String with Credentials"),
    ];

    sources
        .iter()
        .filter_map(|(pattern, label)| match Regex::new(pattern) {
            Ok(re) => Some((re, *label)),
            Err(e) => {
                // A malformed literal here is a build-time mistake, not a runtime condition.
                debug_assert!(false, "invalid secret pattern {}: {}", pattern, e);
                None
            }
        })
        .collect()
});

static GENERIC_SECRET_PATTERN: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:api_key|apikey|secret_key|app_secret|auth_token|bearer_token|access_token)\s*=\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#).ok()
});

const PRIVATE_KEY_HEADERS: [&str; 6] = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
];

/// Scans file content for common leaked secrets (AWS, GCP, GitHub, Slack, Discord, OpenAI, Stripe, Private Keys).
pub fn scan_for_secrets(path: &Path) -> Option<String> {
    let content = match read_file_prefix_or_content(path, 256 * 1024) {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Cheap substring checks first, before touching the regex engine.
    if PRIVATE_KEY_HEADERS.iter().any(|header| content.contains(header)) {
        return Some("Cryptographic Private Key".to_string());
    }

    if content.contains("https://discord.com/api/webhooks/") || content.contains("https://discordapp.com/api/webhooks/") {
        return Some("Discord Webhook URL".to_string());
    }

    for (re, label) in SECRET_PATTERNS.iter() {
        if re.is_match(&content) {
            return Some(label.to_string());
        }
    }

    if let Some(re) = GENERIC_SECRET_PATTERN.as_ref() {
        if re.is_match(&content) {
            return Some("Generic API / Secret Key".to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_extensions_match_the_filename_tail() {
        assert!(matches_extension("backup.tar.gz", "gz", "tar.gz"));
        assert!(matches_extension("backup.tar.gz", "gz", "gz"));
        assert!(matches_extension("report.PDF", "pdf", ".pdf"));
        assert!(!matches_extension("backup.tar.gz", "gz", "zip"));
        assert!(!matches_extension("notes.gz", "gz", "tar.gz"));
        assert!(!matches_extension("anything", "", ""));
    }
}
