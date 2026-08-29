use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
    #[serde(default = "default_quarantine_dir")]
    pub default_quarantine_dir: String,
    #[serde(default)]
    pub dry_run: bool,
    /// Optional VirusTotal API Key for SHA-256 hash reputation checks
    pub virustotal_api_key: Option<String>,
}

fn default_debounce_ms() -> u64 {
    500
}

fn default_quarantine_dir() -> String {
    "~/.local/share/jugglr/quarantine".to_string()
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            debounce_ms: default_debounce_ms(),
            default_quarantine_dir: default_quarantine_dir(),
            dry_run: false,
            virustotal_api_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    pub watch_dir: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: ConditionGroup,
    pub actions: ActionConfig,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    #[default]
    All,
    Any,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConditionGroup {
    #[serde(default, rename = "match")]
    pub match_mode: MatchMode,

    /// List of allowed or matching extensions without dot, e.g. ["pdf", "png"]
    pub extensions: Option<Vec<String>>,

    /// Regex to match on filename (or relative path)
    pub name_regex: Option<String>,

    /// Glob pattern to match on filename, e.g. "invoice_*.pdf"
    pub name_glob: Option<String>,

    /// Minimum file size in bytes
    pub min_size_bytes: Option<u64>,

    /// Maximum file size in bytes
    pub max_size_bytes: Option<u64>,

    /// List of matching MIME types, e.g. ["application/pdf", "image/*"]
    pub mime_types: Option<Vec<String>>,

    /// Text keywords that must be present in the file content
    pub content_contains: Option<Vec<String>>,

    /// Regular expression to match inside file content
    pub content_regex: Option<String>,

    /// Check if filename has suspicious double extensions (e.g. invoice.pdf.sh)
    pub double_extension: Option<bool>,

    /// Check if file has dangerous/unexpected executable permissions
    pub dangerous_permissions: Option<bool>,

    /// Check if file contains leaked secrets (API keys, private keys, .env tokens)
    pub contains_secrets: Option<bool>,

    /// Check if file is a suspicious/phishing .desktop launcher file
    pub suspicious_desktop_file: Option<bool>,

    /// Check if file extension is spoofed compared to its actual binary magic bytes
    pub mime_spoofing: Option<bool>,

    /// Check if file matches known malware, web shell, reverse shell, or exploit payload signatures
    pub malware_signature: Option<bool>,

    /// Minimum number of VirusTotal antivirus engine detections to trigger (requires virustotal_api_key)
    pub virustotal_min_positives: Option<u32>,

    /// Check if file is a fork bomb script (:(){ :|:& };: / while True: os.fork())
    pub forkbomb_detector: Option<bool>,

    /// Check if archive is a decompression zip bomb (>100:1 ratio or recursive)
    pub zipbomb_detector: Option<bool>,

    /// Check if filename or text contains hidden zero-width unicode characters
    pub invisible_unicode_detector: Option<bool>,

    /// Check if image file contains hidden polyglot payloads appended after EOF
    pub polyglot_payload_detector: Option<bool>,

    /// Check if filename contains mixed Cyrillic/Latin lookalike homoglyphs
    pub homoglyph_detector: Option<bool>,

    /// File age filters (in days or seconds)
    pub older_than_days: Option<u32>,
    pub newer_than_days: Option<u32>,
    pub older_than_secs: Option<u64>,
    pub newer_than_secs: Option<u64>,

    /// Date field to check for age ("modified", "created", "accessed")
    pub date_type: Option<String>,

    /// Check if file contains EXIF photo metadata
    pub has_exif: Option<bool>,

    /// Check if file contains audio/ID3 metadata
    pub has_audio_tags: Option<bool>,

    /// Nested condition groups for complex boolean trees
    pub subgroups: Option<Vec<ConditionGroup>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    #[default]
    #[serde(rename = "move")]
    Move,
    #[serde(rename = "copy")]
    Copy,
    #[serde(rename = "rename")]
    Rename,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "trash")]
    Trash,
    #[serde(rename = "extract")]
    Extract,
    #[serde(rename = "symlink")]
    Symlink,
    #[serde(rename = "hardlink")]
    Hardlink,
    #[serde(rename = "quarantine")]
    Quarantine,
    #[serde(rename = "script")]
    Script,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    #[default]
    RenameWithCounter,
    Overwrite,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionConfig {
    pub action: ActionType,

    /// Destination directory or new filename template
    pub destination: Option<String>,

    #[serde(default)]
    pub conflict_resolution: ConflictResolution,

    /// Automatically strip executable bit (chmod -x)
    #[serde(default)]
    pub strip_executable: bool,

    /// Audit for exposed secrets and log/tag security warnings
    #[serde(default)]
    pub secret_audit: bool,

    /// Trigger desktop notifications
    #[serde(default)]
    pub notify: bool,

    /// Notification urgency: "low", "normal", "critical"
    pub alert_urgency: Option<String>,

    /// Shell command or script to execute
    pub script: Option<String>,

    /// Custom desktop notification message template
    pub notify_message: Option<String>,

    /// Webhook URL (Discord, Slack, or generic HTTP POST)
    pub webhook_url: Option<String>,

    /// Automatically remove or trash original archive after extracting
    #[serde(default)]
    pub delete_archive_after_extract: bool,
}
