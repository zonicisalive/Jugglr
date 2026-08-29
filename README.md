# Jugglr

Linux File Automation and Defense Daemon with Desktop GUI.

Jugglr is a low-overhead, daemonized background service and native graphical desktop application for Linux. It watches filesystem directories via native Linux inotify, evaluates declarative rule conditions (metadata, regex, MIME type, deceptive extensions, leaked secrets, photo EXIF, ID3 audio tags, file age), and executes structured actions (atomic organizing, renaming, safe extraction, FreeDesktop trash, symlinking, security quarantining, script execution, and desktop alerts).

---

## Features

### 1. High-Performance Event Ingestion and Debouncing
- Native Linux inotify streaming (`IN_CLOSE_WRITE`, `IN_MOVED_TO`).
- Asynchronous task workers powered by Tokio.
- Sliding-window debounce mechanism (default: 500ms) to ensure partially downloaded files settle before rules execute.

### 2. Declarative TOML Rule Engine
- Boolean condition evaluation: `match = "all"` (AND), `match = "any"` (OR), and `match = "none"` (NOT) with nested condition trees.
- Path and Name filters: Regex patterns with named and indexed capture groups, glob matching (`*.pdf`), extension filtering.
- Metadata filters: Size ranges (`min_size_bytes`, `max_size_bytes`), MIME type matching (via magic number detection).
- Content inspection: Plaintext keyword search and regex extraction on file contents.
- Time-based age conditions: `older_than_days`, `newer_than_days`, `older_than_secs`, `newer_than_secs` (`modified`, `created`, `accessed`).
- Media metadata extractors: Photo EXIF capture dates and camera models, ID3 audio tags (artist, album, title, track).

### 3. Action Execution Pipeline and Dynamic Variables
- Structured actions:
  - `move`: Atomic file moves with cross-filesystem fallback.
  - `copy`: File duplication.
  - `rename`: In-place or template renaming.
  - `trash`: FreeDesktop trash integration (`~/.local/share/Trash`).
  - `delete`: Permanent removal.
  - `extract`: Archive decompression (`.zip`, `.tar.gz`, `.tar.xz`, `.tar.bz2`, `.tar`) with Zip-Slip path traversal protection.
  - `symlink` / `hardlink`: Link creation without duplicating file bytes.
  - `quarantine`: Security threat isolation (`0o600` permissions with structured JSONL audit trail).
  - `script`: Bash script execution with environment variables passed.
- Conflict resolution policies: `rename_with_counter` (`file (1).pdf`), `overwrite`, `skip`.
- Dynamic variable interpolation:
  - `{year}`, `{month}`, `{day}`, `{hour}`, `{minute}`
  - `{filename}`, `{stem}`, `{ext}`, `{original_dir}`
  - `{mime_type}`, `{sha256}`, `{file_age_days}`, `{file_age_hours}`
  - `{exif_year}`, `{exif_month}`, `{exif_day}`, `{camera_make}`, `{camera_model}`
  - `{music_artist}`, `{music_album}`, `{music_title}`, `{music_track}`
  - `{regex_match_N}`, `{custom_named_capture}`

### 4. Built-in Security Modules
- Dangerous Permission Neutralizer: Automatically strips executable bits (`chmod -x` / mode `0o644`) from downloaded documents, images, and non-binaries.
- Double-Extension Detector: Identifies deceptive extensions (e.g. `resume.pdf.sh`, `invoice.docx.py`) while preserving valid multi-part archives (e.g. `.tar.gz`, `.tar.xz`). Moves threats to `~/.local/share/jugglr/quarantine/` with `0o600` permissions and writes audit logs to `quarantine_audit.jsonl`.
- Secret and API Key Leak Audit: Scans downloaded `.env`, `.json`, `.yaml`, and text files for leaked AWS access keys (`AKIA...`), SSH private keys, GitHub tokens, Slack tokens, and generic credentials.
- Phishing Launcher Detection: Flags `.desktop` files disguised as documents or containing hidden shell execution lines.

### 5. Desktop GUI and Systemd Integration
- Native desktop graphical user interface with responsive sidebar, visual condition/action card builders, and 1-click token inserters.
- Live inotify activity log tab and quarantine vault explorer with 1-click file restore.
- Dry-run simulation tool to test rules against any directory without touching files.
- Preset recipe library with safe default disabled state (`enabled = false`).
- Native desktop notifications via notify-rust / libnotify with urgency levels (`low`, `normal`, `critical`).
- Webhook dispatcher for Discord, Slack, and REST endpoints.
- Dynamic configuration reload via `SIGHUP` signal.
- Systemd user service unit template.

---

## Installation and Build

### Prerequisites
- Linux with Rust 1.75+ and Cargo installed.
- Desktop display (X11 or Wayland) for GUI mode.

### Build from Source
```bash
git clone https://github.com/example/jugglr.git
cd jugglr
cargo build --release

# Install binary to ~/.cargo/bin
cargo install --path .
```

---

## Configuration

Default configuration file location: `~/.config/jugglr/rules.toml`

To initialize:
```bash
mkdir -p ~/.config/jugglr
cp rules.example.toml ~/.config/jugglr/rules.toml
```

### Configuration Example

```toml
[global]
debounce_ms = 500
default_quarantine_dir = "~/.local/share/jugglr/quarantine"
dry_run = false

# Rule 1: Organize Invoices
[[rules]]
name = "Auto-organize Invoices and Receipts"
watch_dir = "~/Downloads"
enabled = true

  [rules.conditions]
  match = "all"
  extensions = ["pdf"]
  content_contains = ["Invoice", "Receipt", "Total Due"]
  min_size_bytes = 1024

  [rules.actions]
  action = "move"
  destination = "~/Documents/Finance/{year}/"
  conflict_resolution = "rename_with_counter"
  notify = true

# Rule 2: Security Quarantine for Suspicious Scripts
[[rules]]
name = "Security Quarantine for Suspicious Scripts"
watch_dir = "~/Downloads"
enabled = true

  [rules.conditions]
  match = "any"
  extensions = ["sh", "py", "elf", "bin"]
  double_extension = true

  [rules.actions]
  action = "quarantine"
  destination = "~/.local/share/jugglr/quarantine/"
  strip_executable = true
  notify = true
  alert_urgency = "critical"
```

---

## Command-Line Usage

```bash
# Launch Desktop GUI (Default)
jugglr

# Explicit GUI flag
jugglr --gui

# Run background inotify daemon
jugglr --daemon

# Validate rule syntax and exit
jugglr --validate --config ~/.config/jugglr/rules.toml

# Dry-run simulation mode (logs actions without touching files)
jugglr --dry-run --config ~/.config/jugglr/rules.toml

# Live configuration reload (without restarting daemon)
kill -HUP $(pgrep -f "jugglr --daemon")
```

---

## Systemd Service Setup

To run Jugglr as a background user service:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/jugglr.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now jugglr.service
systemctl --user status jugglr.service
```

---

## Testing

Run the automated test suite covering all engine, config, action, and security modules:

```bash
cargo test
```

---

## License

MIT OR Apache-2.0
