# Jugglr

Linux File Automation and Threat Defense Daemon with Desktop GUI.

Jugglr is an ultra-low overhead, daemonized background service and native graphical desktop application for Linux. It watches filesystem directories via native Linux inotify, evaluates declarative rule conditions (metadata, regex, MIME type, deceptive extensions, leaked secrets, photo EXIF, ID3 audio tags, file age, malware signatures, fork bombs, zip bombs, invisible Unicode, and VirusTotal hash reputation), and executes structured actions (atomic organizing, renaming, safe extraction, FreeDesktop trash, symlinking, security quarantining, script execution, and webhook alerts).

---

## Features

### 1. High-Performance Event Ingestion and Debouncing
- Native Linux inotify streaming (`IN_CLOSE_WRITE`, `IN_MOVED_TO`).
- Asynchronous task workers powered by Tokio with blocking offloading.
- Pure event-driven debouncer sleeping unconditionally when the file queue is empty.
- Sliding-window debounce mechanism (default: 500ms) ensuring partially written downloads settle before rules execute.

### 2. Declarative TOML Rule Engine
- Boolean condition evaluation: `match = "all"` (AND), `match = "any"` (OR), and `match = "none"` (NOT) with nested condition trees.
- Path and Name filters: Regex patterns with named and indexed capture groups, glob matching (`*.pdf`), extension filtering.
- Tiered Short-Circuit Evaluation: Evaluates in-memory string checks first, followed by inode metadata, executing deep content inspections only when necessary.
- Metadata filters: Size ranges (`min_size_bytes`, `max_size_bytes`), MIME type matching (via magic byte detection).
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

### 4. Advanced Threat Defense and Security Modules
- Dangerous Permission Neutralizer: Automatically strips executable bits (`chmod -x` / mode `0o644`) from downloaded documents, images, and non-binaries.
- Double-Extension Detector: Identifies deceptive extensions (e.g. `resume.pdf.sh`, `invoice.docx.py`) while preserving valid multi-part archives (e.g. `.tar.gz`, `.tar.xz`).
- Right-to-Left Override (RTLO) Trap: Detects Unicode `\u{202E}` characters used to flip filename extensions.
- MIME Spoofing Detector: Detects executable binaries (ELF, PE, Shell) disguised with document or image extensions.
- Leaked Secrets and Credentials Scanner: Scans files for exposed AWS access keys, GitHub tokens, GitLab tokens, OpenAI keys, Anthropic keys, Stripe live keys, Slack/Discord webhooks, Database URIs, and Cryptographic Private Keys.
- Malware and Web Shell Signatures: Fast native detection (< 1ms, 0 MB extra RAM) of EICAR test signatures, PHP/Python/JSP web shells (`c99`, `r57`, `b374k`, `WSO`, `eval(base64_decode`), reverse shells (`/dev/tcp/`, `nc -e`, `socat`), and crypto miner payloads.
- VirusTotal Hash Reputation: Queries VirusTotal API v3 asynchronously using SHA-256 hashes (no file contents uploaded) to detect globally flagged malware.
- Fork Bomb Detector: Identifies infinite process exhaustion scripts across Bash (`:(){ :|:& };:`), Python (`while True: os.fork()`), Windows Batch (`%0|%0`), C/C++, Perl, and Ruby.
- Zip Bomb / Decompression Bomb Detector: Calculates compression ratios without decompressing to flag extreme expansion ratios (> 100:1) and recursive archives (`42.zip`).
- Invisible Zero-Width Unicode Detector: Detects hidden characters (`\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`, `\u{2060}`) used to obscure payload commands.
- IDN and Cyrillic Homoglyph Lookalike Detector: Detects lookalike Cyrillic letters mixed with Latin filenames (`updаte.sh`).
- Polyglot Steganography Detector: Inspects PNG and JPEG image files for trailing executables or ZIP payloads appended after the End-Of-File marker.

### 5. Low-End PC and Resource Optimization
- Ultra-low memory background daemon: Consumes ~7.1 MB RSS at idle.
- Event-driven reactive GUI rendering: 0.0% CPU usage when untouched.
- Stream-capped I/O: Inspects only 64KB-256KB header slices; processing massive files (e.g. 50GB ISOs) never causes memory spikes.
- Release optimizations: Fat Link-Time Optimization (`lto = "fat"`), `panic = "abort"`, single code generation units (`codegen-units = 1`), and stripped symbols.

### 6. Desktop GUI and Systemd Integration
- Native desktop graphical user interface with responsive sidebar, visual condition/action card builders, and 1-click token inserters.
- Live inotify activity log tab and quarantine vault explorer with 1-click file restore.
- Non-blocking asynchronous dry-run simulation tool to test rules against any directory with real-time result streaming.
- Preset recipe library with safe default disabled state (`enabled = false`).
- Native desktop notifications via notify-rust with configurable urgency levels (`low`, `normal`, `critical`).
- Webhook dispatcher for Discord, Slack, and custom REST endpoints.
- Dynamic configuration reload via `SIGHUP` signal.
- Systemd user service unit template.

---

## Installation and Build

### Prerequisites
- Linux with Rust 1.75+ and Cargo installed.
- Desktop display (X11 or Wayland) for GUI mode.

### Build from Source
```bash
git clone https://github.com/ZonicExists/Jugglr.git
cd Jugglr
cargo build --release

# Install binary to ~/.cargo/bin
cargo install --path .

# Install Desktop Launcher and Application Icon
mkdir -p ~/.local/share/applications ~/.local/share/icons/hicolor/scalable/apps
cp assets/jugglr.desktop ~/.local/share/applications/
cp assets/icons/jugglr.svg ~/.local/share/icons/hicolor/scalable/apps/
update-desktop-database ~/.local/share/applications || true
gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor || true
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
# virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"

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
  match = "all"
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
