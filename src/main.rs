use std::path::PathBuf;
use std::sync::Arc;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use jugglr::config::{default_config_path, load_config, validate_config};
use jugglr::engine::RuleEngine;
use jugglr::watcher::WatcherService;

#[derive(Parser, Debug)]
#[command(
    name = "jugglr",
    author = "Jugglr Contributors",
    version = "0.1.0",
    about = "Linux File Automation & Defense Daemon"
)]
struct Cli {
    /// Path to TOML rules configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Run in daemon mode (systemd service integration)
    #[arg(short, long)]
    daemon: bool,

    /// Launch graphical user interface (File Juggler style)
    #[arg(short, long)]
    gui: bool,

    /// Dry-run mode: evaluate rules and simulate actions without touching files
    #[arg(long)]
    dry_run: bool,

    /// Validate rule configuration syntax and exit
    #[arg(long)]
    validate: bool,

    /// Batch scan and process existing files in a directory
    #[arg(short, long, value_name = "DIR")]
    scan: Option<PathBuf>,

    /// Enable verbose / debug logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Determine config path
    let config_path = cli.config.unwrap_or_else(default_config_path);

    // If --validate flag is passed
    if cli.validate {
        println!("Validating configuration file: {}", config_path.display());
        match load_config(&config_path) {
            Ok(cfg) => {
                let errors = validate_config(&cfg);
                if errors.is_empty() {
                    println!("✅ Configuration validation SUCCESSFUL: {} rules loaded cleanly.", cfg.rules.len());
                    std::process::exit(0);
                } else {
                    eprintln!("❌ Configuration validation FAILED with {} issue(s):", errors.len());
                    for err in errors {
                        eprintln!("  - {}", err);
                    }
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to parse configuration file: {}", e);
                std::process::exit(1);
            }
        }
    }

    // If --scan flag is passed to process existing files
    if let Some(scan_dir) = cli.scan {
        let scan_path = jugglr::config::expand_path(&scan_dir.to_string_lossy());
        if !scan_path.exists() || !scan_path.is_dir() {
            eprintln!("Error: Target directory does not exist: {}", scan_path.display());
            std::process::exit(1);
        }

        let mut config = match load_config(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error loading config from {}: {}", config_path.display(), e);
                std::process::exit(1);
            }
        };

        if cli.dry_run {
            config.global.dry_run = true;
            println!("🔍 Running in DRY-RUN mode (no files will be moved or modified)");
        }

        println!("⚡ Processing existing files in: {}", scan_path.display());
        let engine = RuleEngine::new(config);
        let mut processed_count = 0;
        let mut matched_count = 0;

        if let Ok(entries) = std::fs::read_dir(&scan_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    processed_count += 1;
                    let outcomes = engine.process_file(&path);
                    if !outcomes.is_empty() {
                        matched_count += 1;
                        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown");
                        for outcome in outcomes {
                            println!("  [MATCH] {} -> {:?}", fname, outcome.action_type);
                            if let Some(ref target) = outcome.target_path {
                                println!("          Destination: {}", target.display());
                            }
                        }
                    }
                }
            }
        }

        println!("✅ Scan complete: {} files inspected, {} matched rules.", processed_count, matched_count);
        return Ok(());
    }

    // Default to GUI if not in daemon / dry-run mode
    let should_launch_gui = cli.gui || (!cli.daemon && !cli.dry_run);

    if should_launch_gui {
        // If config file doesn't exist yet, copy example config or create default
        if !config_path.exists() {
            if let Some(parent) = config_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let example_path = std::path::Path::new("rules.example.toml");
            if example_path.exists() {
                let _ = std::fs::copy(example_path, &config_path);
            }
        }

        // Run GUI
        return jugglr::gui::run_gui(config_path);
    }

    // Otherwise, initialize tracing subscriber and run background daemon
    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("Failed to set tracing subscriber: {}", e))?;

    info!("Jugglr - Linux File Automation & Defense Daemon v0.1.0");

    // Load configuration
    let mut config = match load_config(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Could not load configuration from {}: {}", config_path.display(), e);
            warn!("Please create a configuration file or specify --config <path>.");
            return Err(e);
        }
    };

    if cli.dry_run {
        config.global.dry_run = true;
        info!("🔍 Dry-run mode ENABLED: Actions will be simulated without modifying files.");
    }

    let validation_errors = validate_config(&config);
    if !validation_errors.is_empty() {
        warn!("Configuration has {} warnings:", validation_errors.len());
        for err in validation_errors {
            warn!("  - {}", err);
        }
    }

    info!("Loaded {} active rule(s) from {}", config.rules.len(), config_path.display());

    let engine = Arc::new(RwLock::new(RuleEngine::new(config)));
    let watcher = WatcherService::new(Arc::clone(&engine));

    // Setup signal handlers for SIGHUP (config reload) and SIGTERM/SIGINT (graceful shutdown)
    let mut sig_term = signal(SignalKind::terminate())?;
    let mut sig_int = signal(SignalKind::interrupt())?;
    let mut sig_hup = signal(SignalKind::hangup())?;

    let engine_for_reload = Arc::clone(&engine);
    let reload_config_path = config_path.clone();

    // Spawn SIGHUP listener for live reload
    tokio::spawn(async move {
        while sig_hup.recv().await.is_some() {
            info!("🔄 SIGHUP received: Reloading configuration from {}", reload_config_path.display());
            match load_config(&reload_config_path) {
                Ok(new_cfg) => {
                    let errs = validate_config(&new_cfg);
                    if errs.is_empty() {
                        let mut eng = engine_for_reload.write().await;
                        let count = new_cfg.rules.len();
                        eng.update_config(new_cfg);
                        info!("✅ Configuration successfully reloaded with {} active rules", count);
                    } else {
                        warn!("⚠️ Reload skipped due to {} validation errors", errs.len());
                    }
                }
                Err(e) => {
                    error!("❌ Failed to reload configuration: {}", e);
                }
            }
        }
    });

    // Run watcher service with graceful shutdown listener
    tokio::select! {
        res = watcher.run() => {
            if let Err(e) = res {
                error!("Watcher error: {}", e);
            }
        }
        _ = sig_term.recv() => {
            info!("🛑 SIGTERM received: Shutting down gracefully...");
        }
        _ = sig_int.recv() => {
            info!("🛑 SIGINT received: Shutting down gracefully...");
        }
    }

    info!("Jugglr daemon stopped cleanly.");
    Ok(())
}
