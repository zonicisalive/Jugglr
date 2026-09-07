use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;
use jugglr::actions::{resolve_target_path, ActionExecutor};
use jugglr::config::schema::{ActionConfig, ActionType, ConflictResolution};
use jugglr::engine::variables::ContextVariables;

#[test]
fn test_variable_interpolation() {
    let mut ctx = ContextVariables::new();
    ctx.insert("year", "2026");
    ctx.insert("month", "08");
    ctx.insert("stem", "invoice_aug");
    ctx.insert("ext", "pdf");

    let template = "~/Finance/{year}/{month}/{stem}_archive.{ext}";
    let result = ctx.interpolate(template);
    assert_eq!(result, "~/Finance/2026/08/invoice_aug_archive.pdf");
}

#[test]
fn test_conflict_resolution_rename_with_counter() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.txt");
    let target = dir.path().join("item.txt");

    File::create(&source).unwrap();
    File::create(&target).unwrap(); // item.txt already exists

    let resolved = resolve_target_path(&source, &target, ConflictResolution::RenameWithCounter);
    assert_eq!(resolved, Some(dir.path().join("item (1).txt")));

    // Create item (1).txt as well
    File::create(dir.path().join("item (1).txt")).unwrap();

    let resolved2 = resolve_target_path(&source, &target, ConflictResolution::RenameWithCounter);
    assert_eq!(resolved2, Some(dir.path().join("item (2).txt")));
}

#[test]
fn test_conflict_resolution_skip() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.txt");
    let target = dir.path().join("item.txt");

    File::create(&source).unwrap();
    File::create(&target).unwrap();

    let resolved = resolve_target_path(&source, &target, ConflictResolution::Skip);
    assert_eq!(resolved, None);
}

#[test]
fn test_move_action() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("my_file.pdf");
    let dest_dir = dir.path().join("sorted");

    let mut f = File::create(&source).unwrap();
    writeln!(f, "Important PDF content").unwrap();

    let action_cfg = ActionConfig {
        action: ActionType::Move,
        destination: Some(dest_dir.to_string_lossy().to_string()),
        conflict_resolution: ConflictResolution::RenameWithCounter,
        ..Default::default()
    };

    let ctx = ContextVariables::from_file(&source, Some("application/pdf"), None, None);
    let outcome = ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Test Move", false).unwrap();

    assert!(outcome.success);
    assert!(!source.exists());
    let expected_dest = dest_dir.join("my_file.pdf");
    assert!(expected_dest.exists());
}

#[test]
fn test_script_action_execution() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("script_target.txt");
    let marker_file = dir.path().join("marker.log");

    File::create(&source).unwrap();

    let action_cfg = ActionConfig {
        action: ActionType::Script,
        script: Some(format!("echo \"Processed: $JUGGLR_FILE\" > {}", marker_file.display())),
        ..Default::default()
    };

    let ctx = ContextVariables::from_file(&source, None, None, None);
    let outcome = ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Test Script", false).unwrap();

    assert!(outcome.success);
    assert!(marker_file.exists());
    let content = fs::read_to_string(&marker_file).unwrap();
    assert!(content.contains("Processed:"));
    assert!(content.contains("script_target.txt"));
}

#[test]
fn test_directories_are_never_treated_as_files() {
    use jugglr::config::schema::{ConditionGroup, Config, MatchMode, RuleConfig};

    let dir = tempdir().unwrap();
    let watch = dir.path().join("in");
    let folder = watch.join("MyPhotos");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("a.txt"), "payload").unwrap();

    let config = Config {
        global: Default::default(),
        rules: vec![RuleConfig {
            name: "catch all".to_string(),
            watch_dir: watch.to_string_lossy().to_string(),
            enabled: true,
            conditions: ConditionGroup { match_mode: MatchMode::All, newer_than_days: Some(9999), ..Default::default() },
            actions: ActionConfig {
                action: ActionType::Move,
                destination: Some(format!("{}/sorted/", dir.path().display())),
                ..Default::default()
            },
        }],
    };

    let engine = jugglr::engine::RuleEngine::new(config);
    let outcomes = engine.process_file(&folder);

    assert!(outcomes.is_empty(), "a directory must not match file rules: {:?}", outcomes);
    assert!(folder.is_dir(), "the folder must stay where it is");
    assert!(folder.join("a.txt").exists(), "its contents must be untouched");
    assert!(!dir.path().join("sorted/MyPhotos").exists(), "the folder must not have been moved");
}

#[test]
fn test_move_onto_itself_is_a_no_op_not_an_endless_rename() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("report.pdf");
    File::create(&source).unwrap();

    // Destination is the directory the file already lives in.
    let action_cfg = ActionConfig {
        action: ActionType::Move,
        destination: Some(format!("{}/", dir.path().display())),
        conflict_resolution: ConflictResolution::RenameWithCounter,
        ..Default::default()
    };

    let ctx = ContextVariables::from_file(&source, None, None, None);
    let outcome = ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Self move", false).unwrap();

    assert!(outcome.target_path.is_none(), "no move should be planned");
    assert!(source.exists(), "the original must still be there");
    assert!(!dir.path().join("report (1).pdf").exists(), "must not spawn a numbered duplicate");
}

#[test]
fn test_destination_is_never_observable_half_written() {
    // The reported corruption: a destination file that exists but holds an incomplete copy.
    // Writing straight into the destination name makes that state visible to anything looking
    // at the folder; staging under a temp name and renaming makes it unreachable. An observer
    // polls the destination while a large copy runs and must never catch it partly written.
    const LEN: usize = 64 * 1024 * 1024;
    let dir = tempdir().unwrap();
    let source = dir.path().join("large.bin");
    fs::write(&source, vec![0xABu8; LEN]).unwrap();

    let target = dir.path().join("dest.bin");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let observer = {
        let target = target.clone();
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut worst: Option<u64> = None;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(meta) = fs::metadata(&target) {
                    let len = meta.len();
                    if len != LEN as u64 {
                        worst = Some(worst.map_or(len, |w: u64| w.min(len)));
                    }
                }
            }
            worst
        })
    };

    jugglr::actions::copy_file_atomic(&source, &target).unwrap();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let partial = observer.join().unwrap();

    assert_eq!(
        partial, None,
        "destination was visible at {:?} bytes instead of {} - a reader would have seen a corrupt file",
        partial, LEN
    );
    assert_eq!(fs::metadata(&target).unwrap().len(), LEN as u64);
}

#[test]
fn test_move_across_filesystems_preserves_content() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("data.bin");
    let payload: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    fs::write(&source, &payload).unwrap();

    let target = dir.path().join("moved/data.bin");
    fs::create_dir_all(target.parent().unwrap()).unwrap();

    jugglr::actions::move_file_atomic(&source, &target).unwrap();

    assert!(!source.exists(), "source should be gone after a move");
    assert_eq!(fs::read(&target).unwrap(), payload, "content must survive the move byte for byte");
}
