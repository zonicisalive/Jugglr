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
