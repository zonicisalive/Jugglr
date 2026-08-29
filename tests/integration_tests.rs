use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use jugglr::config::schema::{ActionConfig, ActionType, ConditionGroup, Config, ConflictResolution, RuleConfig};
use jugglr::engine::RuleEngine;

#[test]
fn test_end_to_end_rule_engine_pipeline() {
    let base_dir = tempdir().unwrap();
    let watch_dir = base_dir.path().join("Downloads");
    let dest_dir = base_dir.path().join("Documents/Finance");
    let quarantine_dir = base_dir.path().join("quarantine");

    fs::create_dir_all(&watch_dir).unwrap();

    let mut config = Config::default();
    config.global.default_quarantine_dir = quarantine_dir.to_string_lossy().to_string();

    // Rule 1: Move Invoices
    let mut invoice_conditions = ConditionGroup::default();
    invoice_conditions.extensions = Some(vec!["pdf".to_string()]);
    invoice_conditions.content_contains = Some(vec!["Invoice".to_string()]);

    let invoice_action = ActionConfig {
        action: ActionType::Move,
        destination: Some(format!("{}/{{year}}/", dest_dir.display())),
        conflict_resolution: ConflictResolution::RenameWithCounter,
        ..Default::default()
    };

    config.rules.push(RuleConfig {
        name: "Organize Invoices".to_string(),
        watch_dir: watch_dir.to_string_lossy().to_string(),
        enabled: true,
        conditions: invoice_conditions,
        actions: invoice_action,
    });

    // Rule 2: Quarantine Deceptive Scripts
    let mut script_conditions = ConditionGroup::default();
    script_conditions.double_extension = Some(true);

    let script_action = ActionConfig {
        action: ActionType::Quarantine,
        destination: Some(quarantine_dir.to_string_lossy().to_string()),
        strip_executable: true,
        ..Default::default()
    };

    config.rules.push(RuleConfig {
        name: "Quarantine Suspicious Scripts".to_string(),
        watch_dir: watch_dir.to_string_lossy().to_string(),
        enabled: true,
        conditions: script_conditions,
        actions: script_action,
    });

    // Rule 3: Neutralize Executable Permission on normal documents
    let mut perm_conditions = ConditionGroup::default();
    perm_conditions.extensions = Some(vec!["docx".to_string()]);
    perm_conditions.dangerous_permissions = Some(true);

    let perm_action = ActionConfig {
        action: ActionType::None,
        strip_executable: true,
        ..Default::default()
    };

    config.rules.push(RuleConfig {
        name: "Neutralize Permissions".to_string(),
        watch_dir: watch_dir.to_string_lossy().to_string(),
        enabled: true,
        conditions: perm_conditions,
        actions: perm_action,
    });

    let engine = RuleEngine::new(config);

    // Test 1: Process invoice
    let invoice_file = watch_dir.join("Invoice_ACME_101.pdf");
    let mut f1 = File::create(&invoice_file).unwrap();
    writeln!(f1, "Invoice #101\nTotal: $1,200.00").unwrap();

    let outcomes1 = engine.process_file(&invoice_file);
    assert_eq!(outcomes1.len(), 1);
    assert!(outcomes1[0].success);
    assert!(!invoice_file.exists());
    let current_year = chrono::Local::now().format("%Y").to_string();
    let expected_invoice_path = dest_dir.join(format!("{}/Invoice_ACME_101.pdf", current_year));
    assert!(expected_invoice_path.exists(), "Invoice should have been moved into year folder: {}", expected_invoice_path.display());

    // Test 2: Process deceptive script
    let deceptive_file = watch_dir.join("payroll.pdf.sh");
    let mut f2 = File::create(&deceptive_file).unwrap();
    writeln!(f2, "#!/bin/bash\necho bad").unwrap();

    let outcomes2 = engine.process_file(&deceptive_file);
    assert_eq!(outcomes2.len(), 1);
    assert!(outcomes2[0].success);
    assert!(!deceptive_file.exists());
    assert!(outcomes2[0].target_path.as_ref().unwrap().exists());

    // Test 3: Process executable docx
    let doc_file = watch_dir.join("strategy.docx");
    File::create(&doc_file).unwrap();
    fs::set_permissions(&doc_file, Permissions::from_mode(0o777)).unwrap();

    let outcomes3 = engine.process_file(&doc_file);
    assert_eq!(outcomes3.len(), 1);
    let final_perms = fs::metadata(&doc_file).unwrap().permissions().mode();
    assert_eq!(final_perms & 0o111, 0, "Execute bit must be stripped");
}
