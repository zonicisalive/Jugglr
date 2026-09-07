use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use jugglr::actions::security::{neutralize_permissions, quarantine_file};
use jugglr::engine::conditions::{is_suspicious_double_extension, scan_for_secrets};

#[test]
fn test_double_extension_detection() {
    assert!(is_suspicious_double_extension("invoice.pdf.sh"));
    assert!(is_suspicious_double_extension("photo.jpg.exe"));
    assert!(is_suspicious_double_extension("resume.docx.py"));
    assert!(is_suspicious_double_extension("archive.zip.bin"));

    // Legitimate tar archives must NOT be flagged
    assert!(!is_suspicious_double_extension("archive.tar.gz"));
    assert!(!is_suspicious_double_extension("backup.tar.bz2"));
    assert!(!is_suspicious_double_extension("source.tar.xz"));
    assert!(!is_suspicious_double_extension("data.tar.zst"));
    assert!(!is_suspicious_double_extension("normal_file.pdf"));
}

#[test]
fn test_permission_neutralizer() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("downloaded_doc.pdf");
    File::create(&file_path).unwrap();

    // Give executable permissions (0o755)
    fs::set_permissions(&file_path, Permissions::from_mode(0o755)).unwrap();

    let initial_mode = fs::metadata(&file_path).unwrap().permissions().mode();
    assert_ne!(initial_mode & 0o111, 0, "Should have execute bit set");

    let modified = neutralize_permissions(&file_path, false).unwrap();
    assert!(modified);

    let final_mode = fs::metadata(&file_path).unwrap().permissions().mode();
    assert_eq!(final_mode & 0o111, 0, "Execute bits must be stripped (0o644)");
}

#[test]
fn test_secret_detection() {
    let dir = tempdir().unwrap();

    // 1. AWS Access Key
    let aws_env = dir.path().join(".env");
    let mut f1 = File::create(&aws_env).unwrap();
    writeln!(f1, "AWS_ACCESS_KEY_ID={}{}\nAWS_SECRET_ACCESS_KEY=mocksecretkey1234567890", "AKIA", "IOSFODNN7EXAMPLE").unwrap();
    let res = scan_for_secrets(&aws_env);
    assert_eq!(res, Some("AWS Access Key ID".to_string()));

    // 2. Private Key
    let key_file = dir.path().join("id_rsa");
    let mut f2 = File::create(&key_file).unwrap();
    writeln!(f2, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n-----END OPENSSH PRIVATE KEY-----").unwrap();
    let res_key = scan_for_secrets(&key_file);
    assert_eq!(res_key, Some("Cryptographic Private Key".to_string()));

    // 3. Normal Clean File
    let clean_file = dir.path().join("clean.txt");
    let mut f3 = File::create(&clean_file).unwrap();
    writeln!(f3, "This is a clean document with no tokens.").unwrap();
    let res_clean = scan_for_secrets(&clean_file);
    assert_eq!(res_clean, None);
}

#[test]
fn test_quarantine_action_and_audit_log() {
    let dir = tempdir().unwrap();
    let quarantine_dir = dir.path().join("quarantine");
    let evil_file = dir.path().join("trojan.pdf.sh");

    let mut f = File::create(&evil_file).unwrap();
    writeln!(f, "#!/bin/bash\necho 'Suspicious payload'").unwrap();

    let target_path = quarantine_file(&evil_file, &quarantine_dir, "Deceptive double extension", false).unwrap();

    assert!(!evil_file.exists(), "Original file should have been moved");
    assert!(target_path.exists(), "Quarantined file must exist in quarantine dir");

    // Check permissions are 0o600
    let perms = fs::metadata(&target_path).unwrap().permissions().mode();
    assert_eq!(perms & 0o777, 0o600, "Quarantined file permissions must be 0o600");

    // Check audit log
    let audit_log = quarantine_dir.join("quarantine_audit.jsonl");
    assert!(audit_log.exists(), "quarantine_audit.jsonl must be created");
    let log_content = fs::read_to_string(&audit_log).unwrap();
    assert!(log_content.contains("trojan.pdf.sh"));
    assert!(log_content.contains("Deceptive double extension"));
}

#[test]
fn test_script_action_cannot_be_injected_via_filename() {
    let dir = tempdir().unwrap();
    // A filename an attacker controls, carrying a shell command break-out. No quotes of its
    // own: the template does not quote the placeholder, so bare `;` is enough.
    let source = dir.path().join("photo; touch pwned; echo x.jpg");
    let canary = dir.path().join("pwned");
    File::create(&source).unwrap();

    let action_cfg = jugglr::config::schema::ActionConfig {
        action: jugglr::config::schema::ActionType::Script,
        script: Some(format!("cd {} && echo {{filename}} > handled.log", dir.path().display())),
        ..Default::default()
    };

    let ctx = jugglr::engine::variables::ContextVariables::from_file(&source, None, None, None);
    jugglr::actions::ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Injection", false).unwrap();

    assert!(!canary.exists(), "filename must not be able to run commands of its own");
    let logged = fs::read_to_string(dir.path().join("handled.log")).unwrap();
    assert!(logged.contains("photo"), "the real filename should still reach the script");
}

#[test]
fn test_move_destination_cannot_escape_via_metadata() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("track.mp3");
    File::create(&source).unwrap();

    let mut ctx = jugglr::engine::variables::ContextVariables::new();
    ctx.insert("music_artist", "../..");

    let dest_root = dir.path().join("Music");
    let action_cfg = jugglr::config::schema::ActionConfig {
        action: jugglr::config::schema::ActionType::Move,
        destination: Some(format!("{}/{{music_artist}}/", dest_root.display())),
        ..Default::default()
    };

    let outcome =
        jugglr::actions::ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Escape", false).unwrap();

    assert!(outcome.success, "{}", outcome.message);

    // Compare resolved paths: `Music/../../track.mp3` starts_with `Music/` lexically while
    // actually landing two directories above it.
    let landed = outcome.target_path.unwrap().canonicalize().unwrap();
    let dest_root = dest_root.canonicalize().unwrap();
    assert!(landed.starts_with(&dest_root), "file escaped to {}", landed.display());
}

#[test]
fn test_rename_stays_in_the_source_directory() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("report.pdf");
    File::create(&source).unwrap();

    let action_cfg = jugglr::config::schema::ActionConfig {
        action: jugglr::config::schema::ActionType::Rename,
        destination: Some("../../owned.pdf".to_string()),
        ..Default::default()
    };

    let ctx = jugglr::engine::variables::ContextVariables::from_file(&source, None, None, None);
    let outcome =
        jugglr::actions::ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Rename", false).unwrap();

    assert!(outcome.success);
    assert_eq!(outcome.target_path.unwrap(), dir.path().join("owned.pdf"));
}

#[test]
fn test_rename_to_a_name_without_an_extension() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("scan001.pdf");
    File::create(&source).unwrap();

    let action_cfg = jugglr::config::schema::ActionConfig {
        action: jugglr::config::schema::ActionType::Rename,
        destination: Some("invoice_archive".to_string()),
        ..Default::default()
    };

    let ctx = jugglr::engine::variables::ContextVariables::from_file(&source, None, None, None);
    let outcome =
        jugglr::actions::ActionExecutor::execute(&action_cfg, &source, &ctx, "/tmp", "Rename", false).unwrap();

    assert!(outcome.success, "{}", outcome.message);
    let target = dir.path().join("invoice_archive");
    assert!(target.is_file(), "a dotless rename target is a filename, not a folder");
}

#[test]
fn test_secret_scan_reads_files_that_are_not_valid_utf8() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("payload.bin");
    let mut f = File::create(&path).unwrap();
    f.write_all(&[0xff, 0xfe, 0x00]).unwrap();
    f.write_all(b"-----BEGIN RSA PRIVATE KEY-----").unwrap();
    f.write_all(&[0x80, 0x81]).unwrap();

    assert_eq!(
        scan_for_secrets(&path),
        Some("Cryptographic Private Key".to_string()),
        "binary files must still be scanned for secrets"
    );
}
