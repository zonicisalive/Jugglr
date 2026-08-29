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
