use std::io::Write;
use tempfile::NamedTempFile;
use jugglr::config::{load_config, validate_config};

#[test]
fn test_load_and_validate_example_config() {
    let example_path = std::path::Path::new("rules.example.toml");
    assert!(example_path.exists(), "rules.example.toml must exist");

    let config = load_config(example_path).expect("Failed to load example config");
    assert_eq!(config.rules.len(), 12);
    assert_eq!(config.global.debounce_ms, 500);

    let errors = validate_config(&config);
    assert!(errors.is_empty(), "Example config should have 0 validation errors, got: {:?}", errors);
}

#[test]
fn test_invalid_regex_validation() {
    let toml_content = r#"
[[rules]]
name = "Invalid Regex Rule"
watch_dir = "/tmp/watch"
enabled = true

  [rules.conditions]
  match = "all"
  name_regex = "[unclosed_regex("

  [rules.actions]
  action = "delete"
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(toml_content.as_bytes()).unwrap();

    let config = load_config(temp_file.path()).unwrap();
    let errors = validate_config(&config);
    assert!(!errors.is_empty(), "Should fail validation on invalid regex");
    assert!(errors[0].message.contains("Invalid name_regex"));
}

#[test]
fn test_missing_destination_validation() {
    let toml_content = r#"
[[rules]]
name = "Missing Dest Rule"
watch_dir = "/tmp/watch"
enabled = true

  [rules.conditions]
  match = "all"
  extensions = ["pdf"]

  [rules.actions]
  action = "move"
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(toml_content.as_bytes()).unwrap();

    let config = load_config(temp_file.path()).unwrap();
    let errors = validate_config(&config);
    assert!(!errors.is_empty(), "Should fail validation when move destination is missing");
    assert!(errors[0].message.contains("requires a 'destination'"));
}
