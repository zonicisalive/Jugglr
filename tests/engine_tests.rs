use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use jugglr::config::schema::{ConditionGroup, MatchMode};
use jugglr::engine::conditions::ConditionEvaluator;

#[test]
fn test_extension_matching() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("document.pdf");
    File::create(&file_path).unwrap();

    let mut condition = ConditionGroup::default();
    condition.extensions = Some(vec!["pdf".to_string(), "docx".to_string()]);

    let res = ConditionEvaluator::evaluate(&condition, &file_path).unwrap();
    assert!(res.matched);

    let mut no_match = ConditionGroup::default();
    no_match.extensions = Some(vec!["png".to_string(), "jpg".to_string()]);
    let res_fail = ConditionEvaluator::evaluate(&no_match, &file_path).unwrap();
    assert!(!res_fail.matched);
}

#[test]
fn test_regex_matching_and_captures() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("Invoice_2026_9988.pdf");
    File::create(&file_path).unwrap();

    let mut condition = ConditionGroup::default();
    condition.name_regex = Some(r"^Invoice_(?P<inv_year>\d{4})_(?P<inv_id>\d+)\.pdf$".to_string());

    let res = ConditionEvaluator::evaluate(&condition, &file_path).unwrap();
    assert!(res.matched);
    assert_eq!(res.captures.get("inv_year").map(|s| s.as_str()), Some("2026"));
    assert_eq!(res.captures.get("inv_id").map(|s| s.as_str()), Some("9988"));
    assert_eq!(res.captures.get("regex_match_1").map(|s| s.as_str()), Some("2026"));
}

#[test]
fn test_glob_matching() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("report_q3_final.xlsx");
    File::create(&file_path).unwrap();

    let mut condition = ConditionGroup::default();
    condition.name_glob = Some("report_*_final.xlsx".to_string());

    let res = ConditionEvaluator::evaluate(&condition, &file_path).unwrap();
    assert!(res.matched);

    let mut fail_condition = ConditionGroup::default();
    fail_condition.name_glob = Some("statement_*.xlsx".to_string());
    let res_fail = ConditionEvaluator::evaluate(&fail_condition, &file_path).unwrap();
    assert!(!res_fail.matched);
}

#[test]
fn test_size_boundaries() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("data.bin");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(&vec![0u8; 5000]).unwrap(); // 5000 bytes

    let mut condition = ConditionGroup::default();
    condition.min_size_bytes = Some(1000);
    condition.max_size_bytes = Some(10000);

    let res = ConditionEvaluator::evaluate(&condition, &file_path).unwrap();
    assert!(res.matched);

    let mut fail_min = ConditionGroup::default();
    fail_min.min_size_bytes = Some(6000);
    let res_fail = ConditionEvaluator::evaluate(&fail_min, &file_path).unwrap();
    assert!(!res_fail.matched);
}

#[test]
fn test_content_contains() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("receipt.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "Payment Receipt\nTotal Due: $450.00\nThank you!").unwrap();

    let mut condition = ConditionGroup::default();
    condition.content_contains = Some(vec!["Receipt".to_string(), "Total Due".to_string()]);

    let res = ConditionEvaluator::evaluate(&condition, &file_path).unwrap();
    assert!(res.matched);
}

#[test]
fn test_nested_match_modes() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("urgent_note.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "Internal note contents").unwrap();

    // MatchMode::None (Negation)
    let condition = ConditionGroup {
        match_mode: MatchMode::None,
        extensions: Some(vec!["pdf".to_string(), "docx".to_string()]),
        ..Default::default()
    };

    let res = ConditionEvaluator::evaluate(&condition, &file_path).unwrap();
    assert!(res.matched, "txt is NOT in pdf or docx, so None mode should match");
}
