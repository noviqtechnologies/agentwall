use agentwall::lint;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_linter_valid_policy() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        validators:
          - path_traversal
"#;
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), policy_content).unwrap();

    let res = lint::execute(file.path().to_str().unwrap());
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0); // Valid, no warnings
}

#[test]
fn test_linter_warning_wildcard_and_missing_validators() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "*"
    action: allow
  - name: "exec_command"
    action: allow
    parameters:
      - name: "command"
        type: string
"#;
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), policy_content).unwrap();

    let res = lint::execute(file.path().to_str().unwrap());
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 2); // Warnings detected
}

#[test]
fn test_linter_fatal_error() {
    let policy_content = r#"
version: "invalid_version"
default_action: allow
"#;
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), policy_content).unwrap();

    let res = lint::execute(file.path().to_str().unwrap());
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 1); // Fatal errors / parsing failure
}
