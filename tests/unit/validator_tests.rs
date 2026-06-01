use agentwall::validate;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_validate_success() {
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
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let payload_content = r#"{"path": "/safe/workspace/file.txt"}"#;
    let payload_file = NamedTempFile::new().unwrap();
    fs::write(payload_file.path(), payload_content).unwrap();

    let res = validate::execute(
        policy_file.path().to_str().unwrap(),
        "read_file",
        payload_file.path().to_str().unwrap(),
    );
    assert!(res.is_ok());
}

#[test]
fn test_validate_fail_path_traversal() {
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
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let payload_content = r#"{"path": "/safe/workspace/../../etc/passwd"}"#;
    let payload_file = NamedTempFile::new().unwrap();
    fs::write(payload_file.path(), payload_content).unwrap();

    let res = validate::execute(
        policy_file.path().to_str().unwrap(),
        "read_file",
        payload_file.path().to_str().unwrap(),
    );
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("validator_failed"));
    assert!(err.contains("path_traversal"));
}

#[test]
fn test_validate_fail_sql_injection() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "db_query"
    action: allow
    parameters:
      - name: "query"
        type: string
        validators:
          - sql_injection_basic
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let payload_content = r#"{"query": "SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin"}"#;
    let payload_file = NamedTempFile::new().unwrap();
    fs::write(payload_file.path(), payload_content).unwrap();

    let res = validate::execute(
        policy_file.path().to_str().unwrap(),
        "db_query",
        payload_file.path().to_str().unwrap(),
    );
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("sql_injection_basic"));
}

#[test]
fn test_validate_fail_shell_injection() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "run_tool"
    action: allow
    parameters:
      - name: "args"
        type: string
        validators:
          - shell_injection_basic
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let payload_content = r#"{"args": "file.txt; rm -rf /"}"#;
    let payload_file = NamedTempFile::new().unwrap();
    fs::write(payload_file.path(), payload_content).unwrap();

    let res = validate::execute(
        policy_file.path().to_str().unwrap(),
        "run_tool",
        payload_file.path().to_str().unwrap(),
    );
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("shell_injection_basic"));
}
