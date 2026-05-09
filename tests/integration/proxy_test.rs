use assert_cmd::prelude::*;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_proxy_integration_mock_mcp() {
    // Write policy file
    let mut policy_file = NamedTempFile::new().unwrap();
    write!(
        policy_file,
        r#"
version: "1"
default_action: deny
tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        required: true
"#
    )
    .unwrap();

    let mut fixture_file = NamedTempFile::new().unwrap();
    write!(
        fixture_file,
        r#"
[
  {{ "tool": "read_file", "params": {{ "path": "/workspace/foo.txt" }} }},
  {{ "tool": "exec_shell", "params": {{ "cmd": "rm -rf /" }} }}
]
"#
    )
    .unwrap();

    // Just use vexa check to verify logic since we can't easily spawn mock server
    // and python agent inside cargo test without external dependencies.
    // The Python test-tools logic serves as the true integration test when run
    // via a bash script in CI. Here we use the vexa check CLI.

    let mut cmd = Command::cargo_bin("vexa").unwrap();
    cmd.arg("check")
        .arg("--policy")
        .arg(policy_file.path())
        .arg(fixture_file.path());

    cmd.assert()
        .code(1) // Should exit 1 because one is denied
        .stdout(predicates::str::contains("ALLOW\tread_file"))
        .stdout(predicates::str::contains("DENY\texec_shell"));
}
