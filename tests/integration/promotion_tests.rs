use std::fs;
use std::process::Command;
use assert_cmd::prelude::*;
use tempfile::tempdir;

#[test]
fn test_promote_v1_fail() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(&policy_path, r#"
version: "1"
default_action: deny
tools: []
"#).unwrap();

    let mut cmd = Command::cargo_bin("agentwall").unwrap();
    cmd.arg("promote").arg("--policy").arg(policy_path.to_str().unwrap());
    
    // Should fail because version is 1
    cmd.assert().failure();
}

#[test]
fn test_promote_v2_missing_risk_fail() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(&policy_path, r#"
version: "2"
default_action: deny
identity:
  issuer: "https://auth.example.com"
  audience: "my-agent"
tools:
  - name: "read_file"
    action: "allow"
    # missing risk
"#).unwrap();

    let mut cmd = Command::cargo_bin("agentwall").unwrap();
    cmd.arg("promote").arg("--policy").arg(policy_path.to_str().unwrap());
    
    cmd.assert().failure();
}

#[test]
fn test_promote_v2_http_issuer_fail() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(&policy_path, r#"
version: "2"
default_action: deny
identity:
  issuer: "http://auth.example.com" # NOT HTTPS
  audience: "my-agent"
tools:
  - name: "read_file"
    action: "allow"
    risk: "low"
"#).unwrap();

    let mut cmd = Command::cargo_bin("agentwall").unwrap();
    cmd.arg("promote").arg("--policy").arg(policy_path.to_str().unwrap());
    
    cmd.assert().failure();
}

#[test]
fn test_promote_v2_success_and_sign() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(&policy_path, r#"
version: "2"
default_action: deny
identity:
  issuer: "https://auth.example.com"
  audience: "my-agent"
tools:
  - name: "read_file"
    action: "allow"
    risk: "low"
"#).unwrap();

    let mut cmd = Command::cargo_bin("agentwall").unwrap();
    cmd.arg("promote").arg("--policy").arg(policy_path.to_str().unwrap());
    
    cmd.assert().success();

    // Check if signature was created
    let sig_path = dir.path().join("policy.yaml.sig");
    assert!(sig_path.exists());
    
    let sig_bytes = fs::read(sig_path).unwrap();
    assert_eq!(sig_bytes.len(), 64); // Ed25519 signature length
}
