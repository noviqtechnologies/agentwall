//! Promotion validation suite (FR-204)
//! Validates risk scores, identity config, and signs policies.

use colored::*;
use ed25519_dalek::{SigningKey, Signer};
use rand::RngCore;
use std::fs;
use std::path::Path;
use crate::policy::loader::{load_policy, PolicyLoadResult};
use crate::policy::schema::PolicyFile;

/// Result of a promotion check
pub enum PromoteResult {
    Success { signature_path: String },
    ValidationError(String),
    IoError(String),
}

/// Run the promotion logic
pub fn run_promote(policy_path: &str, key_path: Option<&str>) -> i32 {
    println!("{} Promoting policy: {}", "ℹ".blue(), policy_path.yellow());

    // 1. Structural & Logic Validation
    // We load the raw YAML first to check for specific v2 requirements before compilation
    let yaml_content = match fs::read_to_string(policy_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to read policy file: {}", "✖".red(), e);
            return 1;
        }
    };

    let policy_file: PolicyFile = match serde_yaml::from_str(&yaml_content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Policy schema invalid: {}", "✖".red(), e);
            return 1;
        }
    };

    // Check version
    if policy_file.version != "2" {
        eprintln!("{} Promotion requires Policy Schema v2.", "✖".red());
        return 1;
    }

    let mut errors = Vec::new();

    // Check identity issuer (HTTPS)
    if let Some(ident) = &policy_file.identity {
        if !ident.issuer.starts_with("https://") {
            errors.push(format!("Identity issuer must use HTTPS: {}", ident.issuer));
        }
    } else {
        errors.push("Production policies MUST have an identity configuration (FR-202).".to_string());
    }

    // Check risk scores for all tools
    if let Some(tools) = &policy_file.tools {
        for tool in tools {
            if tool.risk.is_none() {
                errors.push(format!("Tool '{}' is missing a risk score.", tool.name));
            }
        }
    }

    // Load/Compile policy to ensure it's functional
    match load_policy(Path::new(policy_path), None) {
        PolicyLoadResult::Loaded { .. } => {}
        PolicyLoadResult::Degraded { reason } => errors.push(format!("Policy degraded: {}", reason)),
        PolicyLoadResult::Fatal { error } => errors.push(format!("Policy fatal error: {}", error)),
    }

    if !errors.is_empty() {
        eprintln!("{} Promotion failed with {} errors:", "✖".red(), errors.len());
        for err in errors {
            eprintln!("  - {}", err.yellow());
        }
        return 1;
    }

    println!("{} Validation passed.", "✓".green());

    // 2. Signing
    println!("{} Signing policy...", "ℹ".blue());
    
    // In a real scenario, the key would be loaded from key_path.
    // For FR-204 implementation, we'll generate a temporary key if none provided.
    let signing_key = if let Some(path) = key_path {
        match load_signing_key(path) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("{} Failed to load key: {}", "✖".red(), e);
                return 1;
            }
        }
    } else {
        println!("  {} No key provided, using ephemeral key for signing (DEMO MODE).", "⚠".yellow());
        let mut csprng = rand::rngs::OsRng;
        let mut key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut key_bytes);
        SigningKey::from_bytes(&key_bytes)
    };

    let signature = signing_key.sign(yaml_content.as_bytes());
    let sig_path = format!("{}.sig", policy_path);

    if let Err(e) = fs::write(&sig_path, signature.to_bytes()) {
        eprintln!("{} Failed to write signature: {}", "✖".red(), e);
        return 1;
    }

    println!("{} Policy promoted and signed!", "✓".green().bold());
    println!("  {} Signature saved to: {}", "→".blue(), sig_path.cyan());
    
    // Also output public key for verification
    println!("  {} Public Key (hex): {}", "🔑".blue(), hex::encode(signing_key.verifying_key().to_bytes()));

    0
}

fn load_signing_key(path: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() == 32 {
        let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
        Ok(SigningKey::from_bytes(&array))
    } else {
        Err("Invalid key file: expected 32-byte Ed25519 private key".into())
    }
}
