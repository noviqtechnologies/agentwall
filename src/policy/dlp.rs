use regex::{Regex, RegexSet};
use bip39::Mnemonic;
use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone, PartialEq)]
pub enum SecretCategory {
    AwsAccessKey,
    GitHubToken,
    OpenAiApiKey,
    AnthropicApiKey,
    SshPrivateKey,
    StripeKey,
    DatabaseUri,
    Pii,
    HighEntropy,
    CryptoSeedPhrase,
    EnvVar,
    Other,
}

impl SecretCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretCategory::AwsAccessKey => "AWS Access Key",
            SecretCategory::GitHubToken => "GitHub Token",
            SecretCategory::OpenAiApiKey => "OpenAI API Key",
            SecretCategory::AnthropicApiKey => "Anthropic API Key",
            SecretCategory::SshPrivateKey => "SSH Private Key",
            SecretCategory::StripeKey => "Stripe Key",
            SecretCategory::DatabaseUri => "Database URI",
            SecretCategory::Pii => "PII",
            SecretCategory::HighEntropy => "High Entropy",
            SecretCategory::CryptoSeedPhrase => "Crypto Seed Phrase",
            SecretCategory::EnvVar => "Environment Variable",
            SecretCategory::Other => "Other Secret",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub category: SecretCategory,
    pub pattern_name: String,
    pub position: usize,
    pub length: usize,
    pub preview: String,
}

pub struct PatternDef {
    pub name: &'static str,
    pub category: SecretCategory,
    pub individual_regex: Regex,
}

pub struct DlpScanner {
    regex_set: RegexSet,
    patterns: Vec<PatternDef>,
}

impl DlpScanner {
    pub fn new() -> Result<Self, regex::Error> {
        let pattern_defs = vec![
            ("AWS Access Key (AKIA)", SecretCategory::AwsAccessKey, r"AKIA[0-9A-Z]{16}"),
            ("AWS Access Key (ASIA)", SecretCategory::AwsAccessKey, r"ASIA[0-9A-Z]{16}"),
            ("GitHub PAT (ghp)", SecretCategory::GitHubToken, r"ghp_[0-9a-zA-Z\-]{36,}"),
            ("GitHub OAuth (gho)", SecretCategory::GitHubToken, r"gho_[0-9a-zA-Z\-]{36,}"),
            ("GitHub Fine-Grained PAT", SecretCategory::GitHubToken, r"github_pat_[0-9a-zA-Z_]{80,96}"),
            ("OpenAI API Key", SecretCategory::OpenAiApiKey, r"sk-[a-zA-Z0-9\-]{20,}"),
            ("Anthropic API Key", SecretCategory::AnthropicApiKey, r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
            ("SSH Private Key", SecretCategory::SshPrivateKey, r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
            ("Stripe Secret Key", SecretCategory::StripeKey, r"sk_live_[0-9a-zA-Z]{20,}"),
            ("Stripe Restricted Key", SecretCategory::StripeKey, r"rk_live_[0-9a-zA-Z]{20,}"),
            ("PostgreSQL URI", SecretCategory::DatabaseUri, r"postgres(ql)?://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+"),
            ("MongoDB URI", SecretCategory::DatabaseUri, r"mongodb(\+srv)?://[^:]+:[^@]+@[a-zA-Z0-9.-]+"),
            ("Redis URI", SecretCategory::DatabaseUri, r"redis(s)?://(:[^@]+@)?[a-zA-Z0-9.-]+:[0-9]+"),
            ("US SSN", SecretCategory::Pii, r"\b[0-8][0-9]{2}-[0-9]{2}-[0-9]{4}\b"),
            ("Emirates ID", SecretCategory::Pii, r"\b784-[0-9]{4}-[0-9]{7}-[0-9]\b"),
            ("Env Var Access", SecretCategory::EnvVar, r"\$[A-Z_][A-Z0-9_]+"),
        ];

        let raw_patterns: Vec<String> = pattern_defs.iter().map(|(_, _, p)| p.to_string()).collect();
        let regex_set = RegexSet::new(&raw_patterns)?;

        let mut patterns = Vec::new();
        for (name, category, pat) in pattern_defs {
            patterns.push(PatternDef {
                name,
                category,
                individual_regex: Regex::new(pat)?,
            });
        }

        Ok(Self { regex_set, patterns })
    }

    pub fn scan_content(&self, content: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();
        let mut decoded = content.to_string();
        
        // Base64 recursive decoding (up to 3 levels)
        for _ in 0..3 {
            if is_base64_like(&decoded) {
                if let Ok(bytes) = general_purpose::STANDARD.decode(decoded.trim()) {
                    if let Ok(utf8) = String::from_utf8(bytes) {
                        decoded = utf8;
                        continue;
                    }
                }
            }
            break;
        }

        // Regex patterns
        let matched_indices: Vec<usize> = self.regex_set.matches(&decoded).into_iter().collect();
        for idx in matched_indices {
            let pat = &self.patterns[idx];
            for m in pat.individual_regex.find_iter(&decoded) {
                let text = m.as_str();
                if idx == 5 && text.starts_with("sk-ant-") { continue; } // OpenAI vs Anthropic overlap
                
                // Optional: checksum validation
                if pat.name == "Emirates ID" && !validate_emirates_id(text) { continue; }

                findings.push(SecretFinding {
                    category: pat.category.clone(),
                    pattern_name: pat.name.to_string(),
                    position: m.start(),
                    length: m.len(),
                    preview: truncated_preview(text),
                });
            }
        }

        // BIP-39 detection
        if let Some(phrase) = detect_bip39(&decoded) {
            findings.push(SecretFinding {
                category: SecretCategory::CryptoSeedPhrase,
                pattern_name: "BIP-39 Seed Phrase".to_string(),
                position: 0,
                length: phrase.len(),
                preview: truncated_preview(&phrase),
            });
        }

        // Entropy analysis
        let words = decoded.split_whitespace();
        for w in words {
            if w.len() > 32 && calculate_shannon_entropy(w) > 4.5 {
                // Ignore if it matches a known pattern to avoid double reporting
                let mut known = false;
                for f in &findings {
                    if w.contains(&f.preview.replace("*", "")) { known = true; break; }
                }
                if !known && !is_base64_like(w) { 
                    findings.push(SecretFinding {
                        category: SecretCategory::HighEntropy,
                        pattern_name: "suspicious_high_entropy".to_string(),
                        position: 0,
                        length: w.len(),
                        preview: truncated_preview(w),
                    });
                }
            }
        }

        findings
    }
}

// Helpers
fn is_base64_like(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 16 || s.len() % 4 != 0 { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

pub fn calculate_shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut total = 0;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 { return 0.0; }
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / total as f64;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn detect_bip39(s: &str) -> Option<String> {
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() < 12 { return None; }
    
    // Check sliding windows of 12 or 24 words
    for window_size in [24, 12] {
        if words.len() >= window_size {
            for window in words.windows(window_size) {
                let phrase = window.join(" ");
                if Mnemonic::parse(&phrase).is_ok() {
                    return Some(phrase);
                }
            }
        }
    }
    None
}

fn validate_emirates_id(id: &str) -> bool {
    let digits: Vec<u32> = id.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 15 {
        return false;
    }
    if digits[0] != 7 || digits[1] != 8 || digits[2] != 4 {
        return false;
    }
    
    // Luhn Mod-10 checksum check
    let mut sum = 0;
    let mut double = false;
    for i in (0..15).rev() {
        let mut d = digits[i];
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

pub fn truncated_preview(secret: &str) -> String {
    if secret.len() <= 8 { return "****".to_string(); }
    let prefix_len = secret.char_indices().skip(2).find(|(_, c)| *c == '_' || *c == '-').map(|(i, _)| (i + 1).min(6)).unwrap_or(4).min(secret.len());
    let suffix_len = 4.min(secret.len().saturating_sub(prefix_len + 4));
    let suffix_start = secret.len() - suffix_len;
    format!("{}****{}", &secret[..prefix_len], &secret[suffix_start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_secrets() {
        let scanner = DlpScanner::new().unwrap();
        let findings = scanner.scan_content("Here is my aws key: AKIAIOSFODNN7EXAMPLE and my github token: ghp_123456789012345678901234567890123456");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].category, SecretCategory::AwsAccessKey);
        assert_eq!(findings[1].category, SecretCategory::GitHubToken);
    }

    #[test]
    fn test_base64_recursive() {
        let scanner = DlpScanner::new().unwrap();
        // Base64 of "sk-12345678901234567890" -> c2stMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
        let encoded = "c2stMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";
        let findings = scanner.scan_content(encoded);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, SecretCategory::OpenAiApiKey);
    }

    #[test]
    fn test_high_entropy() {
        let scanner = DlpScanner::new().unwrap();
        let random_string = "xK9!pL4@mQ1#vN8$zW2%bC7^hR5&jT3*fD6(yG0)";
        let findings = scanner.scan_content(random_string);
        let entropy_findings: Vec<_> = findings.into_iter().filter(|f| f.category == SecretCategory::HighEntropy).collect();
        assert_eq!(entropy_findings.len(), 1);
    }

    #[test]
    fn test_bip39() {
        let scanner = DlpScanner::new().unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let findings = scanner.scan_content(phrase);
        let crypto_findings: Vec<_> = findings.into_iter().filter(|f| f.category == SecretCategory::CryptoSeedPhrase).collect();
        assert_eq!(crypto_findings.len(), 1);
    }

    #[test]
    fn test_env_var() {
        let scanner = DlpScanner::new().unwrap();
        let text = "Please fetch $AWS_SECRET_ACCESS_KEY from env";
        let findings = scanner.scan_content(text);
        assert_eq!(findings[0].category, SecretCategory::EnvVar);
    }

    #[test]
    fn test_emirates_id() {
        let scanner = DlpScanner::new().unwrap();
        // Valid Luhn Emirates ID (sum is 70, which is divisible by 10)
        let valid_id = "My Emirates ID is 784-1982-1234567-6";
        let findings_valid = scanner.scan_content(valid_id);
        assert_eq!(findings_valid.len(), 1);
        assert_eq!(findings_valid[0].category, SecretCategory::Pii);

        // Invalid Luhn Emirates ID (sum is 65, not divisible by 10)
        let invalid_id = "My Emirates ID is 784-1982-1234567-1";
        let findings_invalid = scanner.scan_content(invalid_id);
        assert_eq!(findings_invalid.len(), 0);
    }
}
