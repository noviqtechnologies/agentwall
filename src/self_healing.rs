use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the Self-Healing engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealingConfig {
    pub enabled: bool,
    pub decay_window_days: u32,
    pub auto_suggest: bool,
    pub suggest_threshold: f64,
    pub approval_required: bool,
}

impl Default for SelfHealingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decay_window_days: 30,
            auto_suggest: true,
            suggest_threshold: 0.9,
            approval_required: true,
        }
    }
}

/// Computes the confidence decay of a rule based on how stale it is.
pub struct ConfidenceDecay;

impl ConfidenceDecay {
    /// Calculate decay factor from 0.0 (fully decayed/stale) to 1.0 (fresh).
    /// `last_seen_ns` is timestamp in nanoseconds.
    pub fn calculate(last_seen_ns: i64, decay_window_days: u32) -> f64 {
        let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64;
        Self::calculate_with_now(last_seen_ns, now_ns, decay_window_days)
    }

    /// Calculate with a specific 'now' time for testing.
    pub fn calculate_with_now(last_seen_ns: i64, now_ns: i64, decay_window_days: u32) -> f64 {
        if decay_window_days == 0 {
            return 1.0;
        }

        let elapsed_ns = now_ns.saturating_sub(last_seen_ns).max(0);
        let elapsed_days = elapsed_ns as f64 / (1_000_000_000.0 * 60.0 * 60.0 * 24.0);

        let decay = 1.0 - (elapsed_days / decay_window_days as f64);
        decay.clamp(0.0, 1.0)
    }
}

/// Z-Score based anomaly scorer for parameter values.
pub struct AnomalyScorer {
    // tool -> parameter -> value -> count
    frequencies: HashMap<String, HashMap<String, HashMap<String, usize>>>,
    // tool -> count
    tool_counts: HashMap<String, usize>,
}

impl AnomalyScorer {
    pub fn new() -> Self {
        Self {
            frequencies: HashMap::new(),
            tool_counts: HashMap::new(),
        }
    }

    /// Add a value to the baseline frequency distribution.
    pub fn observe(&mut self, tool: &str, param: &str, value: &str) {
        let tool_map = self.frequencies.entry(tool.to_string()).or_default();
        let param_map = tool_map.entry(param.to_string()).or_default();
        *param_map.entry(value.to_string()).or_default() += 1;
        
        *self.tool_counts.entry(tool.to_string()).or_default() += 1;
    }

    /// Calculate anomaly score (0.0 to 1.0) for a specific value based on the established baseline.
    /// Uses a frequency-based Z-score approximation where rarer values score closer to 1.0.
    pub fn score(&self, tool: &str, param: &str, value: &str) -> f64 {
        let tool_map = match self.frequencies.get(tool) {
            Some(m) => m,
            None => return 1.0, // Tool never seen = max anomaly
        };

        let param_map = match tool_map.get(param) {
            Some(m) => m,
            None => return 1.0, // Parameter never seen = max anomaly
        };

        let value_count = *param_map.get(value).unwrap_or(&0);
        if value_count == 0 {
            return 1.0; // Value never seen = max anomaly
        }

        // Calculate total occurrences of this parameter and the max frequency
        let mut total_param_count = 0;
        let mut max_freq = 0;
        for &count in param_map.values() {
            total_param_count += count;
            if count > max_freq {
                max_freq = count;
            }
        }

        if max_freq == 0 {
            return 1.0;
        }

        // If this parameter has only ever had one value, and we just saw it, score is 0.
        if param_map.len() == 1 && value_count == total_param_count {
            return 0.0;
        }

        // Calculate score: 1.0 - (frequency / max_frequency), adjusted for total occurrences
        // A single occurrence in a sea of 100 common values will score very high.
        // A single occurrence where every value is unique will score around 0.5.
        
        let freq_ratio = value_count as f64 / max_freq as f64;
        
        // Base score inversely proportional to frequency relative to the most common item
        let base_score = 1.0 - freq_ratio;

        // Confidence factor: if we have very little data, scale back the anomaly score
        // to avoid false positives early on.
        let confidence_factor = if total_param_count < 5 {
            0.5
        } else if total_param_count < 20 {
            0.8
        } else {
            1.0
        };

        (base_score * confidence_factor).clamp(0.0, 1.0)
    }
}

impl Default for AnomalyScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a proposed change to the security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuggestion {
    pub tool: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub anomaly_score: f64,
    pub timestamp_ns: i64,
    pub suggested_action: String,
}

/// Generates GitOps PR metadata based on baseline deviations.
pub struct SuggestionEngine;

impl SuggestionEngine {
    /// Detect deviations and generate suggestions.
    /// In a real implementation, this would compare current traffic against the ENFORCED policy.
    /// For the generator, we use the AnomalyScorer to find high-anomaly items.
    pub fn generate_suggestions(
        scorer: &AnomalyScorer,
        threshold: f64,
        events: &[crate::proxy::db::EgressEvent],
    ) -> Vec<PolicySuggestion> {
        let mut suggestions = Vec::new();
        let mut seen_keys = HashSet::new();

        for event in events {
            if event.transport != "mcp" {
                continue;
            }
            
            let tool = match &event.url_path {
                Some(t) => t,
                None => continue,
            };

            if let Some(body) = &event.request_body {
                if let Ok(params) = serde_json::from_str::<serde_json::Value>(body) {
                    let mut flat = Vec::new();
                    crate::generate_policy::flatten_json(&params, "", 0, 5, &mut flat);

                    for (k, v) in flat {
                        if let serde_json::Value::String(s) = v {
                            let score = scorer.score(tool, &k, &s);
                            
                            if score >= threshold {
                                let dedup_key = format!("{}::{}::{}", tool, k, s);
                                if !seen_keys.contains(&dedup_key) {
                                    seen_keys.insert(dedup_key);
                                    
                                    suggestions.push(PolicySuggestion {
                                        tool: tool.clone(),
                                        field: k.clone(),
                                        old_value: "baseline".to_string(),
                                        new_value: s.clone(),
                                        anomaly_score: score,
                                        timestamp_ns: event.timestamp_ns,
                                        suggested_action: "Review potential baseline deviation".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        suggestions
    }
}

/// Interface for GitOps PR integration.
pub trait GitOpsPrPayload {
    fn create_suggestion_pr(&self, suggestion: &PolicySuggestion) -> Result<String, String>;
}

/// Stub implementation that writes to stderr (acting as local SIEM alert).
pub struct StubGitOps;

impl GitOpsPrPayload for StubGitOps {
    fn create_suggestion_pr(&self, suggestion: &PolicySuggestion) -> Result<String, String> {
        // Emit SIEM alert if score > 0.95 (FR-4 AC)
        if suggestion.anomaly_score > 0.95 {
            let alert = serde_json::json!({
                "alert_type": "HIGH_ANOMALY_SCORE",
                "severity": "CRITICAL",
                "tool": suggestion.tool,
                "field": suggestion.field,
                "value": suggestion.new_value,
                "score": suggestion.anomaly_score,
                "timestamp_ns": suggestion.timestamp_ns
            });
            eprintln!("[SIEM ALERT] {}", alert);
        }
        
        Ok(format!("Stub PR created for {} deviation", suggestion.tool))
    }
}
