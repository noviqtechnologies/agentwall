use std::path::Path;
use crate::policy::loader::{load_policy, PolicyLoadResult};
use crate::policy::schema::ParamType;

pub fn execute(policy_path: &str) -> Result<i32, String> {
    // 1. Load the policy
    let load_res = load_policy(Path::new(policy_path), None);

    let (policy, loader_warnings) = match load_res {
        PolicyLoadResult::Fatal { error } => {
            eprintln!("LINT ERROR: Policy load failed with fatal error: {}", error);
            return Ok(1); // Exit code 1 for schema validation / parsing errors
        }
        PolicyLoadResult::Degraded { reason } => {
            eprintln!("LINT ERROR: Policy is degraded: {}", reason);
            return Ok(1);
        }
        PolicyLoadResult::Loaded { policy, warnings, .. } => (policy, warnings),
    };

    let mut warnings = loader_warnings;
    let errors: Vec<String> = Vec::new();

    // 2. Lint checks for permissive patterns
    for tool in &policy.tools {
        // Warning (a): Wildcard tool names
        if tool.name == "*" {
            warnings.push(format!(
                "Permissive Pattern: Tool rule uses wildcard name '*' which allows execution of any tool."
            ));
        }

        // Warning (b): Missing parameter validators on mutation tools
        // Define mutation tool keywords
        let is_mutation_tool = {
            let name_lower = tool.name.to_lowercase();
            name_lower.contains("write")
                || name_lower.contains("delete")
                || name_lower.contains("update")
                || name_lower.contains("create")
                || name_lower.contains("exec")
                || name_lower.contains("run")
                || name_lower.contains("send")
                || name_lower.contains("post")
                || name_lower.contains("bash")
                || name_lower.contains("terminal")
                || name_lower.contains("shell")
        };

        if is_mutation_tool && tool.action == "allow" {
            for param in &tool.parameters {
                if param.param_type == ParamType::String && param.validators.is_empty() {
                    warnings.push(format!(
                        "Permissive Pattern: Mutation tool '{}' parameter '{}' has type 'string' but no parameter validators are defined. Consider adding path_traversal, shell_injection_basic, etc. to prevent exploit execution.",
                        tool.name, param.name
                    ));
                }
            }
        }
    }

    // Print human-readable summary of what each agent identity is allowed to do
    println!("\n=== AgentWall Policy Access Control Summary ===");
    
    // Group allowed tools by identity
    use std::collections::HashMap;
    let mut identity_map: HashMap<String, Vec<(String, Vec<String>)>> = HashMap::new();

    for tool in &policy.tools {
        if tool.action == "allow" {
            let ident = tool.identity.clone().unwrap_or_else(|| "* (All Identities)".to_string());
            let params: Vec<String> = tool.parameters.iter().map(|p| p.name.clone()).collect();
            identity_map.entry(ident).or_default().push((tool.name.clone(), params));
        }
    }

    if identity_map.is_empty() {
        println!("  (No tools allowed in this policy - default deny applies to everything)");
    } else {
        for (identity, tools) in &identity_map {
            println!("Identity: {}", identity);
            for (tool_name, params) in tools {
                let params_str = if params.is_empty() {
                    "no parameters".to_string()
                } else {
                    format!("params: {}", params.join(", "))
                };
                println!("  - Allow tool '{}' ({})", tool_name, params_str);
            }
        }
    }
    println!("================================================\n");

    // Print Warnings and Errors summaries
    if !errors.is_empty() {
        println!("Errors detected:");
        for err in &errors {
            println!("  [ERROR] {}", err);
        }
        return Ok(1);
    }

    if !warnings.is_empty() {
        println!("Warnings detected:");
        for warn in &warnings {
            println!("  [WARN] {}", warn);
        }
        return Ok(2); // Exit code 2 for warnings only
    }

    println!("Policy linting passed successfully with no warnings or errors.");
    Ok(0) // Exit code 0 for fully valid policy with no warnings
}
