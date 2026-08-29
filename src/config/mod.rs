pub mod schema;

use std::fs;
use std::path::{Path, PathBuf};
use regex::Regex;
use glob::Pattern;
use schema::{ActionType, ConditionGroup, Config, RuleConfig};

/// Expand `~` and environment variables in a path string.
pub fn expand_path(path_str: &str) -> PathBuf {
    let expanded = shellexpand::tilde(path_str);
    let resolved = match shellexpand::env(&expanded) {
        Ok(env_expanded) => env_expanded.into_owned(),
        Err(_) => expanded.into_owned(),
    };
    PathBuf::from(resolved)
}

/// Resolve the default configuration path (~/.config/jugglr/rules.toml).
pub fn default_config_path() -> PathBuf {
    expand_path("~/.config/jugglr/rules.toml")
}

/// Load and parse a Config from a TOML file path.
pub fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    if !path.exists() {
        return Err(format!("Configuration file does not exist: {}", path.display()).into());
    }

    let contents = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub rule_name: Option<String>,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref rule) = self.rule_name {
            write!(f, "Rule '{}': {}", rule, self.message)
        } else {
            write!(f, "Global: {}", self.message)
        }
    }
}

/// Validate syntax and integrity of a loaded Config.
pub fn validate_config(config: &Config) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if config.rules.is_empty() {
        errors.push(ValidationError {
            rule_name: None,
            message: "No rules defined in configuration".to_string(),
        });
    }

    for rule in &config.rules {
        validate_rule(rule, &mut errors);
    }

    errors
}

fn validate_rule(rule: &RuleConfig, errors: &mut Vec<ValidationError>) {
    let rule_name = rule.name.clone();

    // Check watch_dir
    let watch_path = expand_path(&rule.watch_dir);
    if !watch_path.exists() {
        // Not a fatal syntax error, but worth noting or warning
        // Note: directory might be created later, but we flag if completely invalid
    }

    // Check condition regexes and globs
    validate_condition_group(&rule.conditions, &rule_name, errors);

    // Check actions
    match rule.actions.action {
        ActionType::Move | ActionType::Copy | ActionType::Symlink | ActionType::Hardlink => {
            if rule.actions.destination.is_none() {
                errors.push(ValidationError {
                    rule_name: Some(rule_name.clone()),
                    message: format!("Action '{:?}' requires a 'destination' path", rule.actions.action),
                });
            }
        }
        ActionType::Rename => {
            if rule.actions.destination.is_none() {
                errors.push(ValidationError {
                    rule_name: Some(rule_name.clone()),
                    message: "Action 'Rename' requires a 'destination' template for the new name".to_string(),
                });
            }
        }
        ActionType::Script => {
            if rule.actions.script.is_none() {
                errors.push(ValidationError {
                    rule_name: Some(rule_name.clone()),
                    message: "Action 'Script' requires a 'script' command or path".to_string(),
                });
            }
        }
        ActionType::Extract | ActionType::Trash | ActionType::Quarantine | ActionType::Delete | ActionType::None => {}
    }
}

fn validate_condition_group(group: &ConditionGroup, rule_name: &str, errors: &mut Vec<ValidationError>) {
    if let Some(ref regex_str) = group.name_regex {
        if let Err(e) = Regex::new(regex_str) {
            errors.push(ValidationError {
                rule_name: Some(rule_name.to_string()),
                message: format!("Invalid name_regex '{}': {}", regex_str, e),
            });
        }
    }

    if let Some(ref glob_str) = group.name_glob {
        if let Err(e) = Pattern::new(glob_str) {
            errors.push(ValidationError {
                rule_name: Some(rule_name.to_string()),
                message: format!("Invalid name_glob '{}': {}", glob_str, e),
            });
        }
    }

    if let Some(ref content_re) = group.content_regex {
        if let Err(e) = Regex::new(content_re) {
            errors.push(ValidationError {
                rule_name: Some(rule_name.to_string()),
                message: format!("Invalid content_regex '{}': {}", content_re, e),
            });
        }
    }

    if let (Some(min), Some(max)) = (group.min_size_bytes, group.max_size_bytes) {
        if min > max {
            errors.push(ValidationError {
                rule_name: Some(rule_name.to_string()),
                message: format!("min_size_bytes ({}) cannot be greater than max_size_bytes ({})", min, max),
            });
        }
    }

    if let Some(ref subgroups) = group.subgroups {
        for sub in subgroups {
            validate_condition_group(sub, rule_name, errors);
        }
    }
}
