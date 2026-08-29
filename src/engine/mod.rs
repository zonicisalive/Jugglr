pub mod conditions;
pub mod variables;

use std::path::Path;
use tracing::{info, debug, warn};

use crate::actions::{ActionExecutor, ExecutionOutcome};
use crate::config::expand_path;
use crate::config::schema::{ActionType, Config};
use crate::engine::conditions::ConditionEvaluator;
use crate::engine::variables::ContextVariables;
use crate::utils::mime::{compute_sha256, detect_mime};

pub struct RuleEngine {
    config: Config,
}

impl RuleEngine {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn update_config(&mut self, config: Config) {
        self.config = config;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Process a debounced file event against all configured rules.
    pub fn process_file(&self, file_path: &Path) -> Vec<ExecutionOutcome> {
        let mut outcomes = Vec::new();

        if !file_path.exists() {
            debug!("File {} no longer exists, skipping evaluation", file_path.display());
            return outcomes;
        }

        let mut current_path = file_path.to_path_buf();

        for rule in &self.config.rules {
            if !rule.enabled {
                continue;
            }

            // Check if file is inside the rule's watch_dir
            let watch_dir = expand_path(&rule.watch_dir);
            let rule_watch_canonical = watch_dir.canonicalize().unwrap_or(watch_dir.clone());

            let is_in_watch_dir = if let Some(parent) = current_path.parent() {
                let parent_canonical = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
                parent_canonical.starts_with(&rule_watch_canonical)
            } else {
                false
            };

            if !is_in_watch_dir {
                continue;
            }

            // Evaluate conditions
            match ConditionEvaluator::evaluate_with_vt(
                &rule.conditions,
                &current_path,
                self.config.global.virustotal_api_key.as_deref(),
            ) {
                Ok(eval_result) => {
                    if eval_result.matched {
                        info!("🎯 Rule '{}' matched on file: {}", rule.name, current_path.display());

                        let mime = eval_result.mime_type.or_else(|| detect_mime(&current_path).ok());
                        let sha256 = compute_sha256(&current_path).ok();

                        let context = ContextVariables::from_file(
                            &current_path,
                            mime.as_deref(),
                            sha256.as_deref(),
                            Some(&eval_result.captures),
                        );

                        let outcome = match ActionExecutor::execute(
                            &rule.actions,
                            &current_path,
                            &context,
                            &self.config.global.default_quarantine_dir,
                            &rule.name,
                            self.config.global.dry_run,
                        ) {
                            Ok(out) => out,
                            Err(e) => {
                                warn!("Action execution error for rule '{}': {}", rule.name, e);
                                ExecutionOutcome {
                                    success: false,
                                    source_path: current_path.clone(),
                                    target_path: None,
                                    action_type: rule.actions.action,
                                    message: format!("Error: {}", e),
                                }
                            }
                        };

                        let terminal_action = matches!(
                            rule.actions.action,
                            ActionType::Move | ActionType::Delete | ActionType::Quarantine
                        );

                        if let Some(new_target) = &outcome.target_path {
                            current_path = new_target.clone();
                        }

                        outcomes.push(outcome);

                        // If the file was moved, deleted, or quarantined, don't run further rules
                        if terminal_action {
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Error evaluating rule '{}' on {}: {}", rule.name, current_path.display(), e);
                }
            }
        }

        outcomes
    }
}
