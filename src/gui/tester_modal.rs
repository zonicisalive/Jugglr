use std::fs;
use std::path::PathBuf;
use egui::{Color32, RichText, Ui};

use crate::config::schema::Config;
use crate::engine::conditions::ConditionEvaluator;
use crate::engine::variables::ContextVariables;
use crate::utils::mime::{compute_sha256, detect_mime};

#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub filename: String,
    pub matched_rule: Option<String>,
    pub planned_action: Option<String>,
    pub target_destination: Option<String>,
    pub threat_detected: Option<String>,
}

#[derive(Default)]
pub struct TesterState {
    pub target_folder: Option<PathBuf>,
    pub is_running: bool,
    pub results: Vec<SimulationResult>,
}

impl TesterState {
    pub fn run_simulation(&mut self, config: &Config) {
        self.results.clear();
        let folder = match &self.target_folder {
            Some(f) => f,
            None => return,
        };

        if !folder.exists() || !folder.is_dir() {
            return;
        }

        if let Ok(entries) = fs::read_dir(folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown").to_string();
                    let mut matched_rule_name = None;
                    let mut planned_action = None;
                    let mut target_dest = None;
                    let mut threat = None;

                    for rule in &config.rules {
                        if !rule.enabled {
                            continue;
                        }

                        if let Ok(eval) = ConditionEvaluator::evaluate(&rule.conditions, &path) {
                            if eval.matched {
                                matched_rule_name = Some(rule.name.clone());
                                planned_action = Some(format!("{:?}", rule.actions.action));

                                if eval.is_double_ext {
                                    threat = Some("Deceptive Double-Extension".to_string());
                                } else if eval.has_dangerous_perms {
                                    threat = Some("Dangerous +x Permission".to_string());
                                } else if let Some(ref sec) = eval.secret_found {
                                    threat = Some(format!("Leaked Secret: {}", sec));
                                }

                                let mime = eval.mime_type.or_else(|| detect_mime(&path).ok());
                                let sha256 = compute_sha256(&path).ok();
                                let ctx = ContextVariables::from_file(&path, mime.as_deref(), sha256.as_deref(), Some(&eval.captures));

                                if let Some(ref dest_tpl) = rule.actions.destination {
                                    target_dest = Some(ctx.interpolate(dest_tpl));
                                }

                                break; // First matching rule
                            }
                        }
                    }

                    self.results.push(SimulationResult {
                        filename,
                        matched_rule: matched_rule_name,
                        planned_action,
                        target_destination: target_dest,
                        threat_detected: threat,
                    });
                }
            }
        }
    }

    pub fn show(&mut self, ui: &mut Ui, config: &Config) {
        ui.heading("🧪 Dry-Run Rule Simulator");
        ui.label("Pick any folder on your system to test your active rules against existing files without modifying or moving them.");

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let folder_display = self.target_folder
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "No folder selected".to_string());

            ui.label("Target Folder:");
            ui.add(egui::Label::new(RichText::new(&folder_display).monospace()));

            if ui.button("📁 Pick Test Folder...").clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.target_folder = Some(folder);
                    self.run_simulation(config);
                }
            }

            if self.target_folder.is_some() && ui.button("🔄 Re-run Simulation").clicked() {
                self.run_simulation(config);
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        if self.results.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);
                ui.label(RichText::new("Select a folder to simulate rules.").color(Color32::GRAY));
            });
            return;
        }

        ui.label(format!("Simulated {} file(s):", self.results.len()));
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("tester_scroll_area")
            .show(ui, |ui| {
            for res in &self.results {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if let Some(ref rule) = res.matched_rule {
                            ui.label(RichText::new("🎯").size(16.0));
                            ui.label(RichText::new(&res.filename).strong());
                            ui.label("matches");
                            ui.label(RichText::new(rule).color(Color32::LIGHT_BLUE).strong());

                            if let Some(ref act) = res.planned_action {
                                ui.label(format!("→ Planned: {}", act));
                            }
                            if let Some(ref dest) = res.target_destination {
                                ui.label(RichText::new(format!("to {}", dest)).color(Color32::from_rgb(180, 180, 180)));
                            }
                            if let Some(ref threat) = res.threat_detected {
                                ui.label(RichText::new(format!("[🚨 {}]", threat)).color(Color32::LIGHT_RED));
                            }
                        } else {
                            ui.label(RichText::new("⚪").size(16.0));
                            ui.label(RichText::new(&res.filename).color(Color32::GRAY));
                            ui.label(RichText::new("(No rule matched)").color(Color32::DARK_GRAY));
                        }
                    });
                });
                ui.add_space(2.0);
            }
        });
    }
}
