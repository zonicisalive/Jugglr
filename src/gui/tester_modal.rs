use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use egui::{Color32, RichText, Ui};

use crate::config::schema::Config;
use crate::engine::conditions::ConditionEvaluator;
use crate::engine::variables::ContextVariables;
use crate::utils::mime::detect_mime;

#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub filename: String,
    pub matched_rule: Option<String>,
    pub planned_action: Option<String>,
    pub target_destination: Option<String>,
    pub threat_detected: Option<String>,
}

pub enum SimMessage {
    Item(SimulationResult),
    Finished,
}

pub struct TesterState {
    pub target_folder: Option<PathBuf>,
    pub is_running: bool,
    pub results: Vec<SimulationResult>,
    receiver: Option<Receiver<SimMessage>>,
    picker_receiver: Option<Receiver<Option<PathBuf>>>,
}

impl TesterState {
    pub fn has_active_picker(&self) -> bool {
        self.picker_receiver.is_some()
    }
}

impl Default for TesterState {
    fn default() -> Self {
        Self {
            target_folder: None,
            is_running: false,
            results: Vec::new(),
            receiver: None,
            picker_receiver: None,
        }
    }
}

impl TesterState {
    pub fn start_simulation(&mut self, folder: PathBuf, config: Config) {
        self.results.clear();
        self.is_running = true;
        let (tx, rx) = channel::<SimMessage>();
        self.receiver = Some(rx);

        thread::spawn(move || {
            if folder.exists() && folder.is_dir() {
                if let Ok(entries) = fs::read_dir(&folder) {
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

                                if let Ok(eval) = ConditionEvaluator::evaluate_with_vt(
                                    &rule.conditions,
                                    &path,
                                    config.global.virustotal_api_key.as_deref(),
                                ) {
                                    if eval.matched {
                                        matched_rule_name = Some(rule.name.clone());
                                        planned_action = Some(format!("{:?}", rule.actions.action));

                                        if let Some(ref mal) = eval.malware_found {
                                            threat = Some(format!("Malware/Exploit: {}", mal));
                                        } else if eval.is_double_ext {
                                            threat = Some("Deceptive Double-Extension".to_string());
                                        } else if eval.has_dangerous_perms {
                                            threat = Some("Dangerous +x Permission".to_string());
                                        } else if let Some(ref sec) = eval.secret_found {
                                            threat = Some(format!("Leaked Secret: {}", sec));
                                        } else if eval.is_suspicious_desktop {
                                            threat = Some("Phishing Launcher / Service".to_string());
                                        } else if eval.is_mime_spoofed {
                                            threat = Some("MIME Spoofing (Binary disguised as document/image)".to_string());
                                        }

                                        let mime = eval.mime_type.or_else(|| detect_mime(&path).ok());
                                        let ctx = ContextVariables::from_file(&path, mime.as_deref(), None, Some(&eval.captures));

                                        if let Some(ref dest_tpl) = rule.actions.destination {
                                            target_dest = Some(ctx.interpolate(dest_tpl));
                                        }

                                        break;
                                    }
                                }
                            }

                            let _ = tx.send(SimMessage::Item(SimulationResult {
                                filename,
                                matched_rule: matched_rule_name,
                                planned_action,
                                target_destination: target_dest,
                                threat_detected: threat,
                            }));
                        }
                    }
                }
            }
            let _ = tx.send(SimMessage::Finished);
        });
    }

    pub fn update(&mut self) {
        // Check for folder picker response
        if let Some(ref rx) = self.picker_receiver {
            if let Ok(folder_opt) = rx.try_recv() {
                self.target_folder = folder_opt;
                self.picker_receiver = None;
            }
        }

        // Check for simulation results
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    SimMessage::Item(res) => {
                        self.results.push(res);
                    }
                    SimMessage::Finished => {
                        self.is_running = false;
                        self.receiver = None;
                        break;
                    }
                }
            }
        }
    }

    pub fn show(&mut self, ui: &mut Ui, config: &Config) {
        self.update();

        // If a new folder was selected from async picker and simulation is not running, trigger it
        if self.target_folder.is_some() && self.receiver.is_none() && self.results.is_empty() && !self.is_running {
            if let Some(folder) = self.target_folder.clone() {
                self.start_simulation(folder, config.clone());
            }
        }

        ui.heading("Dry-Run Rule Simulator");
        ui.label("Pick any folder on your system to test your active rules against existing files without modifying or moving them.");

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let folder_display = self.target_folder
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "No folder selected".to_string());

            ui.label("Target Folder:");
            ui.add(egui::Label::new(RichText::new(&folder_display).monospace()));

            if ui.button("Browse Test Folder...").clicked() && self.picker_receiver.is_none() {
                let (tx, rx) = channel();
                self.picker_receiver = Some(rx);
                thread::spawn(move || {
                    let picked = rfd::FileDialog::new().pick_folder();
                    let _ = tx.send(picked);
                });
            }

            if let Some(ref folder) = self.target_folder {
                if !self.is_running && ui.button("Re-run Simulation").clicked() {
                    let folder_clone = folder.clone();
                    self.start_simulation(folder_clone, config.clone());
                }
            }

            if self.is_running {
                ui.spinner();
                ui.label(RichText::new("Simulating rules in background...").color(Color32::LIGHT_BLUE));
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        if self.results.is_empty() && !self.is_running {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);
                ui.label(RichText::new("Select a folder to simulate rules.").color(Color32::GRAY));
            });
            return;
        }

        let matched_count = self.results.iter().filter(|r| r.matched_rule.is_some()).count();
        ui.horizontal(|ui| {
            ui.label(format!("Simulated {} file(s) ({} matched active rules):", self.results.len(), matched_count));

            if matched_count > 0 && !self.is_running {
                if let Some(ref folder) = self.target_folder {
                    if ui.button(RichText::new("⚡ Apply & Organize Matched Files Now").color(Color32::from_rgb(50, 220, 100)).strong()).clicked() {
                        let folder_clone = folder.clone();
                        let config_clone = config.clone();
                        let f_recheck = folder.clone();
                        let cfg_recheck = config.clone();
                        std::thread::spawn(move || {
                            let engine = crate::engine::RuleEngine::new(config_clone);
                            if let Ok(entries) = fs::read_dir(&folder_clone) {
                                for entry in entries.flatten() {
                                    let p = entry.path();
                                    if p.is_file() {
                                        engine.process_file(&p);
                                    }
                                }
                            }
                        });
                        self.results.clear();
                        self.start_simulation(f_recheck, cfg_recheck);
                    }
                }
            }
        });
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("tester_scroll_area")
            .show(ui, |ui| {
            for res in &self.results {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if let Some(ref rule) = res.matched_rule {
                            ui.label(RichText::new("[MATCH]").strong().color(Color32::LIGHT_GREEN));
                            ui.label(RichText::new(&res.filename).strong());
                            ui.label("matches");
                            ui.label(RichText::new(rule).color(Color32::LIGHT_BLUE).strong());

                            if let Some(ref act) = res.planned_action {
                                ui.label(format!("-> Planned: {}", act));
                            }
                            if let Some(ref dest) = res.target_destination {
                                ui.label(RichText::new(format!("to {}", dest)).color(Color32::from_rgb(180, 180, 180)));
                            }
                            if let Some(ref threat) = res.threat_detected {
                                ui.label(RichText::new(format!("[THREAT: {}]", threat)).color(Color32::LIGHT_RED));
                            }
                        } else {
                            ui.label(RichText::new("[--]").color(Color32::DARK_GRAY));
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
