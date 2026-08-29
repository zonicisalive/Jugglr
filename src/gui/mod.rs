pub mod activity_view;
pub mod quarantine_view;
pub mod rules_view;
pub mod tester_modal;

use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use egui::{Color32, RichText};
use crate::config::schema::Config;
use crate::config::load_config;
use activity_view::ActivityView;
use quarantine_view::QuarantineView;
use rules_view::RulesView;
use tester_modal::TesterState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Rules,
    Activity,
    Quarantine,
    Tester,
}

pub struct JugglrApp {
    pub config: Config,
    pub config_path: PathBuf,
    pub active_tab: Tab,
    pub rules_view: RulesView,
    pub activity_view: ActivityView,
    pub quarantine_view: QuarantineView,
    pub tester_state: TesterState,
    pub status_message: Option<(String, Instant)>,
    pub is_watching: bool,
}

impl JugglrApp {
    pub fn new(cc: &eframe::CreationContext<'_>, config_path: PathBuf) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let config = match load_config(&config_path) {
            Ok(cfg) => cfg,
            Err(_) => Config::default(),
        };

        Self {
            config,
            config_path,
            active_tab: Tab::Rules,
            rules_view: RulesView::new(),
            activity_view: ActivityView::new(),
            quarantine_view: QuarantineView::new(),
            tester_state: TesterState::default(),
            status_message: Some(("Welcome to Jugglr Desktop GUI".to_string(), Instant::now())),
            is_watching: true,
        }
    }

    pub fn save_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = self.config_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let toml_str = toml::to_string_pretty(&self.config)?;
        fs::write(&self.config_path, toml_str)?;

        // Send SIGHUP to background daemon if running to live-reload rules
        let _ = std::process::Command::new("pkill")
            .arg("-HUP")
            .arg("-f")
            .arg("jugglr --daemon")
            .status();

        self.status_message = Some((
            format!("Saved rules to {} and reloaded daemon", self.config_path.display()),
            Instant::now(),
        ));

        Ok(())
    }
}

impl eframe::App for JugglrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("header_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Jugglr").size(20.0).strong().color(Color32::from_rgb(0, 200, 255)));
                ui.label(RichText::new("Linux File Automation & Defense").italics().color(Color32::GRAY));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Save Rules & Apply").clicked() {
                        if let Err(e) = self.save_config() {
                            self.status_message = Some((format!("Save failed: {}", e), Instant::now()));
                        }
                    }

                    if ui.button("Test on Folder").clicked() {
                        self.active_tab = Tab::Tester;
                    }

                    let watch_badge = if self.is_watching {
                        RichText::new("[Active]").color(Color32::LIGHT_GREEN)
                    } else {
                        RichText::new("[Paused]").color(Color32::LIGHT_YELLOW)
                    };

                    if ui.button(watch_badge).on_hover_text("Toggle background monitoring").clicked() {
                        self.is_watching = !self.is_watching;
                    }
                });
            });

            ui.add_space(4.0);

            // Tab bar & API key
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Rules, "Rules Editor");
                ui.selectable_value(&mut self.active_tab, Tab::Activity, format!("Live Activity ({})", self.activity_view.entries.len()));
                ui.selectable_value(&mut self.active_tab, Tab::Quarantine, format!("Quarantine Vault ({})", self.quarantine_view.records.len()));
                ui.selectable_value(&mut self.active_tab, Tab::Tester, "Dry-Run Simulator");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let mut vt_key = self.config.global.virustotal_api_key.clone().unwrap_or_default();
                    ui.label("VirusTotal API Key:");
                    if ui.add(egui::TextEdit::singleline(&mut vt_key).password(true).hint_text("Paste VT Key...")).changed() {
                        self.config.global.virustotal_api_key = if vt_key.trim().is_empty() { None } else { Some(vt_key.trim().to_string()) };
                    }
                });
            });

            ui.add_space(4.0);

            // Status message toast
            if let Some((ref msg, timestamp)) = self.status_message {
                if timestamp.elapsed().as_secs() < 6 {
                    ui.label(RichText::new(msg).color(Color32::LIGHT_BLUE));
                }
            }

            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Rules => {
                    self.rules_view.show(ui, &mut self.config.rules);
                }
                Tab::Activity => {
                    self.activity_view.show(ui);
                }
                Tab::Quarantine => {
                    self.quarantine_view.show(ui);
                }
                Tab::Tester => {
                    self.tester_state.show(ui, &self.config);
                }
            }
        });

        // Request repaint only if simulator or folder picker is running, or toast is active, otherwise sleep
        if self.tester_state.is_running || self.rules_view.has_active_picker() || self.tester_state.has_active_picker() {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        } else if self.status_message.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }
}

/// Launch the desktop GUI application.
pub fn run_gui(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("Jugglr - Linux File Automation & Defense Daemon"),
        ..Default::default()
    };

    eframe::run_native(
        "Jugglr",
        options,
        Box::new(|cc| Ok(Box::new(JugglrApp::new(cc, config_path)))),
    ).map_err(|e| format!("GUI launch failed: {}", e))?;

    Ok(())
}
