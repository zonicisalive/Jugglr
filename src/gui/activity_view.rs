use egui::{Color32, RichText, Ui};
use chrono::Local;

#[derive(Debug, Clone)]
pub struct ActivityEntry {
    pub timestamp: String,
    pub filename: String,
    pub rule_name: String,
    pub action: String,
    pub target: Option<String>,
    pub status: String,
    pub is_security: bool,
}

pub struct ActivityView {
    pub entries: Vec<ActivityEntry>,
    pub filter_text: String,
}

impl ActivityView {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            filter_text: String::new(),
        }
    }

    pub fn add_entry(
        &mut self,
        filename: &str,
        rule_name: &str,
        action: &str,
        target: Option<&str>,
        status: &str,
        is_security: bool,
    ) {
        let entry = ActivityEntry {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            filename: filename.to_string(),
            rule_name: rule_name.to_string(),
            action: action.to_string(),
            target: target.map(|s| s.to_string()),
            status: status.to_string(),
            is_security,
        };
        self.entries.insert(0, entry); // newest first
        if self.entries.len() > 500 {
            self.entries.pop();
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        ui.heading("⚡ Live Activity & Event Log");
        ui.label("Real-time stream of file events processed by the inotify debouncer and rule engine.");

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("🔍 Search:");
            ui.text_edit_singleline(&mut self.filter_text);

            if ui.button("🗑️ Clear Log").clicked() {
                self.entries.clear();
            }

            ui.label(format!("Total entries: {}", self.entries.len()));
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        if self.entries.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(RichText::new("No activity recorded yet. Files dropped in watched folders will appear here in real-time.").color(Color32::GRAY));
            });
            return;
        }

        egui::ScrollArea::vertical()
            .id_salt("activity_scroll_area")
            .show(ui, |ui| {
            for entry in &self.entries {
                if !self.filter_text.is_empty() {
                    let search = self.filter_text.to_lowercase();
                    if !entry.filename.to_lowercase().contains(&search)
                        && !entry.rule_name.to_lowercase().contains(&search)
                        && !entry.action.to_lowercase().contains(&search)
                    {
                        continue;
                    }
                }

                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let icon = if entry.is_security {
                            "🚨"
                        } else if entry.status == "Success" {
                            "✅"
                        } else {
                            "ℹ️"
                        };

                        ui.label(RichText::new(icon).size(16.0));
                        ui.label(RichText::new(&entry.timestamp).monospace().color(Color32::LIGHT_BLUE));
                        ui.label(RichText::new(&entry.filename).strong());
                        ui.label("→");
                        ui.label(RichText::new(&entry.rule_name).italics().color(Color32::from_rgb(200, 200, 100)));
                        ui.label(format!("[{}]", entry.action));

                        if let Some(ref tgt) = entry.target {
                            ui.label(RichText::new(format!("to {}", tgt)).color(Color32::GRAY));
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let status_color = if entry.status == "Success" {
                                Color32::LIGHT_GREEN
                            } else if entry.is_security {
                                Color32::LIGHT_RED
                            } else {
                                Color32::LIGHT_YELLOW
                            };
                            ui.label(RichText::new(&entry.status).color(status_color));
                        });
                    });
                });
                ui.add_space(2.0);
            }
        });
    }
}
