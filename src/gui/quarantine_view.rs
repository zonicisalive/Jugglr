use std::fs;
use std::path::{Path, PathBuf};
use egui::{Color32, RichText, Ui};
use serde::{Deserialize, Serialize};
use crate::actions::resolve_conflict;
use crate::config::schema::ConflictResolution;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub timestamp: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub sha256: String,
    pub reason: String,
}

pub struct QuarantineView {
    pub records: Vec<QuarantineRecord>,
    pub selected_record: Option<usize>,
    pub status_msg: Option<String>,
}

impl QuarantineView {
    pub fn new() -> Self {
        let mut view = Self {
            records: Vec::new(),
            selected_record: None,
            status_msg: None,
        };
        view.reload("~/Downloads/quarantine");
        view
    }

    pub fn reload(&mut self, default_dir: &str) {
        self.records.clear();
        let target_dirs = [
            crate::config::expand_path(default_dir),
            crate::config::expand_path("~/Downloads/quarantine"),
            crate::config::expand_path("~/.local/share/jugglr/quarantine"),
        ];

        for q_dir in &target_dirs {
            let audit_log = q_dir.join("quarantine_audit.jsonl");
            if audit_log.exists() {
                if let Ok(content) = fs::read_to_string(&audit_log) {
                    for line in content.lines() {
                        if let Ok(rec) = serde_json::from_str::<QuarantineRecord>(line) {
                            // The audit log is append-only, so it still lists files that have
                            // since been restored or deleted. Showing those as quarantined
                            // makes the vault's Restore and Delete buttons do nothing.
                            if !Path::new(&rec.quarantined_path).exists() {
                                continue;
                            }
                            if !self.records.iter().any(|r| r.quarantined_path == rec.quarantined_path) {
                                self.records.push(rec);
                            }
                        }
                    }
                }
            }
        }
        self.records.reverse(); // Most recent first
    }

    pub fn show(&mut self, ui: &mut Ui, default_dir: &str) {
        ui.heading("Security Quarantine Vault");
        ui.label("Files identified as deceptive (e.g. .pdf.sh) or malicious are safely isolated with 0o600 permissions.");

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button("Refresh Vault").clicked() {
                self.reload(default_dir);
                self.status_msg = Some("Vault refreshed".to_string());
            }

            if ui.button("Open Quarantine Folder").clicked() {
                let q_dir = crate::config::expand_path(default_dir);
                let _ = fs::create_dir_all(&q_dir);
                let _ = std::process::Command::new("xdg-open").arg(&q_dir).spawn();
            }

            if let Some(ref msg) = self.status_msg {
                ui.label(RichText::new(msg).color(Color32::from_rgb(100, 200, 100)));
            }
        });

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        if self.records.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(RichText::new("No quarantined files. Your system is clean!").size(16.0).color(Color32::LIGHT_GREEN));
            });
            return;
        }

        egui::ScrollArea::vertical()
            .id_salt("quarantine_scroll_area")
            .show(ui, |ui| {
            let mut record_to_restore = None;
            let mut record_to_delete = None;

            for (idx, record) in self.records.iter().enumerate() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("[QUARANTINED]").strong().color(Color32::LIGHT_RED));
                        ui.vertical(|ui| {
                            let q_path = Path::new(&record.quarantined_path);
                            let fname = q_path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown");

                            ui.horizontal(|ui| {
                                ui.label(RichText::new(fname).strong().size(14.0));
                                ui.label(RichText::new(format!("[{}]", record.reason)).color(Color32::LIGHT_RED));
                            });

                            ui.label(format!("Original Location: {}", record.original_path));
                            let sha_short: String = record.sha256.chars().take(16).collect();
                            ui.label(format!("SHA-256: {}  |  Date: {}", sha_short, record.timestamp));
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Delete Permanently").clicked() {
                                record_to_delete = Some(idx);
                            }
                            if ui.button("Restore File").clicked() {
                                record_to_restore = Some(idx);
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }

            if let Some(idx) = record_to_restore {
                let rec = &self.records[idx];
                let src = PathBuf::from(&rec.quarantined_path);
                let original = PathBuf::from(&rec.original_path);
                if src.exists() {
                    if let Some(parent) = original.parent() {
                        let _ = fs::create_dir_all(parent);
                    }

                    // Something else may occupy the original path by now; restoring on top of
                    // it would destroy the user's current file without warning.
                    match resolve_conflict(&original, ConflictResolution::RenameWithCounter) {
                        Some(dest) => {
                            if fs::rename(&src, &dest).is_ok() || fs::copy(&src, &dest).is_ok() {
                                let _ = fs::remove_file(&src);
                                self.status_msg = Some(format!("Restored to {}", dest.display()));
                            } else {
                                self.status_msg = Some(format!("Could not restore to {}", dest.display()));
                            }
                        }
                        None => {
                            self.status_msg = Some("Restore skipped: destination is occupied".to_string());
                        }
                    }
                }
                self.reload(default_dir);
            }

            if let Some(idx) = record_to_delete {
                let rec = &self.records[idx];
                let src = PathBuf::from(&rec.quarantined_path);
                if src.exists() {
                    let _ = fs::remove_file(&src);
                }
                self.status_msg = Some("Quarantined file deleted permanently".to_string());
                self.reload(default_dir);
            }
        });
    }
}
