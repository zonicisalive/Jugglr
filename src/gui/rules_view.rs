use std::path::PathBuf;
use std::sync::mpsc;
use egui::{Color32, RichText, Ui};
use crate::config::schema::{ActionConfig, ActionType, ConditionGroup, ConflictResolution, MatchMode, RuleConfig};

pub struct RulesView {
    pub selected_rule_index: Option<usize>,
    pub filter_search: String,
    picker_receiver: Option<mpsc::Receiver<(usize, bool, PathBuf)>>,
}

impl RulesView {
    pub fn new() -> Self {
        Self {
            selected_rule_index: Some(0),
            filter_search: String::new(),
            picker_receiver: None,
        }
    }

    pub fn has_active_picker(&self) -> bool {
        self.picker_receiver.is_some()
    }

    pub fn show(&mut self, ui: &mut Ui, rules: &mut Vec<RuleConfig>) {
        // Poll background folder picker results without blocking UI
        if let Some(ref rx) = self.picker_receiver {
            if let Ok((idx, is_watch_dir, folder)) = rx.try_recv() {
                if let Some(rule) = rules.get_mut(idx) {
                    if is_watch_dir {
                        rule.watch_dir = folder.to_string_lossy().to_string();
                    } else {
                        rule.actions.destination = Some(format!("{}/", folder.to_string_lossy()));
                    }
                }
            }
        }

        if rules.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(RichText::new("No rules configured.").size(18.0));
                if ui.button("+ Create Blank Rule").clicked() {
                    rules.push(default_new_rule());
                    self.selected_rule_index = Some(0);
                }
            });
            return;
        }

        if self.selected_rule_index.map_or(true, |idx| idx >= rules.len()) {
            self.selected_rule_index = Some(0);
        }

        egui::SidePanel::left("rules_sidebar_panel")
            .resizable(true)
            .default_width(340.0)
            .min_width(260.0)
            .max_width(550.0)
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Rules");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("+ Add Rule").clicked() {
                            rules.push(default_new_rule());
                            self.selected_rule_index = Some(rules.len() - 1);
                        }
                    });
                });

                // PRESET RECIPES DROPDOWN (Safe: Loaded disabled by default)
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("preset_recipes_combo")
                        .selected_text("+ Preset Recipes...")
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(false, "Clean Old Downloads (>14 days to Trash)").clicked() {
                                rules.push(preset_clean_old_downloads());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                            if ui.selectable_label(false, "Auto-Sort Photos by EXIF Date & Camera").clicked() {
                                rules.push(preset_photo_sorter());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                            if ui.selectable_label(false, "Auto-Tag & Organize Music by Artist/Album").clicked() {
                                rules.push(preset_music_sorter());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                            if ui.selectable_label(false, "Auto-Unpack Archives (.zip, .tar.gz)").clicked() {
                                rules.push(preset_auto_unpack());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                            if ui.selectable_label(false, "Quarantine Phishing .desktop Files").clicked() {
                                rules.push(preset_phishing_desktop());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                            if ui.selectable_label(false, "Quarantine Malware & Web Shells (Signatures + VirusTotal)").clicked() {
                                rules.push(preset_malware_quarantine());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                            if ui.selectable_label(false, "Quarantine Invisible Traps & Bombs (ZipBombs, ForkBombs, Polyglots)").clicked() {
                                rules.push(preset_invisible_traps_quarantine());
                                self.selected_rule_index = Some(rules.len() - 1);
                            }
                        });
                });

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("Search:");
                    ui.text_edit_singleline(&mut self.filter_search);
                });

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);

                let mut to_delete = None;
                let mut to_duplicate = None;
                let mut move_up = None;
                let mut move_down = None;

                let total_rules = rules.len();
                egui::ScrollArea::vertical()
                    .id_salt("rules_sidebar_scroll")
                    .show(ui, |ui| {
                        for (idx, rule) in rules.iter_mut().enumerate() {
                            if !self.filter_search.is_empty() {
                                let search = self.filter_search.to_lowercase();
                                if !rule.name.to_lowercase().contains(&search)
                                    && !rule.watch_dir.to_lowercase().contains(&search)
                                {
                                    continue;
                                }
                            }

                            let is_selected = self.selected_rule_index == Some(idx);

                            ui.push_id(idx, |ui| {
                                egui::Frame::group(ui.style())
                                    .stroke(if is_selected {
                                        egui::Stroke::new(2.0, Color32::LIGHT_BLUE)
                                    } else {
                                        egui::Stroke::new(1.0, Color32::DARK_GRAY)
                                    })
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.checkbox(&mut rule.enabled, "");

                                            let title = if rule.name.is_empty() { "Untitled Rule" } else { &rule.name };
                                            if ui.selectable_label(is_selected, RichText::new(title).strong()).clicked() {
                                                self.selected_rule_index = Some(idx);
                                            }
                                        });

                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("Watch: {}", &rule.watch_dir)).size(11.0).color(Color32::GRAY));

                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                if ui.small_button("Del").on_hover_text("Delete rule").clicked() {
                                                    to_delete = Some(idx);
                                                }
                                                if ui.small_button("Copy").on_hover_text("Duplicate rule").clicked() {
                                                    to_duplicate = Some(idx);
                                                }
                                                if idx + 1 < total_rules && ui.small_button("v").on_hover_text("Move down").clicked() {
                                                    move_down = Some(idx);
                                                }
                                                if idx > 0 && ui.small_button("^").on_hover_text("Move up").clicked() {
                                                    move_up = Some(idx);
                                                }
                                            });
                                        });
                                    });
                            });
                            ui.add_space(2.0);
                        }
                    });

                if let Some(idx) = to_delete {
                    rules.remove(idx);
                    if rules.is_empty() {
                        self.selected_rule_index = None;
                    } else if self.selected_rule_index.unwrap_or(0) >= rules.len() {
                        self.selected_rule_index = Some(rules.len() - 1);
                    }
                }

                if let Some(idx) = to_duplicate {
                    let mut dup = rules[idx].clone();
                    dup.name = format!("{} (Copy)", dup.name);
                    rules.insert(idx + 1, dup);
                    self.selected_rule_index = Some(idx + 1);
                }

                if let Some(idx) = move_up {
                    rules.swap(idx, idx - 1);
                    self.selected_rule_index = Some(idx - 1);
                }

                if let Some(idx) = move_down {
                    rules.swap(idx, idx + 1);
                    self.selected_rule_index = Some(idx + 1);
                }
            });

        // RIGHT PANEL: Visual Rule Editor (File Juggler style)
        egui::CentralPanel::default().show_inside(ui, |ui| {
            if let Some(selected_idx) = self.selected_rule_index {
                if let Some(rule) = rules.get_mut(selected_idx) {
                    egui::ScrollArea::vertical()
                        .id_salt("rule_editor_scroll")
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.heading("Rule Settings");
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.checkbox(&mut rule.enabled, "Enable this rule");
                                });
                            });

                            ui.horizontal(|ui| {
                                ui.label("Rule Name:");
                                ui.text_edit_singleline(&mut rule.name);
                            });

                            ui.horizontal(|ui| {
                                ui.label("Watch Folder:");
                                ui.text_edit_singleline(&mut rule.watch_dir);
                                if ui.button("Browse...").clicked() {
                                    let (tx, rx) = mpsc::channel();
                                    self.picker_receiver = Some(rx);
                                    let idx = self.selected_rule_index.unwrap_or(0);
                                    std::thread::spawn(move || {
                                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                            let _ = tx.send((idx, true, folder));
                                        }
                                    });
                                }
                            });

                            ui.add_space(8.0);

                            // IF CONDITIONS CARD
                            show_conditions_card(ui, &mut rule.conditions);

                            ui.add_space(8.0);

                            // THEN ACTIONS CARD
                            show_actions_card(ui, &mut rule.actions, selected_idx, &mut self.picker_receiver);
                        });
                }
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(RichText::new("Select a rule from the left sidebar to edit.").color(Color32::GRAY));
                });
            }
        });
    }
}

fn default_new_rule() -> RuleConfig {
    RuleConfig {
        name: "New Organization Rule".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false, // Safe default
        conditions: ConditionGroup {
            match_mode: MatchMode::All,
            extensions: Some(vec!["pdf".to_string()]),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Move,
            destination: Some("~/Documents/Sorted/{year}/".to_string()),
            conflict_resolution: ConflictResolution::RenameWithCounter,
            notify: true,
            ..Default::default()
        },
    }
}

// Preset Recipes (All created as enabled: false by default for safety!)
fn preset_clean_old_downloads() -> RuleConfig {
    RuleConfig {
        name: "Clean Old Downloads (>14 days)".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false,
        conditions: ConditionGroup {
            match_mode: MatchMode::All,
            older_than_days: Some(14),
            extensions: Some(vec!["iso".to_string(), "deb".to_string(), "rpm".to_string(), "tar.gz".to_string(), "zip".to_string()]),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Trash,
            notify: true,
            notify_message: Some("Moved old download {filename} to trash".to_string()),
            ..Default::default()
        },
    }
}

fn preset_photo_sorter() -> RuleConfig {
    RuleConfig {
        name: "Auto-Sort Photos by EXIF Date & Camera".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false,
        conditions: ConditionGroup {
            match_mode: MatchMode::Any,
            extensions: Some(vec!["jpg".to_string(), "jpeg".to_string(), "png".to_string(), "raw".to_string(), "dng".to_string()]),
            has_exif: Some(true),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Move,
            destination: Some("~/Pictures/Photos/{exif_year}/{camera_model}/".to_string()),
            conflict_resolution: ConflictResolution::RenameWithCounter,
            notify: true,
            ..Default::default()
        },
    }
}

fn preset_music_sorter() -> RuleConfig {
    RuleConfig {
        name: "Auto-Tag & Organize Music by Artist/Album".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false,
        conditions: ConditionGroup {
            match_mode: MatchMode::Any,
            extensions: Some(vec!["mp3".to_string(), "flac".to_string(), "m4a".to_string(), "ogg".to_string()]),
            has_audio_tags: Some(true),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Move,
            destination: Some("~/Music/{music_artist}/{music_album}/{music_track} - {music_title}.{ext}".to_string()),
            conflict_resolution: ConflictResolution::RenameWithCounter,
            notify: true,
            ..Default::default()
        },
    }
}

fn preset_auto_unpack() -> RuleConfig {
    RuleConfig {
        name: "Auto-Unpack Archives (.zip, .tar.gz)".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false,
        conditions: ConditionGroup {
            match_mode: MatchMode::Any,
            extensions: Some(vec!["zip".to_string(), "tar.gz".to_string(), "tgz".to_string(), "tar".to_string()]),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Extract,
            destination: Some("~/Downloads/{stem}/".to_string()),
            delete_archive_after_extract: true,
            notify: true,
            notify_message: Some("Extracted {filename} to {stem}/".to_string()),
            ..Default::default()
        },
    }
}

fn preset_phishing_desktop() -> RuleConfig {
    RuleConfig {
        name: "Quarantine Phishing .desktop Files".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false,
        conditions: ConditionGroup {
            match_mode: MatchMode::All,
            suspicious_desktop_file: Some(true),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Quarantine,
            destination: Some("~/Downloads/quarantine/".to_string()),
            strip_executable: true,
            notify: true,
            alert_urgency: Some("critical".to_string()),
            notify_message: Some("Quarantined suspicious .desktop phishing file: {filename}".to_string()),
            ..Default::default()
        },
    }
}

fn preset_malware_quarantine() -> RuleConfig {
    RuleConfig {
        name: "Quarantine Malware & Web Shells (Signatures + VirusTotal)".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false, // Safe default
        conditions: ConditionGroup {
            match_mode: MatchMode::Any,
            malware_signature: Some(true),
            virustotal_min_positives: Some(3),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Quarantine,
            destination: Some("~/Downloads/quarantine/".to_string()),
            strip_executable: true,
            notify: true,
            alert_urgency: Some("critical".to_string()),
            notify_message: Some("Quarantined malware payload: {filename}".to_string()),
            ..Default::default()
        },
    }
}

fn preset_invisible_traps_quarantine() -> RuleConfig {
    RuleConfig {
        name: "Quarantine Invisible Traps & Bombs (ZipBombs, ForkBombs, Polyglots)".to_string(),
        watch_dir: "~/Downloads".to_string(),
        enabled: false, // Safe default
        conditions: ConditionGroup {
            match_mode: MatchMode::Any,
            forkbomb_detector: Some(true),
            zipbomb_detector: Some(true),
            invisible_unicode_detector: Some(true),
            polyglot_payload_detector: Some(true),
            homoglyph_detector: Some(true),
            ..Default::default()
        },
        actions: ActionConfig {
            action: ActionType::Quarantine,
            destination: Some("~/Downloads/quarantine/".to_string()),
            strip_executable: true,
            notify: true,
            alert_urgency: Some("critical".to_string()),
            notify_message: Some("Quarantined invisible threat or bomb: {filename}".to_string()),
            ..Default::default()
        },
    }
}

fn show_conditions_card(ui: &mut Ui, conditions: &mut ConditionGroup) {
    egui::Frame::group(ui.style())
        .fill(ui.visuals().window_fill())
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("IF (Conditions)").heading().color(Color32::from_rgb(255, 170, 50)));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_id_salt("match_mode_combo")
                        .selected_text(match conditions.match_mode {
                            MatchMode::All => "Match ALL conditions (AND)",
                            MatchMode::Any => "Match ANY condition (OR)",
                            MatchMode::None => "Match NONE (NOT)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut conditions.match_mode, MatchMode::All, "Match ALL conditions (AND)");
                            ui.selectable_value(&mut conditions.match_mode, MatchMode::Any, "Match ANY condition (OR)");
                            ui.selectable_value(&mut conditions.match_mode, MatchMode::None, "Match NONE (NOT)");
                        });
                    ui.label("Logic:");
                });
            });

            ui.separator();

            // 1. File Extensions
            ui.horizontal(|ui| {
                let mut ext_str = conditions.extensions.as_ref().map(|exts| exts.join(", ")).unwrap_or_default();
                let mut has_ext = conditions.extensions.is_some();
                if ui.checkbox(&mut has_ext, "File Extension(s):").changed() {
                    conditions.extensions = if has_ext { Some(vec!["pdf".to_string()]) } else { None };
                }
                if has_ext {
                    if ui.text_edit_singleline(&mut ext_str).changed() {
                        let parsed: Vec<String> = ext_str.split(',')
                            .map(|s| s.trim().trim_start_matches('.').to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        conditions.extensions = Some(parsed);
                    }
                    ui.label(RichText::new("(comma-separated, e.g. pdf, docx, png)").size(11.0).color(Color32::GRAY));
                }
            });

            // 2. Filename Match (Regex / Glob)
            ui.horizontal(|ui| {
                let mut has_glob = conditions.name_glob.is_some();
                if ui.checkbox(&mut has_glob, "Filename Glob:").changed() {
                    conditions.name_glob = if has_glob { Some("*.pdf".to_string()) } else { None };
                }
                if let Some(ref mut glob_pattern) = conditions.name_glob {
                    ui.text_edit_singleline(glob_pattern);
                    ui.label(RichText::new("e.g. invoice_*.pdf").size(11.0).color(Color32::GRAY));
                }
            });

            ui.horizontal(|ui| {
                let mut has_re = conditions.name_regex.is_some();
                if ui.checkbox(&mut has_re, "Filename Regex:").changed() {
                    conditions.name_regex = if has_re { Some(r"^Invoice_(?P<id>\d+)".to_string()) } else { None };
                }
                if let Some(ref mut re_pattern) = conditions.name_regex {
                    ui.text_edit_singleline(re_pattern);
                    ui.label(RichText::new("Supports named captures").size(11.0).color(Color32::GRAY));
                }
            });

            // 3. File Age (Hazel style)
            ui.horizontal(|ui| {
                let mut has_older = conditions.older_than_days.is_some();
                if ui.checkbox(&mut has_older, "Older Than (Days):").changed() {
                    conditions.older_than_days = if has_older { Some(14) } else { None };
                }
                if let Some(ref mut days) = conditions.older_than_days {
                    ui.add(egui::DragValue::new(days).speed(1));
                }

                let mut has_newer = conditions.newer_than_days.is_some();
                if ui.checkbox(&mut has_newer, "Newer Than (Days):").changed() {
                    conditions.newer_than_days = if has_newer { Some(7) } else { None };
                }
                if let Some(ref mut days) = conditions.newer_than_days {
                    ui.add(egui::DragValue::new(days).speed(1));
                }
            });

            // 4. File Size
            ui.horizontal(|ui| {
                let mut has_min_size = conditions.min_size_bytes.is_some();
                if ui.checkbox(&mut has_min_size, "Min Size (Bytes):").changed() {
                    conditions.min_size_bytes = if has_min_size { Some(1024) } else { None };
                }
                if let Some(ref mut min_sz) = conditions.min_size_bytes {
                    ui.add(egui::DragValue::new(min_sz).speed(1024));
                }

                let mut has_max_size = conditions.max_size_bytes.is_some();
                if ui.checkbox(&mut has_max_size, "Max Size (Bytes):").changed() {
                    conditions.max_size_bytes = if has_max_size { Some(10 * 1024 * 1024) } else { None };
                }
                if let Some(ref mut max_sz) = conditions.max_size_bytes {
                    ui.add(egui::DragValue::new(max_sz).speed(1024 * 1024));
                }
            });

            // 5. File Content Keywords & Regex
            ui.horizontal(|ui| {
                let mut kw_str = conditions.content_contains.as_ref().map(|kws| kws.join(", ")).unwrap_or_default();
                let mut has_kw = conditions.content_contains.is_some();
                if ui.checkbox(&mut has_kw, "Content Contains:").changed() {
                    conditions.content_contains = if has_kw { Some(vec!["Invoice".to_string(), "Total".to_string()]) } else { None };
                }
                if has_kw {
                    if ui.text_edit_singleline(&mut kw_str).changed() {
                        let parsed: Vec<String> = kw_str.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        conditions.content_contains = Some(parsed);
                    }
                    ui.label(RichText::new("(comma-separated keywords)").size(11.0).color(Color32::GRAY));
                }
            });

            ui.horizontal(|ui| {
                let mut has_content_re = conditions.content_regex.is_some();
                if ui.checkbox(&mut has_content_re, "Content Regex:").changed() {
                    conditions.content_regex = if has_content_re { Some(r"Total Due:\s*\$([0-9.]+)".to_string()) } else { None };
                }
                if let Some(ref mut re_pat) = conditions.content_regex {
                    ui.text_edit_singleline(re_pat);
                }
            });

            // 6. MIME Types
            ui.horizontal(|ui| {
                let mut mime_str = conditions.mime_types.as_ref().map(|m| m.join(", ")).unwrap_or_default();
                let mut has_mime = conditions.mime_types.is_some();
                if ui.checkbox(&mut has_mime, "MIME Type(s):").changed() {
                    conditions.mime_types = if has_mime { Some(vec!["application/pdf".to_string()]) } else { None };
                }
                if has_mime {
                    if ui.text_edit_singleline(&mut mime_str).changed() {
                        let parsed: Vec<String> = mime_str.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        conditions.mime_types = Some(parsed);
                    }
                    ui.label(RichText::new("e.g. application/pdf, image/*").size(11.0).color(Color32::GRAY));
                }
            });

            // 7. Metadata Extractors (EXIF & Audio)
            ui.horizontal(|ui| {
                let mut has_exif_val = conditions.has_exif.unwrap_or(false);
                if ui.checkbox(&mut has_exif_val, "Require Photo EXIF Data").changed() {
                    conditions.has_exif = if has_exif_val { Some(true) } else { None };
                }

                let mut has_audio_val = conditions.has_audio_tags.unwrap_or(false);
                if ui.checkbox(&mut has_audio_val, "Require ID3 Audio Tags").changed() {
                    conditions.has_audio_tags = if has_audio_val { Some(true) } else { None };
                }
            });

            ui.separator();
            ui.label(RichText::new("Security Conditions:").strong());

            // 8. Security Evaluators
            ui.horizontal(|ui| {
                let mut d_ext = conditions.double_extension.unwrap_or(false);
                if ui.checkbox(&mut d_ext, "Deceptive Double-Extension (e.g. invoice.pdf.sh)").changed() {
                    conditions.double_extension = if d_ext { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_perm = conditions.dangerous_permissions.unwrap_or(false);
                if ui.checkbox(&mut d_perm, "Dangerous Permissions (+x on non-binaries)").changed() {
                    conditions.dangerous_permissions = if d_perm { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_sec = conditions.contains_secrets.unwrap_or(false);
                if ui.checkbox(&mut d_sec, "Leaked Secret / API Key Detection (.env, private keys)").changed() {
                    conditions.contains_secrets = if d_sec { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_desktop = conditions.suspicious_desktop_file.unwrap_or(false);
                if ui.checkbox(&mut d_desktop, "Phishing .desktop Launcher File").changed() {
                    conditions.suspicious_desktop_file = if d_desktop { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_spoof = conditions.mime_spoofing.unwrap_or(false);
                if ui.checkbox(&mut d_spoof, "MIME Spoofing Detection (executable binary disguised as image/PDF)").changed() {
                    conditions.mime_spoofing = if d_spoof { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_mal = conditions.malware_signature.unwrap_or(false);
                if ui.checkbox(&mut d_mal, "Malware & Web Shell Signature Detection (EICAR, PHP/Python web shells, reverse shells)").changed() {
                    conditions.malware_signature = if d_mal { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut has_vt = conditions.virustotal_min_positives.is_some();
                if ui.checkbox(&mut has_vt, "VirusTotal SHA-256 Hash Check (Flag if >= engines detect):").changed() {
                    conditions.virustotal_min_positives = if has_vt { Some(3) } else { None };
                }
                if let Some(ref mut min_pos) = conditions.virustotal_min_positives {
                    ui.add(egui::DragValue::new(min_pos).range(1..=70));
                    ui.label(RichText::new("flagged engines").size(11.0).color(Color32::GRAY));
                }
            });

            ui.horizontal(|ui| {
                let mut d_fork = conditions.forkbomb_detector.unwrap_or(false);
                if ui.checkbox(&mut d_fork, "Fork Bomb Detector (:(){ :|:& };: / while True: os.fork())").changed() {
                    conditions.forkbomb_detector = if d_fork { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_zip = conditions.zipbomb_detector.unwrap_or(false);
                if ui.checkbox(&mut d_zip, "Zip Bomb & Decompression Bomb Detector (>100:1 ratio, 42.zip)").changed() {
                    conditions.zipbomb_detector = if d_zip { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_invis = conditions.invisible_unicode_detector.unwrap_or(false);
                if ui.checkbox(&mut d_invis, "Hidden Zero-Width Unicode Characters (Invisible payload detection)").changed() {
                    conditions.invisible_unicode_detector = if d_invis { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_poly = conditions.polyglot_payload_detector.unwrap_or(false);
                if ui.checkbox(&mut d_poly, "Polyglot Stego Image Payloads (Hidden executables appended after image EOF)").changed() {
                    conditions.polyglot_payload_detector = if d_poly { Some(true) } else { None };
                }
            });

            ui.horizontal(|ui| {
                let mut d_homo = conditions.homoglyph_detector.unwrap_or(false);
                if ui.checkbox(&mut d_homo, "IDN / Cyrillic Homoglyph Lookalike Character Spoofing in Filename").changed() {
                    conditions.homoglyph_detector = if d_homo { Some(true) } else { None };
                }
            });
        });
}

fn show_actions_card(
    ui: &mut Ui,
    action: &mut ActionConfig,
    rule_idx: usize,
    picker_receiver: &mut Option<mpsc::Receiver<(usize, bool, PathBuf)>>,
) {
    egui::Frame::group(ui.style())
        .fill(ui.visuals().window_fill())
        .show(ui, |ui| {
            ui.label(RichText::new("THEN (Actions)").heading().color(Color32::from_rgb(50, 180, 255)));
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Action to Perform:");
                egui::ComboBox::from_id_salt("action_type_combo")
                    .selected_text(match action.action {
                        ActionType::Move => "Move to Folder",
                        ActionType::Copy => "Copy to Folder",
                        ActionType::Rename => "Rename File",
                        ActionType::Delete => "Delete Permanently",
                        ActionType::Trash => "Move to FreeDesktop Trash",
                        ActionType::Extract => "Auto-Extract Archive",
                        ActionType::Symlink => "Create Symlink",
                        ActionType::Hardlink => "Create Hardlink",
                        ActionType::Quarantine => "Quarantine File (0o600)",
                        ActionType::Script => "Execute Shell Script",
                        ActionType::None => "No Action (Inspect Only)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut action.action, ActionType::Move, "Move to Folder");
                        ui.selectable_value(&mut action.action, ActionType::Copy, "Copy to Folder");
                        ui.selectable_value(&mut action.action, ActionType::Rename, "Rename File");
                        ui.selectable_value(&mut action.action, ActionType::Trash, "Move to FreeDesktop Trash");
                        ui.selectable_value(&mut action.action, ActionType::Extract, "Auto-Extract Archive");
                        ui.selectable_value(&mut action.action, ActionType::Symlink, "Create Symlink");
                        ui.selectable_value(&mut action.action, ActionType::Hardlink, "Create Hardlink");
                        ui.selectable_value(&mut action.action, ActionType::Delete, "Delete Permanently");
                        ui.selectable_value(&mut action.action, ActionType::Quarantine, "Quarantine File (0o600)");
                        ui.selectable_value(&mut action.action, ActionType::Script, "Execute Shell Script");
                        ui.selectable_value(&mut action.action, ActionType::None, "No Action (Inspect Only)");
                    });
            });

            // Destination input for Move / Copy / Rename / Extract / Symlink / Quarantine
            if matches!(action.action, ActionType::Move | ActionType::Copy | ActionType::Rename | ActionType::Extract | ActionType::Symlink | ActionType::Hardlink | ActionType::Quarantine) {
                ui.horizontal(|ui| {
                    ui.label("Destination Path:");
                    let mut dest_val = action.destination.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut dest_val).changed() {
                        action.destination = Some(dest_val);
                    }
                    if ui.button("Browse...").clicked() {
                        let (tx, rx) = mpsc::channel();
                        *picker_receiver = Some(rx);
                        std::thread::spawn(move || {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                let _ = tx.send((rule_idx, false, folder));
                            }
                        });
                    }
                });

                // DYNAMIC VARIABLE TOKEN INSERTER CHIPS
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Insert Token:").size(11.0).color(Color32::LIGHT_BLUE));
                    let tokens = [
                        ("{year}", "Year"),
                        ("{month}", "Month"),
                        ("{day}", "Day"),
                        ("{filename}", "Filename"),
                        ("{stem}", "Stem"),
                        ("{ext}", "Ext"),
                        ("{exif_year}", "Photo Year"),
                        ("{camera_model}", "Camera"),
                        ("{music_artist}", "Artist"),
                        ("{music_album}", "Album"),
                        ("{music_title}", "Title"),
                        ("{file_age_days}", "Age(Days)"),
                        ("{sha256}", "SHA-256"),
                    ];

                    for (token, label) in tokens {
                        if ui.button(RichText::new(label).size(11.0)).on_hover_text(format!("Insert {}", token)).clicked() {
                            let mut current = action.destination.clone().unwrap_or_default();
                            current.push_str(token);
                            action.destination = Some(current);
                        }
                    }
                });

                // Conflict Resolution
                if !matches!(action.action, ActionType::Extract | ActionType::Trash) {
                    ui.horizontal(|ui| {
                        ui.label("If File Already Exists:");
                        egui::ComboBox::from_id_salt("conflict_combo")
                            .selected_text(match action.conflict_resolution {
                                ConflictResolution::RenameWithCounter => "Rename with counter (file (1).ext)",
                                ConflictResolution::Overwrite => "Overwrite existing",
                                ConflictResolution::Skip => "Skip file",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut action.conflict_resolution, ConflictResolution::RenameWithCounter, "Rename with counter (file (1).ext)");
                                ui.selectable_value(&mut action.conflict_resolution, ConflictResolution::Overwrite, "Overwrite existing");
                                ui.selectable_value(&mut action.conflict_resolution, ConflictResolution::Skip, "Skip file");
                            });
                    });
                }

                if action.action == ActionType::Extract {
                    ui.checkbox(&mut action.delete_archive_after_extract, "Move archive to trash after extraction");
                }
            }

            // Script Command
            if action.action == ActionType::Script {
                ui.horizontal(|ui| {
                    ui.label("Bash Script / Command:");
                    let mut script_val = action.script.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut script_val).changed() {
                        action.script = Some(script_val);
                    }
                });
                ui.label(RichText::new("Env variables passed: $JUGGLR_FILE, $JUGGLR_RULE, $JUGGLR_VAR_STEM...").size(11.0).color(Color32::GRAY));
            }

            ui.separator();
            ui.label(RichText::new("Security, Notifications & Webhooks:").strong());

            ui.horizontal(|ui| {
                ui.checkbox(&mut action.strip_executable, "Strip Executable Permissions (chmod -x)");
                ui.checkbox(&mut action.secret_audit, "Trigger Secret Leak Warning");
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut action.notify, "Show Desktop Notification");

                if action.notify {
                    ui.label("Urgency:");
                    let mut urgency_val = action.alert_urgency.clone().unwrap_or_else(|| "normal".to_string());
                    egui::ComboBox::from_id_salt("urgency_combo")
                        .selected_text(&urgency_val)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut urgency_val, "low".to_string(), "Low");
                            ui.selectable_value(&mut urgency_val, "normal".to_string(), "Normal");
                            ui.selectable_value(&mut urgency_val, "critical".to_string(), "Critical");
                        });
                    action.alert_urgency = Some(urgency_val);
                }
            });

            ui.horizontal(|ui| {
                ui.label("Webhook URL:");
                let mut wh_val = action.webhook_url.clone().unwrap_or_default();
                if ui.text_edit_singleline(&mut wh_val).changed() {
                    action.webhook_url = if wh_val.is_empty() { None } else { Some(wh_val) };
                }
                ui.label(RichText::new("(Discord, Slack, or REST endpoint)").size(11.0).color(Color32::GRAY));
            });

            if action.notify || action.webhook_url.is_some() {
                ui.horizontal(|ui| {
                    ui.label("Custom Message Template:");
                    let mut msg_val = action.notify_message.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut msg_val).changed() {
                        action.notify_message = if msg_val.is_empty() { None } else { Some(msg_val) };
                    }
                });
            }
        });
}
