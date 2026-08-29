use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use chrono::{DateTime, Local, Utc};
use crate::utils::audio::extract_audio_tags;
use crate::utils::exif::extract_exif;

#[derive(Debug, Clone, Default)]
pub struct ContextVariables {
    pub values: HashMap<String, String>,
}

impl ContextVariables {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    pub fn insert<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.values.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.values.get(key)
    }

    /// Build context variables for a target file.
    pub fn from_file(
        path: &Path,
        mime_type: Option<&str>,
        sha256: Option<&str>,
        regex_captures: Option<&HashMap<String, String>>,
    ) -> Self {
        let mut ctx = Self::new();

        let now: DateTime<Local> = Local::now();
        ctx.insert("year", now.format("%Y").to_string());
        ctx.insert("month", now.format("%m").to_string());
        ctx.insert("day", now.format("%d").to_string());
        ctx.insert("hour", now.format("%H").to_string());
        ctx.insert("minute", now.format("%M").to_string());
        ctx.insert("second", now.format("%S").to_string());

        let now_utc: DateTime<Utc> = Utc::now();
        ctx.insert("utc_year", now_utc.format("%Y").to_string());
        ctx.insert("utc_month", now_utc.format("%m").to_string());
        ctx.insert("utc_day", now_utc.format("%d").to_string());

        if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
            ctx.insert("filename", filename);
        }

        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            ctx.insert("stem", stem);
        }

        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            ctx.insert("ext", ext);
        } else {
            ctx.insert("ext", "");
        }

        if let Some(parent) = path.parent().and_then(|p| p.to_str()) {
            ctx.insert("original_dir", parent);
        }

        if let Some(mime) = mime_type {
            ctx.insert("mime_type", mime);
            ctx.insert("mime_sanitized", mime.replace('/', "_"));
        }

        if let Some(hash) = sha256 {
            ctx.insert("sha256", hash);
            ctx.insert("sha256_short", &hash[..hash.len().min(8)]);
        }

        // File age calculation
        if let Ok(meta) = fs::metadata(path) {
            if let Ok(mod_time) = meta.modified() {
                if let Ok(elapsed) = SystemTime::now().duration_since(mod_time) {
                    let secs = elapsed.as_secs();
                    let days = secs / 86400;
                    let hours = secs / 3600;
                    ctx.insert("file_age_days", days.to_string());
                    ctx.insert("file_age_hours", hours.to_string());
                }
            }
        }

        // EXIF Image metadata extraction
        if let Some(exif) = extract_exif(path) {
            if let Some(y) = exif.year { ctx.insert("exif_year", y); }
            if let Some(m) = exif.month { ctx.insert("exif_month", m); }
            if let Some(d) = exif.day { ctx.insert("exif_day", d); }
            if let Some(make) = exif.camera_make { ctx.insert("camera_make", make); }
            if let Some(model) = exif.camera_model { ctx.insert("camera_model", model); }
        }

        // Audio ID3 metadata extraction
        if let Some(audio) = extract_audio_tags(path) {
            if let Some(artist) = audio.artist { ctx.insert("music_artist", artist); }
            if let Some(album) = audio.album { ctx.insert("music_album", album); }
            if let Some(title) = audio.title { ctx.insert("music_title", title); }
            if let Some(track) = audio.track { ctx.insert("music_track", track); }
        }

        if let Some(captures) = regex_captures {
            for (k, v) in captures {
                ctx.insert(k.clone(), v.clone());
            }
        }

        ctx
    }

    /// Interpolate template string replacing `{key}` with corresponding context value.
    pub fn interpolate(&self, template: &str) -> String {
        let mut result = template.to_string();
        for (key, val) in &self.values {
            let placeholder = format!("{{{}}}", key);
            result = result.replace(&placeholder, val);
        }
        result
    }
}
