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

    /// Interpolate `{key}` placeholders, passing every substituted value through `transform`.
    ///
    /// A single left-to-right pass: substituted values are never rescanned, so a filename or
    /// ID3 tag containing `{sha256}` cannot trigger a second round of substitution. Unknown
    /// keys are left in place verbatim.
    fn interpolate_with(&self, template: &str, transform: impl Fn(&str) -> String) -> String {
        let mut out = String::with_capacity(template.len());
        let mut rest = template;

        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            rest = &rest[open..];

            match rest[1..].find('}') {
                Some(rel_close) => {
                    let key = &rest[1..1 + rel_close];
                    match self.values.get(key) {
                        Some(val) => out.push_str(&transform(val)),
                        None => out.push_str(&rest[..=1 + rel_close]),
                    }
                    rest = &rest[rel_close + 2..];
                }
                None => break,
            }
        }

        out.push_str(rest);
        out
    }

    /// Interpolate for display purposes (log lines, desktop notifications, webhook bodies).
    /// Values are inserted verbatim; never use this to build a path or a shell command.
    pub fn interpolate(&self, template: &str) -> String {
        self.interpolate_with(template, |val| val.to_string())
    }

    /// Interpolate into a filesystem path template.
    ///
    /// Most context values come from untrusted file content (EXIF, ID3 tags, regex captures on
    /// attacker-chosen filenames). A value like `../../.ssh` would otherwise escape the
    /// configured destination tree, so every substituted value is reduced to a single, inert
    /// path component. Separators written literally in the template are preserved.
    pub fn interpolate_path(&self, template: &str) -> String {
        self.interpolate_with(template, |val| sanitize_path_component(val))
    }

    /// Interpolate into a shell command template, quoting each substituted value so that
    /// attacker-controlled metadata cannot break out and run commands of its own.
    pub fn interpolate_shell(&self, template: &str) -> String {
        self.interpolate_with(template, |val| shell_quote(val))
    }
}

/// Reduce an untrusted value to a single path component that cannot traverse directories.
pub fn sanitize_path_component(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();

    let trimmed = cleaned.trim();

    // "", ".", ".." and friends are not usable component names.
    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        return "_".to_string();
    }

    trimmed.to_string()
}

/// POSIX single-quote a value for safe inclusion in a `bash -c` command string.
pub fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_interpolation_cannot_escape_destination() {
        let mut ctx = ContextVariables::new();
        ctx.insert("music_artist", "../../.ssh");
        ctx.insert("music_album", "a/b");
        assert_eq!(
            ctx.interpolate_path("~/Music/{music_artist}/{music_album}/x.mp3"),
            "~/Music/.._.._.ssh/a_b/x.mp3"
        );
    }

    #[test]
    fn shell_interpolation_quotes_injected_commands() {
        let mut ctx = ContextVariables::new();
        ctx.insert("filename", "x; rm -rf ~; it's.jpg");
        assert_eq!(
            ctx.interpolate_shell("convert {filename} out.png"),
            "convert 'x; rm -rf ~; it'\\''s.jpg' out.png"
        );
    }

    #[test]
    fn substituted_values_are_not_rescanned() {
        let mut ctx = ContextVariables::new();
        ctx.insert("stem", "{sha256}");
        ctx.insert("sha256", "deadbeef");
        assert_eq!(ctx.interpolate("{stem}"), "{sha256}");
    }

    #[test]
    fn unknown_placeholders_are_left_intact() {
        let ctx = ContextVariables::new();
        assert_eq!(ctx.interpolate("a{nope}b{"), "a{nope}b{");
    }
}
