use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;
use regex::Regex;
use zip::ZipArchive;

/// `name(){ name|name& };name` with the four name positions captured independently.
static NAMED_FORKBOMB: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"([a-zA-Z0-9_]+)\s*\(\s*\)\s*\{\s*([a-zA-Z0-9_]+)\s*\|\s*([a-zA-Z0-9_]+)\s*&\s*\}\s*;\s*([a-zA-Z0-9_]+)",
    )
    .ok()
});

/// Detects fork bombs across Bash, Python, Batch, C, Perl, and Ruby scripts.
pub fn detect_forkbomb(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut buffer = Vec::new();
    file.take(128 * 1024).read_to_end(&mut buffer).ok()?;

    let content_lossy = String::from_utf8_lossy(&buffer);
    let normalized = content_lossy.replace([' ', '\t', '\n', '\r'], "");
    let normalized_lower = normalized.to_lowercase();

    // 1. Classic & Obfuscated Bash Fork Bombs: :(){ :|:& };: or name(){ name|name& };name
    if normalized.contains(":(){:|:&};:") || normalized.contains("(){|&};") {
        return Some("Classic Bash Fork Bomb (:(){ :|:& };:)".to_string());
    }

    // Generic Bash function calling itself piped into itself in background.
    // The `regex` crate has no backreferences, so the four occurrences of the function name are
    // captured separately and compared here.
    if let Some(re) = NAMED_FORKBOMB.as_ref() {
        for caps in re.captures_iter(&content_lossy) {
            let name = &caps[1];
            if &caps[2] == name && &caps[3] == name && &caps[4] == name {
                return Some("Custom Named Bash Fork Bomb".to_string());
            }
        }
    }

    // 2. Python Fork Bomb: while True: os.fork() / while 1: os.fork()
    if (normalized_lower.contains("whiletrue:") || normalized_lower.contains("while1:") || normalized_lower.contains("whiletrue"))
        && (normalized_lower.contains("os.fork()") || normalized_lower.contains("fork()"))
    {
        return Some("Python Infinite Process Fork Bomb (while True: os.fork())".to_string());
    }

    // 3. Windows Batch Recursive Bomb: %0|%0 or start %0
    if normalized.contains("%0|%0") || (normalized.contains("start%0") && normalized.contains("goto")) {
        return Some("Windows Batch Infinite Recursive Fork Bomb (%0|%0)".to_string());
    }

    // 4. C / C++ Fork Bomb: while(1) fork();
    if normalized_lower.contains("while(1)fork()") || normalized_lower.contains("while(1){fork();}") {
        return Some("C/C++ Infinite Fork Bomb (while(1) fork())".to_string());
    }

    // 5. Perl / Ruby Fork Bomb: fork while 1; or loop { fork }
    if content_lossy.contains("fork while 1") || content_lossy.contains("fork while fork") || normalized_lower.contains("loop{fork}") {
        return Some("Perl/Ruby Fork Bomb (fork while 1)".to_string());
    }

    None
}

/// Detects Zip Bombs and extreme decompression ratio traps (> 100:1 ratio or nested archive recursion).
pub fn detect_zipbomb(path: &Path) -> Option<String> {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    if ext != "zip" {
        return None;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let compressed_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if compressed_size == 0 {
        return None;
    }

    let mut zip = match ZipArchive::new(file) {
        Ok(z) => z,
        Err(_) => return None,
    };

    let mut total_uncompressed_size: u64 = 0;
    let total_files: usize = zip.len();
    let mut nested_archives: usize = 0;

    for i in 0..total_files {
        if let Ok(file_entry) = zip.by_index(i) {
            total_uncompressed_size = total_uncompressed_size.saturating_add(file_entry.size());
            let name_lower = file_entry.name().to_lowercase();
            if name_lower.ends_with(".zip") || name_lower.ends_with(".tar.gz") || name_lower.ends_with(".tar") || name_lower.ends_with(".7z") {
                nested_archives += 1;
            }
        }
    }

    let ratio = (total_uncompressed_size as f64) / (compressed_size as f64);

    // 1. Extreme compression ratio (> 100:1 ratio and uncompressed > 100MB)
    if ratio > 100.0 && total_uncompressed_size > 100 * 1024 * 1024 {
        return Some(format!(
            "Decompression Zip Bomb (Ratio {:.1}:1, {} MB compressed expands to {:.1} GB)",
            ratio,
            compressed_size / (1024 * 1024),
            (total_uncompressed_size as f64) / (1024.0 * 1024.0 * 1024.0)
        ));
    }

    // 2. High file count bomb in tiny archive (> 5,000 files in < 1MB archive)
    if total_files > 5000 && compressed_size < 1024 * 1024 {
        return Some(format!("Inode Exhaustion Zip Bomb ({} files in tiny archive)", total_files));
    }

    // 3. Multi-layer nested recursive zip bomb (e.g. 42.zip)
    if nested_archives > 10 && compressed_size < 5 * 1024 * 1024 {
        return Some(format!("Recursive Nested Zip Bomb (Contains {} nested archives)", nested_archives));
    }

    None
}

/// Detects invisible zero-width Unicode characters inside filenames or text contents.
pub fn detect_invisible_unicode(filename: &str, path: Option<&Path>) -> Option<String> {
    let invisible_chars = [
        ('\u{200B}', "Zero-Width Space"),
        ('\u{200C}', "Zero-Width Non-Joiner"),
        ('\u{200D}', "Zero-Width Joiner"),
        ('\u{200E}', "Left-to-Right Mark"),
        ('\u{200F}', "Right-to-Left Mark"),
        ('\u{FEFF}', "Zero-Width No-Break Space / Invisible BOM"),
        ('\u{2060}', "Word Joiner"),
        ('\u{2061}', "Function Application Invisible Char"),
        ('\u{2062}', "Invisible Times Char"),
        ('\u{2063}', "Invisible Separator"),
        ('\u{2064}', "Invisible Plus"),
    ];

    // Check filename
    for (ch, name) in &invisible_chars {
        if filename.contains(*ch) {
            return Some(format!("Invisible character in filename: {}", name));
        }
    }

    // Check content if path provided
    if let Some(p) = path {
        if let Ok(file) = File::open(p) {
            let mut buffer = Vec::new();
            if file.take(64 * 1024).read_to_end(&mut buffer).is_ok() {
                // Lossy: a strict decode fails on the first stray byte, which would skip the
                // scan entirely on mixed binary/text files that hide payloads.
                let text = String::from_utf8_lossy(&buffer);
                for (ch, name) in &invisible_chars {
                    if text.contains(*ch) {
                        return Some(format!("Hidden zero-width payload: {}", name));
                    }
                }
            }
        }
    }

    None
}

/// Detects Cyrillic and Greek lookalike homoglyphs mixed with Latin characters in filenames.
pub fn detect_homoglyphs(filename: &str) -> Option<String> {
    // Cyrillic letters that are visually identical to Latin letters:
    // а (a), с (c), е (e), о (o), р (p), х (x), у (y), і (i), ј (j), ѕ (s)
    let lookalikes = ['а', 'с', 'е', 'о', 'р', 'х', 'у', 'і', 'ј', 'ѕ', 'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т', 'Х'];

    let mut has_latin = false;
    let mut has_cyrillic_lookalike = false;

    for ch in filename.chars() {
        if ch.is_ascii_alphabetic() {
            has_latin = true;
        }
        if lookalikes.contains(&ch) {
            has_cyrillic_lookalike = true;
        }
    }

    if has_latin && has_cyrillic_lookalike {
        return Some("IDN / Cyrillic Homoglyph Lookalike Spoofing in Filename".to_string());
    }

    None
}

/// Detects polyglot payloads (hidden executables or ZIP archives appended after valid image EOF markers).
pub fn detect_polyglot_payload(path: &Path) -> Option<String> {
    let ext = path.extension().and_then(|s| s.to_str())?.to_lowercase();
    let mut file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let file_len = metadata.len();

    if file_len < 32 {
        return None;
    }

    // Read header (first 4KB)
    let mut header = vec![0u8; std::cmp::min(file_len as usize, 4096)];
    if file.read_exact(&mut header).is_err() {
        return None;
    }

    // Read trailer (last 256KB or full file)
    let mut trailer = Vec::new();
    if file_len <= 256 * 1024 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0)).ok()?;
        file.read_to_end(&mut trailer).ok()?;
    } else {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::End(-256 * 1024)).ok()?;
        file.read_to_end(&mut trailer).ok()?;
    }

    // 1. PNG Polyglot: PNG starts with \x89PNG and ends with chunk `IEND\xAE\x42\x60\x82`
    if ext == "png" && header.starts_with(b"\x89PNG\r\n\x1a\n") {
        let iend_marker = b"IEND\xAE\x42\x60\x82";
        if let Some(pos) = trailer.windows(iend_marker.len()).position(|w| w == iend_marker) {
            let eof_index = pos + iend_marker.len();
            let trailing_bytes = &trailer[eof_index..];
            if trailing_bytes.len() > 64 {
                if trailing_bytes.starts_with(b"PK\x03\x04") {
                    return Some("PNG Polyglot Steganography: Hidden ZIP archive appended after image EOF".to_string());
                }
                if trailing_bytes.starts_with(b"\x7fELF") {
                    return Some("PNG Polyglot Steganography: Hidden ELF executable appended after image EOF".to_string());
                }
                if trailing_bytes.starts_with(b"MZ") {
                    return Some("PNG Polyglot Steganography: Hidden Windows PE binary appended after image EOF".to_string());
                }
                if trailing_bytes.starts_with(b"#!/") {
                    return Some("PNG Polyglot Steganography: Hidden Shell script appended after image EOF".to_string());
                }
            }
        }
    }

    // 2. JPEG Polyglot: JPEG starts with \xFF\xD8\xFF and ends with marker `\xFF\xD9`
    if (ext == "jpg" || ext == "jpeg") && header.starts_with(b"\xFF\xD8\xFF") {
        if let Some(pos) = trailer.windows(2).rposition(|w| w == b"\xFF\xD9") {
            let eof_index = pos + 2;
            let trailing_bytes = &trailer[eof_index..];
            if trailing_bytes.len() > 64 {
                if trailing_bytes.starts_with(b"PK\x03\x04") {
                    return Some("JPEG Polyglot Steganography: Hidden ZIP archive appended after image EOF".to_string());
                }
                if trailing_bytes.starts_with(b"\x7fELF") || trailing_bytes.starts_with(b"MZ") {
                    return Some("JPEG Polyglot Steganography: Hidden Executable Binary appended after image EOF".to_string());
                }
                if trailing_bytes.starts_with(b"#!/") {
                    return Some("JPEG Polyglot Steganography: Hidden Shell Script appended after image EOF".to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("jugglr_threats_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        File::create(&path).unwrap().write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn detects_named_fork_bomb_without_backreferences() {
        let bomb = write_temp("bomb.sh", "#!/bin/bash
boom(){ boom|boom& };boom
");
        assert_eq!(detect_forkbomb(&bomb), Some("Custom Named Bash Fork Bomb".to_string()));

        // Same shape, different names in each position: not a self-recursive bomb.
        let benign = write_temp("benign.sh", "#!/bin/bash
start(){ left|right& };other
");
        assert_eq!(detect_forkbomb(&benign), None);
    }
}
