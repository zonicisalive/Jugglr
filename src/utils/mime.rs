use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use sha2::{Digest, Sha256};

/// Detect MIME type of a file using magic bytes (via infer) with extension and shebang heuristics.
pub fn detect_mime(path: &Path) -> io::Result<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    let mut buffer = [0u8; 8192];
    let bytes_read = file.read(&mut buffer)?;
    let slice = &buffer[..bytes_read];

    // 1. Try magic number detection via `infer`
    if let Some(kind) = infer::get(slice) {
        return Ok(kind.mime_type().to_string());
    }

    // 2. Custom magic bytes checks for formats infer might miss
    if slice.starts_with(b"\x7fELF") {
        return Ok("application/x-executable".to_string());
    }
    if slice.starts_with(b"MZ") {
        return Ok("application/x-dosexec".to_string());
    }
    if slice.starts_with(b"\x00asm") {
        return Ok("application/wasm".to_string());
    }
    if slice.starts_with(b"SQLite format 3\x00") {
        return Ok("application/x-sqlite3".to_string());
    }
    if slice.starts_with(b"%PDF-") {
        return Ok("application/pdf".to_string());
    }
    if slice.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Ok("application/x-7z-compressed".to_string());
    }
    if slice.starts_with(b"Rar!\x1A\x07") {
        return Ok("application/x-rar-compressed".to_string());
    }
    if slice.starts_with(b"\x28\xB5\x2F\xFD") {
        return Ok("application/zstd".to_string());
    }

    // 3. Try shebang inspection for text scripts
    if slice.starts_with(b"#!") {
        if let Ok(shebang) = std::str::from_utf8(&slice[..bytes_read.min(256)]) {
            let first_line = shebang.lines().next().unwrap_or("");
            if first_line.contains("python") {
                return Ok("text/x-python".to_string());
            } else if first_line.contains("sh") || first_line.contains("bash") || first_line.contains("zsh") || first_line.contains("dash") {
                return Ok("application/x-sh".to_string());
            } else if first_line.contains("node") || first_line.contains("deno") || first_line.contains("bun") {
                return Ok("application/javascript".to_string());
            } else if first_line.contains("perl") {
                return Ok("text/x-perl".to_string());
            } else if first_line.contains("ruby") {
                return Ok("text/x-ruby".to_string());
            } else if first_line.contains("php") {
                return Ok("text/x-php".to_string());
            } else if first_line.contains("lua") {
                return Ok("text/x-lua".to_string());
            }
        }
    }

    // 4. Fallback by comprehensive file extension dictionary
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        let mime = match ext_lower.as_str() {
            // Documents & Office
            "pdf" => "application/pdf",
            "doc" => "application/msword",
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls" => "application/vnd.ms-excel",
            "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "ppt" => "application/vnd.ms-powerpoint",
            "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "odt" => "application/vnd.oasis.opendocument.text",
            "ods" => "application/vnd.oasis.opendocument.spreadsheet",
            "odp" => "application/vnd.oasis.opendocument.presentation",
            "rtf" => "application/rtf",
            "epub" => "application/epub+zip",
            // Plain text & Structured Data
            "toml" => "application/toml",
            "json" => "application/json",
            "yaml" | "yml" => "application/yaml",
            "xml" => "application/xml",
            "csv" => "text/csv",
            "tsv" => "text/tab-separated-values",
            "sql" => "application/sql",
            "env" | "conf" | "cfg" | "ini" | "properties" => "text/plain",
            "txt" | "log" | "md" | "markdown" | "rst" | "tex" => "text/plain",
            // Source Code & Scripts
            "sh" | "bash" | "zsh" | "fish" | "ksh" | "csh" => "application/x-sh",
            "py" | "pyw" => "text/x-python",
            "js" | "mjs" | "cjs" | "jsx" => "application/javascript",
            "ts" | "tsx" => "application/typescript",
            "html" | "htm" => "text/html",
            "css" | "scss" | "sass" | "less" => "text/css",
            "rs" => "text/rust",
            "c" | "h" => "text/x-c",
            "cpp" | "hpp" | "cc" | "cxx" => "text/x-c++",
            "go" => "text/x-go",
            "java" => "text/x-java-source",
            "kt" | "kts" => "text/x-kotlin",
            "swift" => "text/x-swift",
            "php" => "text/x-php",
            "rb" => "text/x-ruby",
            "pl" | "pm" => "text/x-perl",
            "lua" => "text/x-lua",
            "r" => "text/x-r",
            // Archives & Disk Images
            "zip" => "application/zip",
            "tar" => "application/x-tar",
            "gz" | "tgz" => "application/gzip",
            "bz2" | "tbz2" => "application/x-bzip2",
            "xz" | "txz" => "application/x-xz",
            "zst" => "application/zstd",
            "7z" => "application/x-7z-compressed",
            "rar" => "application/x-rar-compressed",
            "iso" => "application/x-iso9660-image",
            "deb" => "application/vnd.debian.binary-package",
            "rpm" => "application/x-rpm",
            "apk" => "application/vnd.android.package-archive",
            "dmg" => "application/x-apple-diskimage",
            "appimage" => "application/x-executable",
            // Images
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "bmp" => "image/bmp",
            "tiff" | "tif" => "image/tiff",
            "avif" => "image/avif",
            "heic" | "heif" => "image/heic",
            "raw" | "dng" | "cr2" | "nef" | "arw" => "image/x-dcraw",
            // Audio
            "mp3" => "audio/mpeg",
            "flac" => "audio/flac",
            "wav" => "audio/wav",
            "ogg" | "oga" | "opus" => "audio/ogg",
            "m4a" | "aac" => "audio/mp4",
            "wma" => "audio/x-ms-wma",
            "midi" | "mid" => "audio/midi",
            // Video
            "mp4" | "m4v" => "video/mp4",
            "mkv" => "video/x-matroska",
            "webm" => "video/webm",
            "avi" => "video/x-msvideo",
            "mov" => "video/quicktime",
            "wmv" => "video/x-ms-wmv",
            "flv" => "video/x-flv",
            // Binaries
            "bin" | "elf" => "application/x-executable",
            "exe" | "msi" | "dll" | "scr" => "application/x-dosexec",
            "wasm" => "application/wasm",
            _ => {
                if is_buffer_text(slice) {
                    "text/plain"
                } else {
                    "application/octet-stream"
                }
            }
        };
        return Ok(mime.to_string());
    }

    if is_buffer_text(slice) {
        Ok("text/plain".to_string())
    } else {
        Ok("application/octet-stream".to_string())
    }
}

/// Checks if a buffer is predominantly valid text (UTF-8 and no NULL bytes).
pub fn is_buffer_text(slice: &[u8]) -> bool {
    if slice.is_empty() {
        return true;
    }
    // Null byte presence is a strong indicator of binary content
    if slice.contains(&0) {
        return false;
    }
    std::str::from_utf8(slice).is_ok()
}

/// Check if a file appears to be a binary executable or compiled binary.
pub fn is_binary(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 1024];
    let bytes_read = file.read(&mut buffer)?;
    let slice = &buffer[..bytes_read];

    if slice.starts_with(b"\x7fELF") {
        return Ok(true); // Linux ELF binary
    }
    if slice.starts_with(b"MZ") {
        return Ok(true); // Windows PE executable
    }
    if slice.starts_with(b"\xCA\xFE\xBA\xBE") || slice.starts_with(b"\xCF\xFA\xED\xFE") || slice.starts_with(b"\xCE\xFA\xED\xFE") {
        return Ok(true); // Mach-O / Java bytecode
    }
    if slice.starts_with(b"\x00asm") {
        return Ok(true); // WebAssembly
    }

    Ok(!is_buffer_text(slice))
}

/// Detects MIME spoofing: when an extension claims to be a document or image,
/// but internal magic bytes reveal it is an ELF executable or shell payload.
pub fn detect_mime_spoofing(path: &Path) -> Option<String> {
    let ext = path.extension().and_then(|s| s.to_str())?.to_lowercase();
    let safe_exts = [
        "jpg", "jpeg", "png", "gif", "webp", "pdf", "docx", "xlsx", "pptx", "txt", "mp3", "mp4"
    ];

    if !safe_exts.contains(&ext.as_str()) {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let mut buffer = [0u8; 512];
    let bytes_read = file.read(&mut buffer).ok()?;
    let slice = &buffer[..bytes_read];

    if slice.starts_with(b"\x7fELF") {
        return Some(format!("Disguised ELF executable under .{} extension", ext));
    }
    if slice.starts_with(b"MZ") {
        return Some(format!("Disguised Windows executable (PE) under .{} extension", ext));
    }
    if slice.starts_with(b"#!/bin/sh") || slice.starts_with(b"#!/bin/bash") || slice.starts_with(b"#!/usr/bin/env") {
        return Some(format!("Disguised shell script under .{} extension", ext));
    }

    None
}

/// Compute SHA-256 hash of a file.
pub fn compute_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16384];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}
