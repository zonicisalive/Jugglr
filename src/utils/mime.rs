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

    // 2. Try shebang inspection for text scripts
    if slice.starts_with(b"#!") {
        if let Ok(shebang) = std::str::from_utf8(&slice[..bytes_read.min(256)]) {
            let first_line = shebang.lines().next().unwrap_or("");
            if first_line.contains("python") {
                return Ok("text/x-python".to_string());
            } else if first_line.contains("sh") || first_line.contains("bash") || first_line.contains("zsh") {
                return Ok("application/x-sh".to_string());
            } else if first_line.contains("node") || first_line.contains("deno") {
                return Ok("application/javascript".to_string());
            } else if first_line.contains("perl") {
                return Ok("text/x-perl".to_string());
            } else if first_line.contains("ruby") {
                return Ok("text/x-ruby".to_string());
            }
        }
    }

    // 3. Fallback by file extension
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        let mime = match ext_lower.as_str() {
            "toml" => "application/toml",
            "json" => "application/json",
            "yaml" | "yml" => "application/yaml",
            "csv" => "text/csv",
            "tsv" => "text/tab-separated-values",
            "env" => "text/plain",
            "txt" | "log" | "md" | "rst" => "text/plain",
            "sh" | "bash" | "zsh" => "application/x-sh",
            "py" => "text/x-python",
            "js" | "mjs" | "cjs" => "application/javascript",
            "ts" => "application/typescript",
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "xml" => "application/xml",
            "svg" => "image/svg+xml",
            "rs" => "text/rust",
            "c" | "h" => "text/x-c",
            "cpp" | "hpp" | "cc" => "text/x-c++",
            "go" => "text/x-go",
            "pdf" => "application/pdf",
            "zip" => "application/zip",
            "tar" => "application/x-tar",
            "gz" => "application/gzip",
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
    if slice.starts_with(b"\xCA\xFE\xBA\xBE") || slice.starts_with(b"\xCF\xFA\xED\xFE") {
        return Ok(true); // Mach-O / Java bytecode
    }

    Ok(!is_buffer_text(slice))
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
