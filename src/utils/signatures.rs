use std::fs::File;
use std::io::Read;
use std::path::Path;
use regex::Regex;

/// Scan file content for known malware signatures, web shells, reverse shells, and exploit payloads.
pub fn scan_malware_signatures(path: &Path) -> Option<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut buffer = Vec::new();
    // Read first 512KB for signature scanning
    if file.by_ref().take(512 * 1024).read_to_end(&mut buffer).is_err() {
        return None;
    }

    // 1. EICAR Standard Antivirus Test String Check
    if buffer.windows(68).any(|w| w == b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") {
        return Some("EICAR Standard Antivirus Test Signature".to_string());
    }

    // 2. Binary / Text inspections
    let content_lossy = String::from_utf8_lossy(&buffer);
    let content_lower = content_lossy.to_lowercase();

    // 3. Web Shell Backdoors (PHP, JSP, ASPX, Node, Python)
    let webshell_signatures = [
        ("eval(base64_decode", "Obfuscated Base64 PHP Web Shell"),
        ("eval(gzinflate(base64_decode", "Obfuscated Gzinflate PHP Web Shell"),
        ("eval(gzuncompress(base64_decode", "Obfuscated Gzuncompress PHP Web Shell"),
        ("assert($_post[", "PHP Assert Backdoor"),
        ("assert($_get[", "PHP Assert Backdoor"),
        ("system($_get[", "PHP System Shell Backdoor"),
        ("system($_post[", "PHP System Shell Backdoor"),
        ("passthru($_get[", "PHP Passthru Shell Backdoor"),
        ("shell_exec($_get[", "PHP Shell_Exec Backdoor"),
        ("preg_replace('/.*/e'", "PHP Preg_Replace /e Code Execution Backdoor"),
        ("runtime.getruntime().exec(", "Java Runtime Exec Command Cradle"),
        ("c99shell", "C99 Web Shell"),
        ("r57shell", "R57 Web Shell"),
        ("b374k", "b374k Web Shell"),
        ("wso shell", "WSO Web Shell"),
        ("filesman", "FilesMan Web Shell"),
        ("alfa team", "Alfa Team Web Shell"),
    ];

    for (sig, label) in webshell_signatures {
        if content_lower.contains(sig) {
            return Some(label.to_string());
        }
    }

    // 4. Linux Reverse Shells & Malicious Command Cradles
    let reverse_shell_patterns: [(&str, &str); 8] = [
        (r#"bash\s+-i\s+>&?\s*/dev/tcp/"#, "Bash /dev/tcp Interactive Reverse Shell"),
        (r#"sh\s+-i\s+>&?\s*/dev/tcp/"#, "Sh /dev/tcp Interactive Reverse Shell"),
        (r#"exec\s+\d+<>/dev/tcp/"#, "File Descriptor /dev/tcp Reverse Shell"),
        (r#"nc(?:at)?\s+(?:-[a-z]*e|--exec)\s+/(?:bin/)?(?:ba)?sh"#, "Netcat Interactive Reverse Shell (-e)"),
        (r#"socat\s+.*exec:\s*['"]?(?:/bin/)?(?:ba)?sh"#, "Socat PTY Reverse Shell"),
        (r#"python(?:\d)?\s+-c\s+['"]import\s+socket,subprocess,os;s=socket\.socket"#, "Python Socket Reverse Shell One-Liner"),
        (r#"perl\s+-e\s+['"]use\s+Socket;\$i="#, "Perl Socket Reverse Shell"),
        (r#"ruby\s+-rsocket\s+-e\s*['"]f=TCPSocket\.open"#, "Ruby Socket Reverse Shell"),
    ];

    for (pattern, label) in reverse_shell_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&content_lossy) {
                return Some(label.to_string());
            }
        }
    }

    // 5. Crypto Miners (Stratum mining protocol strings)
    if content_lower.contains("stratum+tcp://") || content_lower.contains("stratum+ssl://") || content_lower.contains("stratum+udp://") {
        if content_lower.contains("xmr") || content_lower.contains("monero") || content_lower.contains("xmrig") || content_lower.contains("pool") {
            return Some("Cryptocurrency Miner Payload (Stratum Protocol)".to_string());
        }
    }

    // 6. Memory Injection / Process Hollowing Signatures
    if content_lower.contains("memfd_create") && (content_lower.contains("fexecve") || content_lower.contains("/proc/self/fd/")) {
        return Some("In-Memory Process Injection / Execution (memfd_create)".to_string());
    }

    None
}
