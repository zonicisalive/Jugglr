use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalReport {
    pub sha256: String,
    pub malicious_count: u32,
    pub suspicious_count: u32,
    pub total_engines: u32,
    pub popular_threat_name: Option<String>,
}

static VT_CACHE: OnceLock<Mutex<HashMap<String, Option<VirusTotalReport>>>> = OnceLock::new();

fn get_cache() -> &'static Mutex<HashMap<String, Option<VirusTotalReport>>> {
    VT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up a file's SHA-256 hash in VirusTotal API v3.
/// Returns the report containing detection counts from 70+ antivirus engines.
pub fn lookup_hash(api_key: &str, sha256: &str) -> Option<VirusTotalReport> {
    if api_key.trim().is_empty() || sha256.len() != 64 {
        return None;
    }

    let cache_lock = get_cache();

    // 1. Check local in-memory cache first
    if let Ok(cache) = cache_lock.lock() {
        if let Some(cached) = cache.get(sha256) {
            return cached.clone();
        }
    }

    // 2. Query VirusTotal API v3 endpoint
    let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
    let resp = ureq::get(&url)
        .set("x-apikey", api_key.trim())
        .timeout(std::time::Duration::from_secs(5))
        .call();

    match resp {
        Ok(r) => {
            if let Ok(body_str) = r.into_string() {
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&body_str) {
                    let stats = json_val.pointer("/data/attributes/last_analysis_stats");
                    let threat = json_val.pointer("/data/attributes/popular_threat_classification/suggested_threat_label")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    if let Some(stats_obj) = stats {
                        let malicious = stats_obj.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let suspicious = stats_obj.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let harmless = stats_obj.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let undetected = stats_obj.get("undetected").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let total = malicious + suspicious + harmless + undetected;

                        let report = VirusTotalReport {
                            sha256: sha256.to_string(),
                            malicious_count: malicious,
                            suspicious_count: suspicious,
                            total_engines: total,
                            popular_threat_name: threat,
                        };

                        info!("VirusTotal lookup for {}...: {}/{} malicious detections", &sha256[..10], malicious, total);

                        if let Ok(mut cache) = cache_lock.lock() {
                            cache.insert(sha256.to_string(), Some(report.clone()));
                        }

                        return Some(report);
                    }
                }
            }
        }
        Err(ureq::Error::Status(404, _)) => {
            // Hash unknown to VirusTotal (never submitted before)
            if let Ok(mut cache) = cache_lock.lock() {
                cache.insert(sha256.to_string(), None);
            }
            return None;
        }
        Err(e) => {
            warn!("VirusTotal API query failed: {}", e);
        }
    }

    None
}
