use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

// ─── Types ───────────────────────────────────────────────────────────

/// Metadata about the file being scanned.
pub struct ScanMetadata {
    pub uploader_id: i64,
    pub channel_id: i64,
    pub server_id: Option<i64>,
    pub filename: String,
    pub content_type: String,
    pub sha256_hash: String,
}

/// Result of a content scan.
#[derive(Debug)]
pub enum ScanVerdict {
    /// Content is clean.
    Clean,
    /// Content was flagged.
    Flagged { match_type: String, confidence: f32 },
    /// Scanner encountered an error (content should be allowed through with pending status).
    Error(String),
}

/// Provider name for audit/logging.
pub trait ContentScanner: Send + Sync {
    fn provider_name(&self) -> &'static str;

    fn scan<'a>(
        &'a self,
        image_bytes: &'a [u8],
        metadata: &'a ScanMetadata,
    ) -> Pin<Box<dyn Future<Output = ScanVerdict> + Send + 'a>>;
}

/// Returns true when the current policy scans this content type.
pub fn should_scan(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

// ─── NoopScanner ─────────────────────────────────────────────────────

/// Always returns Clean. Used when scanning is disabled.
pub struct NoopScanner;

impl ContentScanner for NoopScanner {
    fn provider_name(&self) -> &'static str {
        "none"
    }

    fn scan<'a>(
        &'a self,
        _image_bytes: &'a [u8],
        _metadata: &'a ScanMetadata,
    ) -> Pin<Box<dyn Future<Output = ScanVerdict> + Send + 'a>> {
        Box::pin(async { ScanVerdict::Clean })
    }
}

// ─── MockScanner ─────────────────────────────────────────────────────

/// Flags images whose SHA-256 matches a configured set of "known bad" hashes.
/// For end-to-end testing of the pipeline.
pub struct MockScanner {
    known_bad_hashes: HashSet<String>,
}

impl MockScanner {
    pub fn new(hashes: HashSet<String>) -> Self {
        Self {
            known_bad_hashes: hashes,
        }
    }
}

impl ContentScanner for MockScanner {
    fn provider_name(&self) -> &'static str {
        "mock"
    }

    fn scan<'a>(
        &'a self,
        _image_bytes: &'a [u8],
        metadata: &'a ScanMetadata,
    ) -> Pin<Box<dyn Future<Output = ScanVerdict> + Send + 'a>> {
        let hash = metadata.sha256_hash.clone();
        let is_flagged = self.known_bad_hashes.contains(&hash);
        Box::pin(async move {
            if is_flagged {
                ScanVerdict::Flagged {
                    match_type: "hash_match".to_string(),
                    confidence: 1.0,
                }
            } else {
                ScanVerdict::Clean
            }
        })
    }
}

// ─── Factory ─────────────────────────────────────────────────────────

/// Try to create the appropriate scanner based on the provider configuration.
pub fn try_create_scanner(
    provider: &str,
    _api_key: Option<&str>,
    mock_hashes: Option<&str>,
) -> Result<Box<dyn ContentScanner>, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "mock" => {
            let hashes: HashSet<String> = mock_hashes
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            tracing::info!("Content scanner: mock ({} known-bad hashes)", hashes.len());
            Ok(Box::new(MockScanner::new(hashes)))
        }
        "photodna" | "thorn" => Err(format!(
            "content scanner provider '{provider}' is not supported in this build"
        )),
        "none" | "" => {
            tracing::info!("Content scanner: disabled (noop)");
            Ok(Box::new(NoopScanner))
        }
        other => Err(format!("unknown content scanner provider '{other}'")),
    }
}

/// Create the appropriate scanner based on the provider configuration.
pub fn create_scanner(
    provider: &str,
    api_key: Option<&str>,
    mock_hashes: Option<&str>,
) -> Box<dyn ContentScanner> {
    try_create_scanner(provider, api_key, mock_hashes).unwrap_or_else(|err| panic!("{err}"))
}

#[cfg(test)]
mod tests {
    use super::{create_scanner, try_create_scanner};

    #[test]
    fn disabled_scanner_reports_provider_none() {
        let scanner = create_scanner("none", None, None);

        assert_eq!(scanner.provider_name(), "none");
    }

    #[test]
    fn unsupported_scanner_provider_is_rejected() {
        let err = match try_create_scanner("photodna", None, None) {
            Ok(_) => panic!("photodna must fail"),
            Err(err) => err,
        };

        assert!(err.contains("not supported"));
    }
}
