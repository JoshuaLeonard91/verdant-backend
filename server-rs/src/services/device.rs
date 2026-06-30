use crate::services::crypto::hash_token;

/// Parsed device info from User-Agent.
pub struct DeviceInfo {
    pub device_hash: String,
    pub device_label: String,
}

/// Parse a User-Agent string into a device fingerprint.
///
/// Fingerprint = SHA-256("browser:os:osMajor").
/// We do a simple UA parse here — no need for the full ua-parser-js library.
pub fn parse_device(user_agent: Option<&str>) -> DeviceInfo {
    let ua = user_agent.unwrap_or("Unknown");

    let browser = detect_browser(ua);
    let (os, os_version) = detect_os(ua);
    let os_major = os_version.split('.').next().unwrap_or("");

    let fingerprint = format!("{browser}:{os}:{os_major}");
    let device_hash = hash_token(&fingerprint);

    let device_label = if os_major.is_empty() {
        format!("{browser} on {os}")
    } else {
        format!("{browser} on {os} {os_major}")
    };

    DeviceInfo {
        device_hash,
        device_label,
    }
}

fn detect_browser(ua: &str) -> &str {
    // Order matters: check more specific browsers first
    if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Vivaldi") {
        "Vivaldi"
    } else if ua.contains("Brave") {
        "Brave"
    } else if ua.contains("Chrome/") {
        "Chrome"
    } else if ua.contains("Safari/") && !ua.contains("Chrome") {
        "Safari"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else {
        "Unknown"
    }
}

fn detect_os(ua: &str) -> (&str, String) {
    if ua.contains("Windows NT 10") {
        // Could be Win10 or Win11 — UA doesn't distinguish reliably
        ("Windows", "10".to_string())
    } else if ua.contains("Windows NT") {
        ("Windows", String::new())
    } else if ua.contains("Mac OS X") {
        let version = extract_between(ua, "Mac OS X ", ")").unwrap_or_default();
        ("macOS", version.replace('_', "."))
    } else if ua.contains("Android") {
        let version = extract_between(ua, "Android ", ";").unwrap_or_default();
        ("Android", version)
    } else if ua.contains("iPhone OS") || ua.contains("iPad") {
        let version = extract_between(ua, "OS ", " ").unwrap_or_default();
        ("iOS", version.replace('_', "."))
    } else if ua.contains("Linux") {
        ("Linux", String::new())
    } else {
        ("Unknown", String::new())
    }
}

fn extract_between<'a>(s: &'a str, start: &str, end: &str) -> Option<String> {
    let start_idx = s.find(start)? + start.len();
    let remaining = &s[start_idx..];
    let end_idx = remaining.find(end).unwrap_or(remaining.len());
    Some(remaining[..end_idx].trim().to_string())
}
