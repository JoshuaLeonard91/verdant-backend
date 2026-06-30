/// Whitelisted hosts for inline media embeds. URLs from other hosts are still
/// allowed as plain text but must not render inline as images/videos.
const ALLOWED_MEDIA_HOSTS: &[&str] = &["media.klipy.com", "static.klipy.com"];

/// Check if message content contains media-looking URLs from non-whitelisted
/// hosts. Returns the offending host when an image/video URL should be blocked.
pub fn check_media_urls(content: &str) -> Option<String> {
    let media_exts = [".gif", ".png", ".jpg", ".jpeg", ".webp", ".mp4", ".webm"];

    for word in content.split_whitespace() {
        let lower = word.to_lowercase();
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            continue;
        }

        let path_end = lower.find('?').unwrap_or(lower.len());
        let path_end = lower[..path_end].rfind('#').unwrap_or(path_end);
        let path_part = &lower[..path_end];
        if !media_exts.iter().any(|ext| path_part.ends_with(ext)) {
            continue;
        }

        let after_scheme = if lower.starts_with("https://") {
            &word[8..]
        } else {
            &word[7..]
        };
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let host_port = &after_scheme[..host_end].to_lowercase();
        let host = host_port.split(':').next().unwrap_or(host_port);

        if !ALLOWED_MEDIA_HOSTS.contains(&host) {
            return Some(host.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::check_media_urls;

    #[test]
    fn allows_klipy_media_hosts() {
        assert_eq!(check_media_urls("https://media.klipy.com/a.gif"), None);
        assert_eq!(check_media_urls("https://static.klipy.com/a.webp"), None);
    }

    #[test]
    fn rejects_media_urls_from_untrusted_hosts() {
        assert_eq!(
            check_media_urls("hello https://evil.example/a.png?x=1").as_deref(),
            Some("evil.example")
        );
        assert_eq!(
            check_media_urls("hello https://www.media.klipy.com/a.mp4").as_deref(),
            Some("www.media.klipy.com")
        );
    }

    #[test]
    fn ignores_non_media_urls() {
        assert_eq!(check_media_urls("https://evil.example/page"), None);
    }
}
