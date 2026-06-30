use std::collections::BTreeMap;

use serde_json::Value;
use url::Url;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct MediaDiagnosticSummary {
    pub present: usize,
    pub invalid: usize,
    pub secure: usize,
    pub fields: BTreeMap<String, usize>,
    pub origins: BTreeMap<String, usize>,
    pub path_roots: BTreeMap<String, usize>,
    pub source_path_roots: BTreeMap<String, usize>,
    pub extensions: BTreeMap<String, usize>,
}

impl MediaDiagnosticSummary {
    pub(crate) fn record_json_field(&mut self, field: &str, object: &Value, key: &str) {
        self.record(field, object.get(key).and_then(Value::as_str));
    }

    pub(crate) fn record(&mut self, field: &str, raw_url: Option<&str>) {
        let Some(raw_url) = raw_url.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };

        self.present += 1;
        increment(&mut self.fields, field);

        let Ok(parsed) = Url::parse(raw_url) else {
            self.invalid += 1;
            return;
        };

        if parsed.scheme().eq_ignore_ascii_case("https") {
            self.secure += 1;
        }
        increment(&mut self.origins, &origin_for_log(&parsed));
        increment(&mut self.path_roots, &path_root_for_log(&parsed));
        increment(
            &mut self.source_path_roots,
            &source_path_root_for_log(&parsed),
        );
        increment(&mut self.extensions, &extension_for_log(&parsed));
    }
}

pub(crate) fn summarize_server_media(server: &Value) -> MediaDiagnosticSummary {
    let mut summary = MediaDiagnosticSummary::default();
    summary.record_json_field("server.icon", server, "iconUrl");
    summary.record_json_field("server.banner", server, "bannerUrl");
    summary
}

pub(crate) fn summarize_servers_media(servers: &[Value]) -> MediaDiagnosticSummary {
    let mut summary = MediaDiagnosticSummary::default();
    for server in servers {
        summary.record_json_field("server.icon", server, "iconUrl");
        summary.record_json_field("server.banner", server, "bannerUrl");
    }
    summary
}

pub(crate) fn summarize_user_media(user: &Value, prefix: &str) -> MediaDiagnosticSummary {
    let mut summary = MediaDiagnosticSummary::default();
    record_user_media(&mut summary, user, prefix);
    summary
}

pub(crate) fn summarize_member_media(members: &[Value], prefix: &str) -> MediaDiagnosticSummary {
    let mut summary = MediaDiagnosticSummary::default();
    for member in members {
        record_user_media(&mut summary, member, prefix);
    }
    summary
}

pub(crate) fn summarize_message_media(messages: &[Value]) -> MediaDiagnosticSummary {
    let mut summary = MediaDiagnosticSummary::default();
    for message in messages {
        summary.record_json_field("message.authorAvatar", message, "avatarUrl");
        summary.record_json_field("message.replyAuthorAvatar", message, "replyAuthorAvatarUrl");
    }
    summary
}

fn record_user_media(summary: &mut MediaDiagnosticSummary, user: &Value, prefix: &str) {
    summary.record_json_field(&format!("{prefix}.avatar"), user, "avatarUrl");
    summary.record_json_field(&format!("{prefix}.banner"), user, "bannerUrl");
    summary.record_json_field(
        &format!("{prefix}.memberListBanner"),
        user,
        "memberListBannerUrl",
    );
}

fn increment(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

fn origin_for_log(parsed: &Url) -> String {
    match parsed.port() {
        Some(port) => format!(
            "{}://{}:{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or(""),
            port
        ),
        None => format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or("")),
    }
}

fn path_root_for_log(parsed: &Url) -> String {
    parsed
        .path_segments()
        .and_then(|mut segments| segments.find(|segment| !segment.trim().is_empty()))
        .unwrap_or("none")
        .to_ascii_lowercase()
}

fn source_path_root_for_log(parsed: &Url) -> String {
    let Some(segments) = parsed.path_segments() else {
        return "none".to_string();
    };
    let segments: Vec<_> = segments
        .filter(|segment| !segment.trim().is_empty())
        .collect();
    if segments.len() >= 4
        && segments[0].eq_ignore_ascii_case("cdn-cgi")
        && segments[1].eq_ignore_ascii_case("image")
    {
        return segments[3].to_ascii_lowercase();
    }
    segments
        .first()
        .map(|segment| segment.to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string())
}

fn extension_for_log(parsed: &Url) -> String {
    let Some(filename) = parsed
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back())
    else {
        return "none".to_string();
    };
    let Some((_, extension)) = filename.rsplit_once('.') else {
        return "none".to_string();
    };
    let extension = extension.to_ascii_lowercase();
    if extension.len() <= 12 {
        extension
    } else {
        "long".to_string()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MediaDiagnosticSummary, summarize_server_media, summarize_user_media};

    #[test]
    fn summarizes_cdn_transformed_media_without_logging_object_keys() {
        let user = json!({
            "avatarUrl": "https://cdn.pryzmapp.com/cdn-cgi/image/metadata=none,format=auto/avatars/user-secret.webp",
            "bannerUrl": "https://cdn.pryzmapp.com/banners/banner-secret.png",
            "memberListBannerUrl": null,
        });

        let summary = summarize_user_media(&user, "currentUser");

        assert_eq!(summary.present, 2);
        assert_eq!(summary.invalid, 0);
        assert_eq!(summary.secure, 2);
        assert_eq!(summary.fields["currentUser.avatar"], 1);
        assert_eq!(summary.fields["currentUser.banner"], 1);
        assert_eq!(summary.path_roots["cdn-cgi"], 1);
        assert_eq!(summary.source_path_roots["avatars"], 1);
        assert_eq!(summary.source_path_roots["banners"], 1);
        assert_eq!(summary.extensions["webp"], 1);
        assert_eq!(summary.extensions["png"], 1);
        assert!(!format!("{summary:?}").contains("user-secret"));
    }

    #[test]
    fn records_invalid_presence_without_copying_the_url() {
        let server = json!({
            "iconUrl": "not a url containing key",
            "bannerUrl": "https://cdn.example.com/server-banners/banner.webp",
        });

        let summary = summarize_server_media(&server);

        assert_eq!(
            summary,
            MediaDiagnosticSummary {
                present: 2,
                invalid: 1,
                secure: 1,
                fields: [
                    ("server.banner".to_string(), 1),
                    ("server.icon".to_string(), 1),
                ]
                .into(),
                origins: [("https://cdn.example.com".to_string(), 1)].into(),
                path_roots: [("server-banners".to_string(), 1)].into(),
                source_path_roots: [("server-banners".to_string(), 1)].into(),
                extensions: [("webp".to_string(), 1)].into(),
            }
        );
        assert!(!format!("{summary:?}").contains("not a url"));
    }
}
