//! Announcement message schema and validation.
//!
//! Announcements are stored as regular messages with `type = 2` (announcement).
//! The message `content` field contains a JSON string matching the [Announcement] schema.
//! Clients detect `type == 2` and render a rich card instead of plain text.
//!
//! # Message Types
//!
//! | type | Description |
//! |------|-------------|
//! | 0    | Regular message |
//! | 1    | System message (join/leave) |
//! | 2    | Announcement (rich card) |
//!
//! # Security
//!
//! - All text fields are plain text (no HTML)
//! - Image URLs must be from the app's own CDN (no external images)
//! - Button actions are internal navigation only (channel/invite) OR
//!   external URLs validated by Google Safe Browsing
//! - Color is validated as hex (#RRGGBB)

use serde::{Deserialize, Serialize};

use super::url_safety;

pub const MESSAGE_TYPE_ANNOUNCEMENT: i32 = 2;
const MAX_TITLE_LEN: usize = 256;
const MAX_DESCRIPTION_LEN: usize = 4096;
const MAX_SECTIONS: usize = 10;
const MAX_BUTTON_LABEL_LEN: usize = 80;
const MAX_FOOTER_LEN: usize = 256;
const MAX_IMAGE_ALT_LEN: usize = 256;
const MAX_CHART_TITLE_LEN: usize = 128;
const MAX_CHART_POINTS: usize = 24;
const MAX_CHART_LABEL_LEN: usize = 64;
const MAX_CHART_VALUE: f64 = 1_000_000_000.0;
const MAX_RICH_TEXT_SPANS: usize = 64;
const MIN_TEXT_FONT_SIZE: f32 = 8.0;
const MAX_TEXT_FONT_SIZE: f32 = 48.0;
const MAX_CDN_IMAGE_PATH_DECODE_PASSES: usize = 5;

/// Allowed CDN hosts for announcement images.
const ALLOWED_IMAGE_HOSTS: &[&str] = &[
    "cdn.pryzmapp.com",
    "cdn.verdant.chat",
    "verdant-media.nyc3.cdn.digitaloceanspaces.com",
    "verdant-media.nyc3.digitaloceanspaces.com",
];

/// Top-level announcement schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Announcement {
    pub title: String,
    #[serde(rename = "titleStyle", skip_serializing_if = "Option::is_none")]
    pub title_style: Option<TextStyle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "descriptionStyle", skip_serializing_if = "Option::is_none")]
    pub description_style: Option<TextStyle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<AnnouncementSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<String>,
    #[serde(rename = "footerStyle", skip_serializing_if = "Option::is_none")]
    pub footer_style: Option<TextStyle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextStyle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<TextSize>,
    #[serde(rename = "fontSize", skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<TextWeight>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub italic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strikethrough: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TextSize {
    Xs,
    Sm,
    Md,
    Lg,
    Xl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TextWeight {
    Normal,
    Medium,
    Semibold,
    Bold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RichTextSpan {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<TextStyle>,
}

/// Individual section within an announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum AnnouncementSection {
    /// Plain text paragraph.
    Text {
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        color: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<TextStyle>,
    },
    /// Flat styled text spans rendered by native clients without HTML/Markdown.
    RichText {
        spans: Vec<RichTextSpan>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<TextStyle>,
    },
    Heading {
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        level: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<TextStyle>,
    },
    Quote {
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<TextStyle>,
    },
    List {
        items: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ordered: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<TextStyle>,
    },
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<TextStyle>,
        #[serde(rename = "headerStyle", skip_serializing_if = "Option::is_none")]
        header_style: Option<TextStyle>,
        #[serde(rename = "cellStyle", skip_serializing_if = "Option::is_none")]
        cell_style: Option<TextStyle>,
    },
    Code {
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        language: Option<String>,
    },
    /// Image from the app's CDN only.
    Image {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        alt: Option<String>,
    },
    /// Visual divider line.
    Divider,
    /// Clickable button — internal navigation or validated external URL.
    Button {
        label: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<ButtonStyle>,
        #[serde(skip_serializing_if = "Option::is_none")]
        colors: Option<ButtonColors>,
        action: ButtonAction,
    },
    /// Simple client-rendered chart from bounded label/value rows.
    Chart {
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        kind: ChartKind,
        points: Vec<ChartPoint>,
    },
    /// YouTube playback reference rendered by a reviewed client player.
    #[serde(rename = "video", alias = "youtube")]
    Youtube {
        url: String,
        #[serde(rename = "videoId")]
        video_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ButtonColors {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub border: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ButtonStyle {
    Primary,
    Secondary,
    Danger,
}

/// Button action — either internal navigation or external URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ButtonAction {
    /// Navigate to a channel within the app.
    NavigateChannel {
        #[serde(rename = "channelId", alias = "channel_id")]
        channel_id: String,
    },
    /// Open a server invite.
    Invite { code: String },
    /// Open an external URL (validated by Safe Browsing).
    ExternalUrl { url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChartKind {
    Bar,
    Line,
    Donut,
    Metrics,
    Progress,
    Sparkline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChartPoint {
    pub label: String,
    pub value: f64,
}

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

/// Sanitize all text fields in an announcement (strip HTML, bidi, invisible chars).
/// Must be called before [`validate`].
pub fn sanitize(announcement: &mut Announcement) {
    use super::sanitize::{sanitize_code_text, sanitize_text, sanitize_text_preserve_edges};
    announcement.title = sanitize_text(&announcement.title);
    if let Some(ref mut desc) = announcement.description {
        *desc = sanitize_text(desc);
    }
    if let Some(ref mut footer) = announcement.footer {
        *footer = sanitize_text(footer);
    }
    for section in &mut announcement.sections {
        match section {
            AnnouncementSection::Text { content, .. }
            | AnnouncementSection::Heading { content, .. }
            | AnnouncementSection::Quote { content, .. } => {
                *content = sanitize_text(content);
            }
            AnnouncementSection::RichText { spans, .. } => {
                for span in spans {
                    span.text = sanitize_text_preserve_edges(&span.text);
                }
            }
            AnnouncementSection::Code { content, .. } => {
                *content = sanitize_code_text(content);
            }
            AnnouncementSection::List { items, .. } => {
                for item in items {
                    *item = sanitize_text(item);
                }
            }
            AnnouncementSection::Table { columns, rows, .. } => {
                for column in columns {
                    *column = sanitize_text(column);
                }
                for row in rows {
                    for cell in row {
                        *cell = sanitize_text(cell);
                    }
                }
            }
            AnnouncementSection::Image { alt, .. } => {
                if let Some(alt) = alt {
                    *alt = sanitize_text(alt);
                }
            }
            AnnouncementSection::Divider => {}
            AnnouncementSection::Button { label, .. } => {
                *label = sanitize_text(label);
            }
            AnnouncementSection::Chart { title, points, .. } => {
                if let Some(title) = title {
                    *title = sanitize_text(title);
                }
                for point in points {
                    point.label = sanitize_text(&point.label);
                }
            }
            AnnouncementSection::Youtube { title, .. } => {
                if let Some(title) = title {
                    *title = sanitize_text(title);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

static HEX_COLOR_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^#[0-9a-fA-F]{6}$").unwrap());
static INLINE_STYLE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\[[^\]\n]{1,512}\]\{([^}\n]{1,180})\}").unwrap()
});
static BRACED_POSTFIX_INLINE_STYLE_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\{[^{}\n]{1,512}\}\[([^\]\n]{1,180})\]").unwrap()
    });
static POSTFIX_INLINE_STYLE_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?:^|[\s(])[^\s\[\]{}]+\[([^\]\n]{1,180})\]").unwrap()
    });
static INLINE_STYLE_ATTR_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"(textColor|color|size|weight|italic|strikethrough)\s*[:=]\s*(#[0-9a-fA-F]{6}|[A-Za-z]+)",
    )
    .unwrap()
});
static TEXT_URL_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r#"https?://[^\s<>"{}|\\^`\[\]]+"#).unwrap());

fn validate_text_style(style: &Option<TextStyle>, label: &str) -> Result<(), String> {
    if let Some(style) = style {
        if let Some(color) = &style.color {
            if !HEX_COLOR_RE.is_match(color) {
                return Err(format!("{label}: text color must be #RRGGBB format"));
            }
        }
        if let Some(font_size) = style.font_size {
            if !font_size.is_finite()
                || !(MIN_TEXT_FONT_SIZE..=MAX_TEXT_FONT_SIZE).contains(&font_size)
            {
                return Err(format!(
                    "{label}: font size must be {MIN_TEXT_FONT_SIZE}-{MAX_TEXT_FONT_SIZE}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_button_colors(colors: &Option<ButtonColors>, label: &str) -> Result<(), String> {
    if let Some(colors) = colors {
        for (field, value) in [
            ("background", &colors.background),
            ("text", &colors.text),
            ("border", &colors.border),
        ] {
            if let Some(value) = value {
                if !HEX_COLOR_RE.is_match(value) {
                    return Err(format!(
                        "{label}: button {field} color must be #RRGGBB format"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_inline_style_tokens(value: &str, label: &str) -> Result<(), String> {
    for caps in INLINE_STYLE_RE.captures_iter(value) {
        if caps
            .get(0)
            .and_then(|m| value[..m.start()].chars().last())
            .map(|c| c == '\\')
            .unwrap_or(false)
        {
            continue;
        }
        let Some(attrs) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        validate_inline_style_attrs(attrs, label)?;
    }

    for caps in BRACED_POSTFIX_INLINE_STYLE_RE.captures_iter(value) {
        if caps
            .get(0)
            .and_then(|m| value[..m.start()].chars().last())
            .map(|c| c == '\\')
            .unwrap_or(false)
        {
            continue;
        }
        let Some(attrs) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if should_validate_postfix_style_attrs(attrs) {
            validate_inline_style_attrs(attrs, label)?;
        }
    }

    for caps in POSTFIX_INLINE_STYLE_RE.captures_iter(value) {
        let Some(full_match) = caps.get(0) else {
            continue;
        };
        let bracket_index = full_match
            .as_str()
            .rfind('[')
            .map(|relative| full_match.start() + relative);
        if bracket_index
            .and_then(|index| value[..index].chars().last())
            .map(|c| c == '\\')
            .unwrap_or(false)
        {
            continue;
        }
        let Some(attrs) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if should_validate_postfix_style_attrs(attrs) {
            validate_inline_style_attrs(attrs, label)?;
        }
    }
    Ok(())
}

fn should_validate_postfix_style_attrs(attrs: &str) -> bool {
    attrs.contains(':') || attrs.contains('=')
}

fn validate_inline_style_attrs(attrs: &str, label: &str) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    let mut found = false;

    for caps in INLINE_STYLE_ATTR_RE.captures_iter(attrs) {
        found = true;
        let Some(raw_key) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(raw_value) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let key = if raw_key == "textColor" {
            "color"
        } else {
            raw_key
        };
        if !seen.insert(key.to_string()) {
            return Err(format!("{label}: inline text style is invalid"));
        }
        match key {
            "color" => {
                if !HEX_COLOR_RE.is_match(raw_value) {
                    return Err(format!("{label}: inline text color must be #RRGGBB format"));
                }
            }
            "size" => {
                if !matches!(raw_value, "xs" | "sm" | "md" | "lg" | "xl") {
                    return Err(format!("{label}: inline text size is invalid"));
                }
            }
            "weight" => {
                if !matches!(raw_value, "normal" | "medium" | "semibold" | "bold") {
                    return Err(format!("{label}: inline text weight is invalid"));
                }
            }
            "italic" | "strikethrough" => {
                if !matches!(raw_value, "true" | "false") {
                    return Err(format!("{label}: inline text decoration flag is invalid"));
                }
            }
            _ => {
                return Err(format!("{label}: inline text style key is not allowed"));
            }
        }
    }

    let leftover = INLINE_STYLE_ATTR_RE.replace_all(attrs, "");
    if !found
        || leftover
            .chars()
            .any(|c| !(c.is_ascii_whitespace() || c == ';' || c == ','))
    {
        return Err(format!("{label}: inline text style is invalid"));
    }

    Ok(())
}

fn trim_url_trailing_punctuation(value: &str) -> &str {
    value.trim_end_matches(|c: char| {
        matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}')
    })
}

async fn validate_text_urls(value: &str, label: &str) -> Result<(), String> {
    let urls: Vec<String> = TEXT_URL_RE
        .find_iter(value)
        .map(|m| trim_url_trailing_punctuation(m.as_str()).to_string())
        .filter(|url| !url.is_empty())
        .collect();

    for url in urls {
        url_safety::validate_announcement_url(&url)
            .await
            .map_err(|e| format!("{label}: unsafe URL: {e}"))?;
    }

    Ok(())
}

/// Validate an announcement. Returns Ok(()) or a descriptive error.
pub async fn validate(announcement: &Announcement) -> Result<(), String> {
    // Title
    if announcement.title.is_empty() || announcement.title.len() > MAX_TITLE_LEN {
        return Err(format!("Title must be 1-{MAX_TITLE_LEN} characters"));
    }
    validate_inline_style_tokens(&announcement.title, "Title")?;
    validate_text_urls(&announcement.title, "Title").await?;

    // Description
    if let Some(ref desc) = announcement.description {
        if desc.len() > MAX_DESCRIPTION_LEN {
            return Err(format!(
                "Description must not exceed {MAX_DESCRIPTION_LEN} characters"
            ));
        }
        validate_inline_style_tokens(desc, "Description")?;
        validate_text_urls(desc, "Description").await?;
    }
    validate_text_style(&announcement.title_style, "Title")?;
    validate_text_style(&announcement.description_style, "Description")?;

    // Color
    if let Some(ref color) = announcement.color {
        if !HEX_COLOR_RE.is_match(color) {
            return Err("Color must be #RRGGBB format".to_string());
        }
    }

    // Sections
    if announcement.sections.len() > MAX_SECTIONS {
        return Err(format!("Maximum {MAX_SECTIONS} sections allowed"));
    }

    // Footer
    if let Some(ref footer) = announcement.footer {
        if footer.len() > MAX_FOOTER_LEN {
            return Err(format!(
                "Footer must not exceed {MAX_FOOTER_LEN} characters"
            ));
        }
        validate_inline_style_tokens(footer, "Footer")?;
        validate_text_urls(footer, "Footer").await?;
    }
    validate_text_style(&announcement.footer_style, "Footer")?;

    // Validate each section
    for (i, section) in announcement.sections.iter().enumerate() {
        match section {
            AnnouncementSection::Text {
                content,
                color,
                style,
            } => {
                if content.is_empty() || content.len() > MAX_DESCRIPTION_LEN {
                    return Err(format!(
                        "Section {i}: text must be 1-{MAX_DESCRIPTION_LEN} characters"
                    ));
                }
                validate_inline_style_tokens(content, &format!("Section {i}"))?;
                validate_text_urls(content, &format!("Section {i}")).await?;
                if let Some(color) = color {
                    if !HEX_COLOR_RE.is_match(color) {
                        return Err(format!("Section {i}: text color must be #RRGGBB format"));
                    }
                }
                validate_text_style(style, &format!("Section {i}"))?;
            }
            AnnouncementSection::RichText { spans, style } => {
                if spans.is_empty() || spans.len() > MAX_RICH_TEXT_SPANS {
                    return Err(format!(
                        "Section {i}: rich text must contain 1-{MAX_RICH_TEXT_SPANS} spans"
                    ));
                }
                let mut total_len = 0usize;
                for (span_index, span) in spans.iter().enumerate() {
                    if span.text.is_empty() {
                        return Err(format!(
                            "Section {i}: rich text span {span_index} must not be empty"
                        ));
                    }
                    total_len += span.text.len();
                    if total_len > MAX_DESCRIPTION_LEN {
                        return Err(format!(
                            "Section {i}: rich text must be at most {MAX_DESCRIPTION_LEN} characters"
                        ));
                    }
                    validate_inline_style_tokens(&span.text, &format!("Section {i}"))?;
                    validate_text_urls(&span.text, &format!("Section {i}")).await?;
                    validate_text_style(&span.style, &format!("Section {i} span {span_index}"))?;
                }
                validate_text_style(style, &format!("Section {i}"))?;
            }
            AnnouncementSection::Heading {
                content,
                level,
                style,
            } => {
                if content.is_empty() || content.len() > MAX_TITLE_LEN {
                    return Err(format!(
                        "Section {i}: heading must be 1-{MAX_TITLE_LEN} characters"
                    ));
                }
                validate_inline_style_tokens(content, &format!("Section {i}"))?;
                validate_text_urls(content, &format!("Section {i}")).await?;
                if let Some(level) = level {
                    if !(1..=3).contains(level) {
                        return Err(format!("Section {i}: heading level must be 1-3"));
                    }
                }
                validate_text_style(style, &format!("Section {i}"))?;
            }
            AnnouncementSection::Quote { content, style } => {
                if content.is_empty() || content.len() > MAX_DESCRIPTION_LEN {
                    return Err(format!(
                        "Section {i}: quote must be 1-{MAX_DESCRIPTION_LEN} characters"
                    ));
                }
                validate_inline_style_tokens(content, &format!("Section {i}"))?;
                validate_text_urls(content, &format!("Section {i}")).await?;
                validate_text_style(style, &format!("Section {i}"))?;
            }
            AnnouncementSection::List { items, style, .. } => {
                if items.is_empty() || items.len() > 50 {
                    return Err(format!("Section {i}: list must contain 1-50 items"));
                }
                for item in items {
                    if item.is_empty() || item.len() > 512 {
                        return Err(format!("Section {i}: list item must be 1-512 characters"));
                    }
                    validate_inline_style_tokens(item, &format!("Section {i}"))?;
                    validate_text_urls(item, &format!("Section {i}")).await?;
                }
                validate_text_style(style, &format!("Section {i}"))?;
            }
            AnnouncementSection::Table {
                columns,
                rows,
                style,
                header_style,
                cell_style,
            } => {
                if columns.is_empty() || columns.len() > 6 {
                    return Err(format!("Section {i}: table must contain 1-6 columns"));
                }
                if rows.is_empty() || rows.len() > 25 {
                    return Err(format!("Section {i}: table must contain 1-25 rows"));
                }
                for column in columns {
                    if column.is_empty() || column.len() > 128 {
                        return Err(format!(
                            "Section {i}: table column must be 1-128 characters"
                        ));
                    }
                    validate_inline_style_tokens(column, &format!("Section {i}"))?;
                    validate_text_urls(column, &format!("Section {i}")).await?;
                }
                for row in rows {
                    if row.len() > columns.len() {
                        return Err(format!("Section {i}: table row has too many cells"));
                    }
                    for cell in row {
                        if cell.len() > 512 {
                            return Err(format!(
                                "Section {i}: table cell must be at most 512 characters"
                            ));
                        }
                        validate_inline_style_tokens(cell, &format!("Section {i}"))?;
                        validate_text_urls(cell, &format!("Section {i}")).await?;
                    }
                }
                validate_text_style(style, &format!("Section {i}"))?;
                validate_text_style(header_style, &format!("Section {i} header"))?;
                validate_text_style(cell_style, &format!("Section {i} cell"))?;
            }
            AnnouncementSection::Code { content, language } => {
                if content.is_empty() || content.len() > MAX_DESCRIPTION_LEN {
                    return Err(format!(
                        "Section {i}: code must be 1-{MAX_DESCRIPTION_LEN} characters"
                    ));
                }
                if let Some(language) = language {
                    if language.len() > 32
                        || !language
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    {
                        return Err(format!("Section {i}: code language is invalid"));
                    }
                }
            }
            AnnouncementSection::Image { url, alt } => {
                validate_image_url(url)?;
                if let Some(alt) = alt {
                    if alt.len() > MAX_IMAGE_ALT_LEN {
                        return Err(format!(
                            "Section {i}: image alt text must be at most {MAX_IMAGE_ALT_LEN} characters"
                        ));
                    }
                }
            }
            AnnouncementSection::Divider => {}
            AnnouncementSection::Button {
                label,
                action,
                colors,
                ..
            } => {
                if label.is_empty() || label.len() > MAX_BUTTON_LABEL_LEN {
                    return Err(format!(
                        "Section {i}: button label must be 1-{MAX_BUTTON_LABEL_LEN} characters"
                    ));
                }
                validate_button_colors(colors, &format!("Section {i}"))?;
                validate_button_action(action).await?;
            }
            AnnouncementSection::Chart { title, points, .. } => {
                if let Some(title) = title {
                    if title.is_empty() || title.len() > MAX_CHART_TITLE_LEN {
                        return Err(format!(
                            "Section {i}: chart title must be 1-{MAX_CHART_TITLE_LEN} characters"
                        ));
                    }
                    validate_inline_style_tokens(title, &format!("Section {i}"))?;
                    validate_text_urls(title, &format!("Section {i}")).await?;
                }
                if points.is_empty() || points.len() > MAX_CHART_POINTS {
                    return Err(format!(
                        "Section {i}: chart must contain 1-{MAX_CHART_POINTS} points"
                    ));
                }
                for point in points {
                    if point.label.is_empty() || point.label.len() > MAX_CHART_LABEL_LEN {
                        return Err(format!(
                            "Section {i}: chart label must be 1-{MAX_CHART_LABEL_LEN} characters"
                        ));
                    }
                    validate_inline_style_tokens(&point.label, &format!("Section {i}"))?;
                    validate_text_urls(&point.label, &format!("Section {i}")).await?;
                    if !point.value.is_finite()
                        || point.value < 0.0
                        || point.value > MAX_CHART_VALUE
                    {
                        return Err(format!("Section {i}: chart value is out of range"));
                    }
                }
            }
            AnnouncementSection::Youtube {
                url,
                video_id,
                title,
            } => {
                validate_youtube_section(url, video_id)
                    .map_err(|error| format!("Section {i}: {error}"))?;
                if let Some(title) = title {
                    if title.is_empty() || title.len() > MAX_TITLE_LEN {
                        return Err(format!(
                            "Section {i}: YouTube title must be 1-{MAX_TITLE_LEN} characters"
                        ));
                    }
                    validate_inline_style_tokens(title, &format!("Section {i}"))?;
                    validate_text_urls(title, &format!("Section {i}")).await?;
                }
            }
        }
    }

    Ok(())
}

fn validate_image_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "Invalid image URL")?;

    let scheme = parsed.scheme();
    if scheme != "https" {
        return Err("Image URL must use HTTPS".to_string());
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Image URL must not contain credentials".to_string());
    }
    if parsed.fragment().is_some() {
        return Err("Image URL must not contain a fragment".to_string());
    }
    if parsed.port().is_some_and(|port| port != 443) {
        return Err("Image URL must use the default HTTPS port".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or("Image URL must have a host")?
        .to_ascii_lowercase();
    if !ALLOWED_IMAGE_HOSTS.iter().any(|&h| host == h) {
        return Err(format!(
            "Image must be uploaded to the app's CDN. External image URLs are not allowed."
        ));
    }
    validate_public_cdn_image_path(&parsed)?;

    Ok(())
}

fn validate_public_cdn_image_path(parsed: &url::Url) -> Result<(), String> {
    let raw_path = parsed.path();
    if raw_path.is_empty() || raw_path == "/" {
        return Err("Image URL must include an object path".to_string());
    }

    for path in decoded_cdn_image_path_candidates(raw_path)? {
        validate_public_cdn_image_path_candidate(&path)?;
    }

    Ok(())
}

fn decoded_cdn_image_path_candidates(raw_path: &str) -> Result<Vec<String>, String> {
    let mut candidates = Vec::with_capacity(MAX_CDN_IMAGE_PATH_DECODE_PASSES + 1);
    let mut current = raw_path.to_string();
    candidates.push(current.clone());

    for _ in 0..MAX_CDN_IMAGE_PATH_DECODE_PASSES {
        let decoded = urlencoding::decode(&current)
            .map_err(|_| "Image URL path has invalid encoding".to_string())?
            .into_owned();
        if decoded == current {
            return Ok(candidates);
        }
        candidates.push(decoded.clone());
        current = decoded;
    }

    Err("Image URL path is too deeply encoded".to_string())
}

fn validate_public_cdn_image_path_candidate(path: &str) -> Result<(), String> {
    if path.is_empty() || path == "/" {
        return Err("Image URL must include an object path".to_string());
    }

    let raw_path = path;
    let lower_path = raw_path.to_ascii_lowercase();
    if lower_path.contains('\\') || lower_path.contains('\0') {
        return Err("Image URL path is not allowed".to_string());
    }
    if lower_path.contains("%2e")
        || lower_path.contains("%2f")
        || lower_path.contains("%5c")
        || lower_path.contains("%00")
    {
        return Err("Image URL path must not contain encoded traversal".to_string());
    }

    let normalized_path = lower_path.trim_start_matches('/');
    if normalized_path.is_empty() {
        return Err("Image URL must include an object path".to_string());
    }

    let segments = normalized_path
        .split('/')
        .map(|segment| segment.to_string())
        .collect::<Vec<_>>();
    if segments
        .iter()
        .any(|segment| matches!(segment.as_str(), "" | "." | ".." | "attachments"))
    {
        return Err("Image URL path is not an allowed public media path".to_string());
    }
    if segments
        .windows(2)
        .any(|window| window[0] == "cdn-cgi" && window[1] == "image")
    {
        return Err("Image URL must not use a CDN transform path".to_string());
    }

    let filename = segments
        .last()
        .ok_or_else(|| "Image URL must include an object path".to_string())?;
    if filename.ends_with(".svg") || filename.ends_with(".svgz") {
        return Err("SVG images are not allowed".to_string());
    }

    Ok(())
}

fn validate_youtube_section(url: &str, video_id: &str) -> Result<(), String> {
    let extracted = extract_youtube_video_id(url).ok_or("Invalid YouTube URL")?;
    if extracted != video_id {
        return Err("YouTube video ID did not match URL".to_string());
    }
    Ok(())
}

fn extract_youtube_video_id(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    if host == "youtu.be" {
        let id = parsed.path_segments()?.next().unwrap_or_default();
        return clean_youtube_video_id(id);
    }
    let is_youtube_host = matches!(
        host.as_str(),
        "youtube.com" | "www.youtube.com" | "youtube-nocookie.com" | "www.youtube-nocookie.com"
    );
    if !is_youtube_host {
        return None;
    }
    if parsed.path() == "/watch" {
        return parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "v").then_some(value))
            .and_then(|value| clean_youtube_video_id(&value));
    }
    let mut segments = parsed.path_segments()?;
    let route = segments.next()?.to_ascii_lowercase();
    if matches!(route.as_str(), "embed" | "shorts" | "live") {
        return segments.next().and_then(clean_youtube_video_id);
    }
    None
}

fn clean_youtube_video_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if (6..=32).contains(&trimmed.len())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Some(trimmed.to_string());
    }
    None
}

pub async fn validate_server_targets(
    state: &crate::state::AppState,
    server_id: i64,
    announcement: &Announcement,
) -> Result<(), crate::error::AppError> {
    for section in &announcement.sections {
        let AnnouncementSection::Button { action, .. } = section else {
            continue;
        };

        match action {
            ButtonAction::NavigateChannel { channel_id } => {
                let target_channel_id = channel_id
                    .parse::<i64>()
                    .map_err(|_| crate::error::AppError::Validation("Invalid channel ID".into()))?;
                let channel = crate::services::pg::channels::by_id(&state.pg, target_channel_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            channel_id = target_channel_id,
                            error = %e,
                            "announcement target channel validation failed"
                        );
                        crate::error::AppError::Internal
                    })?;
                let Some(channel) = channel else {
                    return Err(crate::error::AppError::Validation(
                        "Button channel target must belong to this server".into(),
                    ));
                };
                if channel.server_id != Some(server_id) {
                    return Err(crate::error::AppError::Validation(
                        "Button channel target must belong to this server".into(),
                    ));
                }
            }
            ButtonAction::Invite { code } => {
                let invite = crate::services::pg::server_invites::by_code(&state.pg, code)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            code_len = code.len(),
                            error = %e,
                            "announcement target invite validation failed"
                        );
                        crate::error::AppError::Internal
                    })?;
                let Some(invite) = invite else {
                    return Err(crate::error::AppError::Validation(
                        "Button invite target must belong to this server".into(),
                    ));
                };
                if invite.server_id != server_id {
                    return Err(crate::error::AppError::Validation(
                        "Button invite target must belong to this server".into(),
                    ));
                }
                let now_ms = chrono::Utc::now().timestamp_millis();
                if invite
                    .expires_at_ms
                    .map(|expires| expires <= now_ms)
                    .unwrap_or(false)
                    || (invite.max_uses > 0 && invite.uses >= invite.max_uses)
                {
                    return Err(crate::error::AppError::Validation(
                        "Button invite target is invalid or expired".into(),
                    ));
                }
            }
            ButtonAction::ExternalUrl { .. } => {}
        }
    }

    Ok(())
}

pub async fn validate_server_targets_for_user(
    state: &crate::state::AppState,
    server_id: i64,
    announcement: &Announcement,
    user_id: i64,
) -> Result<(), crate::error::AppError> {
    validate_server_targets(state, server_id, announcement).await?;

    for section in &announcement.sections {
        let AnnouncementSection::Button {
            action: ButtonAction::NavigateChannel { channel_id },
            ..
        } = section
        else {
            continue;
        };
        let target_channel_id = channel_id
            .parse::<i64>()
            .map_err(|_| crate::error::AppError::Validation("Invalid channel ID".into()))?;
        match state
            .permissions
            .check_channel_permission(
                user_id,
                target_channel_id,
                server_id,
                crate::services::permissions::bits::VIEW_CHANNEL,
            )
            .await
        {
            Ok(()) => {}
            Err(crate::error::AppError::Internal) => return Err(crate::error::AppError::Internal),
            Err(_) => {
                return Err(crate::error::AppError::Validation(
                    "Button channel target must be visible to the poster".into(),
                ));
            }
        }
    }

    Ok(())
}

pub async fn validate_server_targets_for_bot(
    state: &crate::state::AppState,
    server_id: i64,
    announcement: &Announcement,
    bot: &crate::middleware::auth::BotIdentity,
) -> Result<(), crate::error::AppError> {
    validate_server_targets(state, server_id, announcement).await?;
    if bot.server_id != server_id {
        return Err(crate::error::AppError::Validation(
            "Button channel target must belong to this server".into(),
        ));
    }

    for section in &announcement.sections {
        let AnnouncementSection::Button {
            action: ButtonAction::NavigateChannel { channel_id },
            ..
        } = section
        else {
            continue;
        };
        let target_channel_id = channel_id
            .parse::<i64>()
            .map_err(|_| crate::error::AppError::Validation("Invalid channel ID".into()))?;
        let allowed = crate::services::bot_permissions::has_channel_permission(
            state,
            bot,
            target_channel_id,
            crate::services::permissions::bits::VIEW_CHANNEL,
        )
        .await?;
        if !allowed {
            return Err(crate::error::AppError::Validation(
                "Button channel target must be visible to the bot".into(),
            ));
        }
    }

    Ok(())
}

async fn validate_button_action(action: &ButtonAction) -> Result<(), String> {
    match action {
        ButtonAction::NavigateChannel { channel_id } => {
            // Validate snowflake ID format
            if channel_id.is_empty()
                || channel_id.len() > 20
                || !channel_id.chars().all(|c| c.is_ascii_digit())
            {
                return Err("Invalid channel ID".to_string());
            }
            Ok(())
        }
        ButtonAction::Invite { code } => {
            if code.is_empty()
                || code.len() > 32
                || !code.chars().all(|c| c.is_ascii_alphanumeric())
            {
                return Err("Invalid invite code".to_string());
            }
            Ok(())
        }
        ButtonAction::ExternalUrl { url } => {
            // Full URL safety validation including Google Safe Browsing
            url_safety::validate_announcement_url(url).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigate_channel_action_uses_client_camel_case() {
        let action: ButtonAction = serde_json::from_value(serde_json::json!({
            "type": "navigateChannel",
            "channelId": "1234567890"
        }))
        .unwrap();

        match &action {
            ButtonAction::NavigateChannel { channel_id } => {
                assert_eq!(channel_id, "1234567890");
            }
            _ => panic!("expected navigateChannel action"),
        }

        assert_eq!(
            serde_json::to_value(action).unwrap(),
            serde_json::json!({
                "type": "navigateChannel",
                "channelId": "1234567890"
            })
        );
    }

    #[test]
    fn navigate_channel_action_accepts_legacy_snake_case() {
        let action: ButtonAction = serde_json::from_value(serde_json::json!({
            "type": "navigateChannel",
            "channel_id": "1234567890"
        }))
        .unwrap();

        match action {
            ButtonAction::NavigateChannel { channel_id } => {
                assert_eq!(channel_id, "1234567890");
            }
            _ => panic!("expected navigateChannel action"),
        }
    }

    #[tokio::test]
    async fn validate_allows_current_cdn_image_host() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: Some("#22c55e".to_string()),
            sections: vec![AnnouncementSection::Image {
                url: "https://cdn.pryzmapp.com/uploads/release.png".to_string(),
                alt: None,
            }],
            footer: None,
            footer_style: None,
        };

        validate(&announcement).await.unwrap();
    }

    #[tokio::test]
    async fn validate_text_section_color() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Text {
                content: "Rollout complete".to_string(),
                color: Some("#22c55e".to_string()),
                style: None,
            }],
            footer: None,
            footer_style: None,
        };

        validate(&announcement).await.unwrap();
    }

    #[test]
    fn sanitize_preserves_rich_text_span_boundary_spaces() {
        let mut announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::RichText {
                spans: vec![
                    RichTextSpan {
                        text: "Status: ".to_string(),
                        style: None,
                    },
                    RichTextSpan {
                        text: "<b>live</b>".to_string(),
                        style: Some(TextStyle {
                            color: Some("#22c55e".to_string()),
                            size: None,
                            font_size: None,
                            weight: Some(TextWeight::Bold),
                            italic: None,
                            strikethrough: None,
                        }),
                    },
                    RichTextSpan {
                        text: " with safe spacing".to_string(),
                        style: None,
                    },
                ],
                style: None,
            }],
            footer: None,
            footer_style: None,
        };

        sanitize(&mut announcement);

        let AnnouncementSection::RichText { spans, .. } = &announcement.sections[0] else {
            panic!("expected rich text section");
        };
        let joined = spans
            .iter()
            .map(|span| span.text.as_str())
            .collect::<String>();
        assert_eq!(joined, "Status: live with safe spacing");
        assert_eq!(spans[0].text, "Status: ");
        assert_eq!(spans[1].text, "live");
        assert_eq!(spans[2].text, " with safe spacing");
    }

    #[tokio::test]
    async fn validate_rejects_bad_text_section_color() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Text {
                content: "Rollout complete".to_string(),
                color: Some("green".to_string()),
                style: None,
            }],
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_non_cdn_image_hosts() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Image {
                url: "https://media.klipy.com/release.png".to_string(),
                alt: None,
            }],
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_private_or_active_cdn_image_paths() {
        for url in [
            "https://cdn.verdant.chat/attachments/123/456.webp",
            "https://cdn.verdant.chat/%61ttachments/123/456.webp",
            "https://cdn.verdant.chat/attach%6dents/123/456.webp",
            "https://cdn.verdant.chat/%2561ttachments/123/456.webp",
            "https://cdn.verdant.chat/api/media/%61ttachments/456.webp",
            "https://cdn.verdant.chat/cdn-cgi/image/width=640/attachments/123/456.webp",
            "https://cdn.verdant.chat/cdn-cgi%252fimage/width=640/uploads/release.png",
            "https://cdn.verdant.chat/uploads/%2e%2e/attachments/456.webp",
            "https://cdn.verdant.chat/uploads/%252e%252e/public/456.webp",
            "https://cdn.verdant.chat/uploads/%252fattachments/456.webp",
            "https://cdn.verdant.chat/uploads/release.svg",
            "https://cdn.verdant.chat/uploads/release.svgz",
            "https://user:pass@cdn.verdant.chat/uploads/release.png",
            "https://cdn.verdant.chat/uploads/release.png#fragment",
        ] {
            let announcement = Announcement {
                title: "Release".to_string(),
                title_style: None,
                description: None,
                description_style: None,
                color: None,
                sections: vec![AnnouncementSection::Image {
                    url: url.to_string(),
                    alt: None,
                }],
                footer: None,
                footer_style: None,
            };

            assert!(
                validate(&announcement).await.is_err(),
                "expected image URL to be rejected: {url}"
            );
        }
    }

    #[tokio::test]
    async fn validate_rejects_local_text_links() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: Some("Open http://127.0.0.1:8080/admin".to_string()),
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_accepts_safe_text_links() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: Some("Open https://verdant.chat.".to_string()),
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        validate(&announcement).await.unwrap();
    }

    #[tokio::test]
    async fn validate_allows_component_sections_and_styles() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: Some(TextStyle {
                color: Some("#22c55e".to_string()),
                size: Some(TextSize::Lg),
                font_size: Some(18.5),
                weight: Some(TextWeight::Bold),
                italic: None,
                strikethrough: None,
            }),
            description: Some("[green]{color=#22c55e weight=bold}".to_string()),
            description_style: Some(TextStyle {
                color: Some("#d1d5db".to_string()),
                size: Some(TextSize::Md),
                font_size: None,
                weight: None,
                italic: None,
                strikethrough: None,
            }),
            color: Some("#22c55e".to_string()),
            sections: vec![
                AnnouncementSection::Heading {
                    content: "Summary".to_string(),
                    level: Some(2),
                    style: Some(TextStyle {
                        color: Some("#a855f7".to_string()),
                        size: Some(TextSize::Xl),
                        font_size: None,
                        weight: Some(TextWeight::Semibold),
                        italic: None,
                        strikethrough: None,
                    }),
                },
                AnnouncementSection::Quote {
                    content: "Styled quote".to_string(),
                    style: Some(TextStyle {
                        color: Some("#f59e0b".to_string()),
                        size: Some(TextSize::Sm),
                        font_size: None,
                        weight: None,
                        italic: None,
                        strikethrough: None,
                    }),
                },
                AnnouncementSection::List {
                    items: vec!["One".to_string(), "[Two]{color=#22c55e}".to_string()],
                    ordered: Some(false),
                    style: Some(TextStyle {
                        color: Some("#d1d5db".to_string()),
                        size: Some(TextSize::Md),
                        font_size: None,
                        weight: None,
                        italic: None,
                        strikethrough: None,
                    }),
                },
                AnnouncementSection::Table {
                    columns: vec!["Component".to_string(), "Result".to_string()],
                    rows: vec![vec!["Table".to_string(), "Rendered".to_string()]],
                    style: None,
                    header_style: Some(TextStyle {
                        color: Some("#22c55e".to_string()),
                        size: Some(TextSize::Xs),
                        font_size: None,
                        weight: Some(TextWeight::Bold),
                        italic: None,
                        strikethrough: None,
                    }),
                    cell_style: Some(TextStyle {
                        color: Some("#d1d5db".to_string()),
                        size: Some(TextSize::Sm),
                        font_size: None,
                        weight: None,
                        italic: None,
                        strikethrough: None,
                    }),
                },
                AnnouncementSection::Code {
                    content: "card().title(\"Hello\")".to_string(),
                    language: Some("ts".to_string()),
                },
                AnnouncementSection::RichText {
                    spans: vec![
                        RichTextSpan {
                            text: "Important ".to_string(),
                            style: Some(TextStyle {
                                color: None,
                                size: None,
                                font_size: None,
                                weight: Some(TextWeight::Bold),
                                italic: None,
                                strikethrough: None,
                            }),
                        },
                        RichTextSpan {
                            text: "notice".to_string(),
                            style: Some(TextStyle {
                                color: Some("#ff005b".to_string()),
                                size: None,
                                font_size: Some(16.0),
                                weight: None,
                                italic: None,
                                strikethrough: None,
                            }),
                        },
                    ],
                    style: None,
                },
                AnnouncementSection::Button {
                    label: "Open Channel".to_string(),
                    style: Some(ButtonStyle::Primary),
                    colors: Some(ButtonColors {
                        background: Some("#14b8a6".to_string()),
                        text: Some("#ffffff".to_string()),
                        border: Some("#2dd4bf".to_string()),
                    }),
                    action: ButtonAction::NavigateChannel {
                        channel_id: "1234567890".to_string(),
                    },
                },
            ],
            footer: Some("Footer".to_string()),
            footer_style: Some(TextStyle {
                color: Some("#9ca3af".to_string()),
                size: Some(TextSize::Xs),
                font_size: None,
                weight: None,
                italic: None,
                strikethrough: None,
            }),
        };

        validate(&announcement).await.unwrap();
    }

    #[tokio::test]
    async fn validate_rejects_bad_component_style_color() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: Some(TextStyle {
                color: Some("green".to_string()),
                size: None,
                font_size: None,
                weight: None,
                italic: None,
                strikethrough: None,
            }),
            description: None,
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_out_of_range_font_size() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: Some(TextStyle {
                color: None,
                size: None,
                font_size: Some(96.0),
                weight: None,
                italic: None,
                strikethrough: None,
            }),
            description: None,
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_bad_rich_text_span_style() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::RichText {
                spans: vec![RichTextSpan {
                    text: "Unsafe".to_string(),
                    style: Some(TextStyle {
                        color: Some("red".to_string()),
                        size: None,
                        font_size: None,
                        weight: None,
                        italic: None,
                        strikethrough: None,
                    }),
                }],
                style: None,
            }],
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_rich_text_span_fields() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "sections": [{
                "type": "richText",
                "spans": [{
                    "text": "hello",
                    "onclick": "alert(1)"
                }]
            }]
        }));

        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_accepts_inline_rich_text_decoration_flags() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "sections": [{
                "type": "richText",
                "spans": [{
                    "text": "Decorated",
                    "style": {
                        "weight": "bold",
                        "italic": true,
                        "strikethrough": true
                    }
                }]
            }]
        }))
        .unwrap();

        let Some(AnnouncementSection::RichText { spans, .. }) = parsed.sections.first() else {
            panic!("expected rich text section");
        };
        let style = spans.first().and_then(|span| span.style.as_ref()).unwrap();
        assert_eq!(style.italic, Some(true));
        assert_eq!(style.strikethrough, Some(true));
    }

    #[test]
    fn deserialize_rejects_unknown_top_level_fields() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "script": "alert(1)"
        }));

        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_section_fields() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "sections": [{
                "type": "text",
                "content": "hello",
                "onclick": "alert(1)"
            }]
        }));

        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_section_type() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "sections": [{
                "type": "poll",
                "question": "Nope"
            }]
        }));

        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_accepts_video_and_legacy_youtube_section_types() {
        for section_type in ["video", "youtube"] {
            let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
                "title": "Release",
                "sections": [{
                    "type": section_type,
                    "url": "https://www.youtube.com/watch?v=k1_ODDevbY8",
                    "videoId": "k1_ODDevbY8"
                }]
            }))
            .unwrap();

            assert!(matches!(
                parsed.sections.first(),
                Some(AnnouncementSection::Youtube { video_id, .. })
                    if video_id == "k1_ODDevbY8"
            ));
        }
    }

    #[test]
    fn deserialize_rejects_unknown_button_action_fields() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "sections": [{
                "type": "button",
                "label": "Open",
                "action": {
                    "type": "navigateChannel",
                    "channelId": "1234567890",
                    "target": "_blank"
                }
            }]
        }));

        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_button_action_type() {
        let parsed = serde_json::from_value::<Announcement>(serde_json::json!({
            "title": "Release",
            "sections": [{
                "type": "button",
                "label": "Open",
                "action": {
                    "type": "openShell",
                    "command": "calc.exe"
                }
            }]
        }));

        assert!(parsed.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_unknown_inline_style_key() {
        let announcement = Announcement {
            title: "[Release]{onclick=alert(1)}".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_ignores_escaped_inline_style_tokens() {
        let announcement = Announcement {
            title: r"\[Release\]{onclick=alert\(1\)}".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        validate(&announcement).await.unwrap();
    }

    #[tokio::test]
    async fn validate_allows_postfix_inline_style_tokens() {
        let announcement = Announcement {
            title: "Deploy passed[textColor: #22c55e weight=bold]".to_string(),
            title_style: None,
            description: Some("I want THIS[textColor: #a855f7] to only change.".to_string()),
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Table {
                columns: vec!["Check".to_string(), "Result".to_string()],
                rows: vec![vec![
                    "Rollout".to_string(),
                    "healthy[textColor: #22c55e weight=bold]".to_string(),
                ]],
                style: None,
                header_style: None,
                cell_style: None,
            }],
            footer: None,
            footer_style: None,
        };

        validate(&announcement).await.unwrap();
    }

    #[tokio::test]
    async fn validate_accepts_constrained_chart_and_youtube_sections() {
        let announcement = Announcement {
            title: "Launch report".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: Some("#1ee3b6".to_string()),
            sections: vec![
                AnnouncementSection::Chart {
                    title: Some("Reader split".to_string()),
                    kind: ChartKind::Donut,
                    points: vec![
                        ChartPoint {
                            label: "Desktop".to_string(),
                            value: 58.0,
                        },
                        ChartPoint {
                            label: "Mobile".to_string(),
                            value: 24.0,
                        },
                    ],
                },
                AnnouncementSection::Youtube {
                    url: "https://www.youtube.com/watch?v=k1_ODDevbY8".to_string(),
                    video_id: "k1_ODDevbY8".to_string(),
                    title: Some("Walkthrough".to_string()),
                },
            ],
            footer: None,
            footer_style: None,
        };

        validate(&announcement).await.unwrap();
    }

    #[tokio::test]
    async fn validate_rejects_untrusted_youtube_section_routes() {
        let announcement = Announcement {
            title: "Launch report".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Youtube {
                url: "https://example.com/watch?v=k1_ODDevbY8".to_string(),
                video_id: "k1_ODDevbY8".to_string(),
                title: None,
            }],
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());

        let announcement = Announcement {
            title: "Launch report".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Youtube {
                url: "https://www.youtube.com/watch?v=k1_ODDevbY8".to_string(),
                video_id: "otherVideo".to_string(),
                title: None,
            }],
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_unbounded_chart_sections() {
        let announcement = Announcement {
            title: "Launch report".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Chart {
                title: Some("Too much".to_string()),
                kind: ChartKind::Bar,
                points: (0..25)
                    .map(|index| ChartPoint {
                        label: format!("Point {index}"),
                        value: index as f64,
                    })
                    .collect(),
            }],
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_bad_postfix_inline_style_tokens() {
        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: Some("I want THIS[textColor: red] to only change.".to_string()),
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());

        let announcement = Announcement {
            title: "Release".to_string(),
            title_style: None,
            description: Some("I want THIS[onclick=alert] to only change.".to_string()),
            description_style: None,
            color: None,
            sections: Vec::new(),
            footer: None,
            footer_style: None,
        };

        assert!(validate(&announcement).await.is_err());
    }

    #[test]
    fn sanitize_strips_html_from_alt_and_button_label() {
        let mut announcement = Announcement {
            title: "<b>Release</b>".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![
                AnnouncementSection::Image {
                    url: "https://cdn.pryzmapp.com/uploads/release.png".to_string(),
                    alt: Some("<img src=x onerror=alert(1)>badge".to_string()),
                },
                AnnouncementSection::Button {
                    label: "<b>Open</b>".to_string(),
                    style: None,
                    colors: None,
                    action: ButtonAction::NavigateChannel {
                        channel_id: "1234567890".to_string(),
                    },
                },
            ],
            footer: None,
            footer_style: None,
        };

        sanitize(&mut announcement);

        assert_eq!(announcement.title, "Release");
        match &announcement.sections[0] {
            AnnouncementSection::Image { alt, .. } => {
                assert_eq!(alt.as_deref(), Some("badge"));
            }
            _ => panic!("expected image"),
        }
        match &announcement.sections[1] {
            AnnouncementSection::Button { label, .. } => {
                assert_eq!(label, "Open");
            }
            _ => panic!("expected button"),
        }
    }

    #[test]
    fn sanitize_preserves_code_punctuation() {
        let mut announcement = Announcement {
            title: "Code".to_string(),
            title_style: None,
            description: None,
            description_style: None,
            color: None,
            sections: vec![AnnouncementSection::Code {
                content: "socket.onopen = () => socket.send('<ready>');".to_string(),
                language: Some("ts".to_string()),
            }],
            footer: None,
            footer_style: None,
        };

        sanitize(&mut announcement);

        match &announcement.sections[0] {
            AnnouncementSection::Code { content, .. } => {
                assert_eq!(content, "socket.onopen = () => socket.send('<ready>');");
            }
            _ => panic!("expected code"),
        }
    }
}
