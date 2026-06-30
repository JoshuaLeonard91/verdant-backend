use ammonia::Builder;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Pre-built ammonia sanitizer that strips ALL HTML tags (reused across calls).
static STRIP_HTML: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut b = Builder::new();
    b.tags(HashSet::new());
    b
});

/// Strip ALL HTML tags from input, preserving only text content.
pub fn strip_html(input: &str) -> String {
    STRIP_HTML.clean(input).to_string()
}

/// Strip dangerous Unicode control characters that can be used for phishing
/// (e.g., RTL override to disguise URLs, zero-width chars for invisible text).
fn strip_bidi_and_invisible(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            !matches!(
                *c,
                // Zero-width and invisible formatting
                '\u{200B}'..='\u{200F}' |
                // Bidi overrides and embeddings
                '\u{202A}'..='\u{202E}' |
                // Bidi isolates
                '\u{2066}'..='\u{2069}'
            )
        })
        .collect()
}

/// Trim whitespace, strip HTML tags, and remove dangerous Unicode control characters.
pub fn sanitize_text(input: &str) -> String {
    strip_bidi_and_invisible(&strip_html(input.trim()))
}

/// Strip HTML tags and dangerous Unicode controls without trimming edge
/// whitespace. Structured rich-text spans use leading/trailing spaces as
/// visible boundaries between styled runs.
pub fn sanitize_text_preserve_edges(input: &str) -> String {
    strip_bidi_and_invisible(&strip_html(input))
}

/// Message text supports stable role mention tokens of the form `@&<role_id>`.
/// Ammonia strips tags correctly, but serializes raw ampersands as `&amp;`.
/// Restore only that narrow token shape after sanitization so role mentions stay
/// machine-readable without allowing arbitrary HTML through.
pub fn sanitize_message_content(input: &str) -> String {
    restore_role_mention_tokens(&sanitize_text(input))
}

fn restore_role_mention_tokens(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(idx) = rest.find("@&amp;") {
        output.push_str(&rest[..idx]);
        let candidate = &rest[idx + "@&amp;".len()..];
        let digit_len = candidate
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .map(char::len_utf8)
            .sum::<usize>();

        if (1..=20).contains(&digit_len) {
            let after_digits = &candidate[digit_len..];
            let next_is_word = after_digits
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
            if !next_is_word {
                output.push_str("@&");
                output.push_str(&candidate[..digit_len]);
                rest = after_digits;
                continue;
            }
        }

        output.push_str("@&amp;");
        rest = candidate;
    }

    output.push_str(rest);
    output
}

/// Trim code text and remove dangerous invisible/bidi controls without HTML-escaping
/// code punctuation. Code blocks are rendered as React text children, not HTML.
pub fn sanitize_code_text(input: &str) -> String {
    strip_bidi_and_invisible(input.trim())
}

#[cfg(test)]
mod tests {
    use super::{sanitize_message_content, sanitize_text, sanitize_text_preserve_edges};

    #[test]
    fn sanitize_text_strips_html_and_escapes_ampersands() {
        assert_eq!(sanitize_text("<b>hi</b> @&123"), "hi @&amp;123");
    }

    #[test]
    fn sanitize_message_content_preserves_role_mention_markers() {
        assert_eq!(sanitize_message_content("<b>hi</b> @&123"), "hi @&123");
        assert_eq!(sanitize_message_content("@&123abc"), "@&amp;123abc");
        assert_eq!(sanitize_message_content("@&"), "@&amp;");
    }

    #[test]
    fn sanitize_text_preserve_edges_keeps_rich_span_boundaries() {
        assert_eq!(sanitize_text_preserve_edges(" <b>live</b> "), " live ");
    }
}
