use rustrict::CensorStr;

/// Reserved usernames that cannot be claimed by users.
/// Includes system terms, URL route collisions, and impersonation targets.
const RESERVED_NAMES: &[&str] = &[
    // System / platform
    "admin",
    "administrator",
    "mod",
    "moderator",
    "staff",
    "system",
    "bot",
    "webhook",
    "everyone",
    "here",
    "verdant",
    "yappy",
    // URL route collisions
    "api",
    "auth",
    "login",
    "register",
    "logout",
    "settings",
    "invite",
    "app",
    "oauth",
    "callback",
    "health",
    "metrics",
    "ws",
    "wss",
    "cdn",
    "assets",
    "static",
    "public",
    // Common impersonation targets
    "support",
    "help",
    "info",
    "security",
    "abuse",
    "root",
    "null",
    "undefined",
    "deleted",
    "unknown",
];

/// Validate a username for safety: reserved names, profanity, and confusable characters.
///
/// Returns `Ok(())` if the username is safe, or `Err(reason)` with a user-facing message.
pub fn check_username(username: &str) -> Result<(), &'static str> {
    // Normalize with decancer to catch homoglyphs and confusables
    let cured = match decancer::cure!(username) {
        Ok(output) => String::from(output),
        Err(_) => username.to_string(),
    };
    let normalized = cured.to_ascii_lowercase();

    // Check against reserved names (using normalized form)
    if RESERVED_NAMES.contains(&normalized.as_str()) {
        return Err("This username is reserved");
    }

    // Check for profanity using rustrict (on normalized form)
    if normalized.is_inappropriate() {
        return Err("This username contains inappropriate language");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_normal_usernames() {
        assert!(check_username("alice").is_ok());
        assert!(check_username("bob_123").is_ok());
        assert!(check_username("Player42").is_ok());
    }

    #[test]
    fn blocks_reserved_names() {
        assert!(check_username("admin").is_err());
        assert!(check_username("Admin").is_err());
        assert!(check_username("SYSTEM").is_err());
        assert!(check_username("verdant").is_err());
    }

    #[test]
    fn blocks_homoglyph_reserved() {
        // Cyrillic "а" instead of Latin "a" in "admin"
        assert!(check_username("аdmin").is_err());
    }
}
