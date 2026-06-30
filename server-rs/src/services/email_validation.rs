use crate::error::{AppError, AppResult};

pub fn normalize_routable_email(input: &str) -> AppResult<String> {
    let email = input.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 254 || !email.is_ascii() {
        return Err(AppError::Validation(
            "Please enter a valid email address".into(),
        ));
    }

    let Some((local, domain)) = email.rsplit_once('@') else {
        return Err(AppError::Validation(
            "Please enter a valid email address".into(),
        ));
    };
    if local.is_empty() || local.len() > 64 || domain.is_empty() {
        return Err(AppError::Validation(
            "Please enter a valid email address".into(),
        ));
    }
    if domain.ends_with('.')
        || !domain.contains('.')
        || domain.split('.').any(str::is_empty)
        || domain.contains("..")
    {
        return Err(AppError::Validation(
            "Please enter a real email address".into(),
        ));
    }

    let tld = domain.rsplit('.').next().unwrap_or_default();
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(AppError::Validation(
            "Please enter a real email address".into(),
        ));
    }

    let reserved_domain = matches!(
        domain,
        "example.com" | "example.net" | "example.org" | "localhost"
    ) || domain.ends_with(".example")
        || domain.ends_with(".invalid")
        || domain.ends_with(".localhost")
        || domain.ends_with(".test")
        || domain.ends_with(".local");
    if reserved_domain {
        return Err(AppError::Validation(
            "Please enter a real email address".into(),
        ));
    }

    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::normalize_routable_email;

    #[test]
    fn accepts_normal_routable_email_shape() {
        assert_eq!(
            normalize_routable_email("Josh+launch@Gmail.com").unwrap(),
            "josh+launch@gmail.com"
        );
    }

    #[test]
    fn rejects_reserved_and_non_routable_domains() {
        for email in [
            "user@example.com",
            "user@localhost",
            "user@site.test",
            "user@site.invalid",
            "user@site.local",
            "user@nodot",
            "user@domain.c",
        ] {
            assert!(normalize_routable_email(email).is_err(), "{email}");
        }
    }

    #[test]
    fn rejects_non_ascii_email() {
        assert!(normalize_routable_email("jos\u{00e9}@example.dev").is_err());
    }
}
