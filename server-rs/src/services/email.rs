use serde_json::json;

/// Email service using the Resend API.
#[derive(Clone)]
pub struct EmailService {
    api_key: String,
    from_address: String,
    frontend_url: String,
    client: reqwest::Client,
}

impl EmailService {
    /// Create a new email service. Returns None if config is missing.
    pub fn from_config(
        api_key: Option<&str>,
        from_address: Option<&str>,
        frontend_url: Option<&str>,
    ) -> Option<Self> {
        let api_key = api_key?;
        let from_address = from_address?;
        let frontend_url = frontend_url.unwrap_or("http://localhost:5173");

        Some(Self {
            api_key: api_key.to_string(),
            from_address: from_address.to_string(),
            frontend_url: frontend_url.to_string(),
            client: reqwest::Client::new(),
        })
    }

    /// Send an email via the Resend API.
    async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), String> {
        let resp = self
            .client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&json!({
                "from": self.from_address,
                "to": [to],
                "subject": subject,
                "html": html,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Resend API error: {body}"));
        }

        Ok(())
    }

    /// Send a password reset email.
    pub async fn send_password_reset(&self, to: &str, token: &str) -> Result<(), String> {
        let reset_url = format!(
            "{}/reset-password?token={}",
            self.frontend_url.trim_end_matches('/'),
            urlencoding::encode(token),
        );

        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Password Reset</h2>
  <p>You requested a password reset for your Verdant account.</p>
  <p>Click the button below to reset your password. This link expires in 30 minutes.</p>
  <p style="margin: 24px 0;">
    <a href="{reset_url}" style="background: #7c3aed; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; display: inline-block;">
      Reset Password
    </a>
  </p>
  <p style="color: #888; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
</div>"#,
        );

        self.send(to, "Reset your Verdant password", &html).await
    }

    /// Send a login notification email.
    pub async fn send_login_notification(
        &self,
        to: &str,
        device: &str,
        location: &str,
        revoke_url: Option<&str>,
    ) -> Result<(), String> {
        let revoke_section = if let Some(url) = revoke_url {
            format!(
                r#"<p>If this wasn't you, <a href="{url}" style="color: #7c3aed;">revoke this session immediately</a>.</p>"#,
            )
        } else {
            String::new()
        };

        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>New Login Detected</h2>
  <p>A new login to your Verdant account was detected:</p>
  <ul>
    <li><strong>Device:</strong> {device}</li>
    <li><strong>Location:</strong> {location}</li>
  </ul>
  {revoke_section}
  <p style="color: #888; font-size: 14px;">This is an automated notification for your security.</p>
</div>"#,
        );

        self.send(to, "New login to your Verdant account", &html)
            .await
    }

    /// Send a high-risk login verification email.
    pub async fn send_login_verification(&self, to: &str, code: &str) -> Result<(), String> {
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Verify Your Login</h2>
  <p>A login attempt was made from an unrecognized location.</p>
  <p>Your verification code is:</p>
  <p style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; margin: 24px 0; color: #7c3aed;">
    {code}
  </p>
  <p style="color: #888; font-size: 14px;">This code expires in 10 minutes. If you didn't attempt to log in, change your password immediately.</p>
</div>"#,
        );

        self.send(to, "Verify your Verdant login", &html).await
    }

    /// Send an email change verification code to the current email.
    pub async fn send_email_change_verification(
        &self,
        to: &str,
        code: &str,
        new_email: &str,
    ) -> Result<(), String> {
        // Mask the new email for display: show first 2 chars + domain
        let masked_new = match new_email.split_once('@') {
            Some((local, domain)) => {
                let visible = local.len().min(2);
                format!(
                    "{}{}@{}",
                    &local[..visible],
                    "*".repeat(local.len().saturating_sub(visible)),
                    domain
                )
            }
            None => "***".to_string(),
        };

        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Confirm Email Change</h2>
  <p>A request was made to change your Verdant email address to <strong>{masked_new}</strong>.</p>
  <p>Your verification code is:</p>
  <p style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; margin: 24px 0; color: #7c3aed;">
    {code}
  </p>
  <p style="color: #888; font-size: 14px;">This code expires in 10 minutes. If you didn't request this change, change your password immediately.</p>
</div>"#,
        );

        self.send(to, "Confirm your Verdant email change", &html)
            .await
    }

    /// Send an email verification link for new signups.
    pub async fn send_email_verification(&self, to: &str, token: &str) -> Result<(), String> {
        let verify_url = format!(
            "{}/verify-email?token={}",
            self.frontend_url.trim_end_matches('/'),
            urlencoding::encode(token),
        );

        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Verify Your Email</h2>
  <p>Thanks for signing up for Verdant! Please verify your email address to get started.</p>
  <p style="margin: 24px 0;">
    <a href="{verify_url}" style="background: #7c3aed; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; display: inline-block;">
      Verify Email
    </a>
  </p>
  <p style="color: #888; font-size: 14px;">This link expires in 24 hours. If you didn't create an account, you can safely ignore this email.</p>
</div>"#,
        );

        self.send(to, "Verify your Verdant email", &html).await
    }
}
