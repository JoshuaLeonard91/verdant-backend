use aws_config::Region;
use aws_sdk_s3::{
    Client,
    config::{Credentials, SharedCredentialsProvider},
    presigning::PresigningConfig,
    primitives::ByteStream,
};
use std::time::Duration;

/// S3-compatible storage client (Cloudflare R2 / DigitalOcean Spaces).
#[derive(Clone)]
pub struct S3Service {
    client: Client,
    bucket: String,
}

impl S3Service {
    /// Create a new S3 service from config values.
    /// Returns None if any required config is missing.
    pub fn from_config(
        endpoint: Option<&str>,
        bucket: Option<&str>,
        key: Option<&str>,
        secret: Option<&str>,
        path_style: bool,
    ) -> Option<Self> {
        let endpoint = endpoint?;
        let bucket = bucket?;
        let key = key?;
        let secret = secret?;

        let creds = Credentials::new(key, secret, None, None, "verdant-env");

        let config = aws_sdk_s3::Config::builder()
            .endpoint_url(endpoint)
            .region(Region::new("auto"))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .force_path_style(path_style)
            .behavior_version_latest()
            .build();

        let client = Client::from_conf(config);

        Some(Self {
            client,
            bucket: bucket.to_string(),
        })
    }

    /// Upload an object to S3.
    pub async fn put_object(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), String> {
        // Derive safe filename from key (last path segment).
        // Escape quotes/backslashes per RFC 6266 to prevent header injection.
        let filename = key.rsplit('/').next().unwrap_or("file");
        let safe = filename.replace('\\', "\\\\").replace('"', "\\\"");
        let disposition = format!("inline; filename=\"{safe}\"");

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type(content_type)
            .content_disposition(&disposition)
            .cache_control("public, max-age=31536000, immutable")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Upload an object to evidence storage (no cache headers, no public access).
    /// The evidence bucket has no custom domain = private by default.
    ///
    /// # Evidence containment strategy
    /// - Separate bucket (`verdant-evidence`) with no custom domain
    /// - Access only via [`presigned_get_url`] with short TTL (recommended: 5 min)
    /// - Admin dashboard generates presigned URLs on demand for review
    /// - Configure a lifecycle rule to auto-expire after legal retention period
    pub async fn put_object_private(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), String> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Fetch an object's raw bytes from S3.
    pub async fn get_object_bytes(&self, key: &str) -> Result<Vec<u8>, String> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .into_bytes();

        Ok(bytes.to_vec())
    }

    /// Delete an object from S3 (best-effort).
    pub async fn delete_object(&self, key: &str) -> Result<(), String> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Generate a presigned GET URL (for downloads).
    pub async fn presigned_get_url(&self, key: &str, expires_secs: u64) -> Result<String, String> {
        self.presigned_get_url_with_response_headers(key, expires_secs, None, None)
            .await
    }

    /// Generate a presigned GET URL with optional response header overrides.
    pub async fn presigned_get_url_with_response_headers(
        &self,
        key: &str,
        expires_secs: u64,
        response_content_type: Option<&str>,
        response_content_disposition: Option<&str>,
    ) -> Result<String, String> {
        let presigning = PresigningConfig::builder()
            .expires_in(Duration::from_secs(expires_secs))
            .build()
            .map_err(|e| e.to_string())?;

        let mut builder = self.client.get_object().bucket(&self.bucket).key(key);

        if let Some(content_type) = response_content_type {
            builder = builder.response_content_type(content_type);
        }

        if let Some(content_disposition) = response_content_disposition {
            builder = builder.response_content_disposition(content_disposition);
        }

        let req = builder
            .presigned(presigning)
            .await
            .map_err(|e| e.to_string())?;

        Ok(req.uri().to_string())
    }

    /// Generate a presigned PUT URL (for client-side uploads).
    pub async fn presigned_put_url(
        &self,
        key: &str,
        content_type: &str,
        expires_secs: u64,
    ) -> Result<String, String> {
        let presigning = PresigningConfig::builder()
            .expires_in(Duration::from_secs(expires_secs))
            .build()
            .map_err(|e| e.to_string())?;

        let req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .presigned(presigning)
            .await
            .map_err(|e| e.to_string())?;

        Ok(req.uri().to_string())
    }

    /// Fetch an object's contents as a UTF-8 string.
    pub async fn get_object_text(&self, key: &str) -> Result<String, String> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .into_bytes();

        String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}
