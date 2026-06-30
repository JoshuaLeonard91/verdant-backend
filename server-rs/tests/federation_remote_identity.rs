use verdant_server::federation::identity::{RemotePrincipalMetadata, remote_principal_projection};

#[test]
fn remote_principal_projection_is_deterministic_and_non_secret() {
    let first = remote_principal_projection("host:a.example", "remote-user-1")
        .expect("projection should be valid");
    let second = remote_principal_projection("host:a.example", "remote-user-1")
        .expect("projection should be stable");

    assert_eq!(first, second);
    assert!(first.username.starts_with("fed_"));
    assert!(first.email.ends_with("@federation.invalid"));
    assert_eq!(
        first.password_hash,
        "!federation-remote-principal-disabled!"
    );
    assert!(!first.username.contains("remote-user-1"));
    assert!(!first.email.contains("remote-user-1"));
}

#[test]
fn remote_principal_projection_rejects_unsafe_ids() {
    assert!(remote_principal_projection("", "remote-user-1").is_err());
    assert!(remote_principal_projection("host:a.example", "").is_err());
    assert!(remote_principal_projection("host:a.example\n", "remote-user-1").is_err());
    assert!(remote_principal_projection("host:a.example", "remote user").is_err());
}

#[test]
fn remote_principal_metadata_validates_public_profile_fields() {
    let metadata = RemotePrincipalMetadata::new(
        Some("remote_user"),
        Some("Remote User"),
        Some("https://cdn.example/avatar.png"),
    )
    .expect("metadata should be accepted");

    assert_eq!(metadata.username.as_deref(), Some("remote_user"));
    assert_eq!(metadata.display_name.as_deref(), Some("Remote User"));
    assert_eq!(
        metadata.avatar_url.as_deref(),
        Some("https://cdn.example/avatar.png")
    );

    assert!(RemotePrincipalMetadata::new(Some("bad user"), None, None).is_err());
    assert!(RemotePrincipalMetadata::new(None, Some(&"x".repeat(121)), None).is_err());
    assert!(RemotePrincipalMetadata::new(None, None, Some("file:///secret")).is_err());
}

#[test]
fn remote_principal_metadata_rejects_private_or_secret_bearing_avatar_urls() {
    for avatar_url in [
        "https://user:pass@cdn.example/avatar.png",
        "https://cdn.example/avatar.png?token=secret",
        "https://127.0.0.1/avatar.png",
        "http://localhost/avatar.png",
        "https://cdn.example/attachments/private-object-key.png",
    ] {
        assert!(
            RemotePrincipalMetadata::new(None, None, Some(avatar_url)).is_err(),
            "unsafe avatar URL should fail: {avatar_url}"
        );
    }
}
