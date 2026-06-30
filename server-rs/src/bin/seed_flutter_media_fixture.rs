use std::{env, net::IpAddr, process, time::Duration};

use fred::prelude::*;
use sqlx::{PgPool, Row};
use url::{Host, Url};
use verdant_server::{
    services::{crypto, pg, s3::S3Service},
    snowflake::SnowflakeGenerator,
};

const DEFAULT_MESSAGE_COUNT: usize = 180;
const DEFAULT_PASSWORD: &str = "flutter-media-test";
const DEFAULT_KLIPY_URL: &str =
    "https://static.klipy.com/ii/d7aec6f6171607374b2065c836f92f4/ec/f3/UKQXellq.webp";
const FIXTURE_MARKER: &str = "[flutter-media-fixture:";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    env_file: Option<String>,
    server_id: Option<i64>,
    channel_id: Option<i64>,
    message_count: usize,
    klipy_urls: Vec<String>,
    apply: bool,
    list_targets: bool,
    keys_only: bool,
    allow_non_local_database: bool,
}

#[derive(Debug, Clone, Copy)]
struct FixtureAccount {
    username: &'static str,
    email: &'static str,
    display_name: &'static str,
    banner_color: &'static str,
    avatar_start: (u8, u8, u8),
    avatar_end: (u8, u8, u8),
    banner_start: (u8, u8, u8),
    banner_end: (u8, u8, u8),
}

#[derive(Debug, Clone)]
struct SeededAccount {
    id: i64,
    username: &'static str,
    display_name: &'static str,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("seed_flutter_media_fixture: {err}");
        process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args_from(env::args())?;
    if let Some(path) = args.env_file.as_deref() {
        dotenvy::from_filename(path).ok();
    } else {
        dotenvy::from_filename(".env.dev.local").ok();
        dotenvy::dotenv().ok();
    }

    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required; pass --env or set it in the shell")?;
    let fixture_password = validate_apply_safety(&args, &database_url)?;
    let pool = PgPool::connect(&database_url).await?;

    if args.list_targets {
        list_targets(&pool).await?;
        return Ok(());
    }

    let Some(server_id) = args.server_id else {
        return Err("pass --server-id or use --list-targets".into());
    };
    validate_message_count(args.message_count)?;
    for url in &args.klipy_urls {
        validate_klipy_url(url)?;
    }

    let channel = resolve_text_channel(&pool, server_id, args.channel_id).await?;
    let accounts = fixture_accounts();
    println!(
        "{} Flutter media fixture: server={} channel={} messages={} accounts={}",
        if args.apply { "seeding" } else { "dry-run:" },
        server_id,
        channel.id,
        args.message_count,
        accounts.len()
    );
    println!("target channel: #{}", channel.name);
    println!(
        "profile media: {}",
        if args.keys_only {
            "keys-only DB references"
        } else {
            "upload generated PNGs to configured public media storage"
        }
    );
    if !args.apply {
        println!("no rows written; rerun with --apply after confirming the target");
        return Ok(());
    }

    let s3 = if args.keys_only {
        None
    } else {
        Some(storage_from_env().ok_or(
            "S3/R2 storage env is required for real profile media; pass --keys-only to write DB references without uploading",
        )?)
    };

    let password_hash = crypto::hash_password(&fixture_password)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let snowflake = SnowflakeGenerator::new(17);

    let seeded_accounts = seed_accounts(
        &pool,
        s3.as_ref(),
        &accounts,
        &password_hash,
        server_id,
        now_ms,
        &snowflake,
    )
    .await?;

    let deleted_messages = delete_existing_fixture_messages(&pool, channel.id).await?;
    let messages = build_fixture_messages(
        channel.id,
        &seeded_accounts,
        args.message_count,
        &args.klipy_urls,
        now_ms,
        &snowflake,
    );
    pg::messages::insert_batch(&pool, &messages).await?;
    let cache_invalidation_required = env::var("FLUTTER_MEDIA_FIXTURE_REDIS_URL").is_ok();
    match invalidate_seeded_channel_cache(channel.id).await {
        Ok(CacheInvalidationResult::Invalidated(deleted)) => {
            println!(
                "invalidated {} scoped message-cache keys for #{}",
                deleted, channel.name
            );
        }
        Ok(CacheInvalidationResult::Skipped) => {
            eprintln!(
                "warning: message cache invalidation skipped because no Redis URL was configured"
            );
        }
        Err(err) => {
            if cache_invalidation_required {
                return Err(format!("message cache invalidation failed after seed: {err}").into());
            }
            eprintln!("warning: message cache invalidation failed after seed: {err}");
        }
    }

    println!(
        "seeded {} accounts and {} messages into #{}; replaced {} previous fixture messages",
        seeded_accounts.len(),
        messages.len(),
        channel.name,
        deleted_messages
    );
    for account in seeded_accounts {
        println!(
            "{}\t{}\t{}",
            account.id, account.username, account.display_name
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct TextChannel {
    id: i64,
    name: String,
}

fn fixture_accounts() -> Vec<FixtureAccount> {
    vec![
        FixtureAccount {
            username: "flutter_media_alex",
            email: "flutter.media.alex@fixture.invalid",
            display_name: "Alex Media",
            banner_color: "#20D6A3",
            avatar_start: (32, 214, 163),
            avatar_end: (11, 91, 74),
            banner_start: (14, 74, 66),
            banner_end: (32, 214, 163),
        },
        FixtureAccount {
            username: "flutter_media_blair",
            email: "flutter.media.blair@fixture.invalid",
            display_name: "Blair Motion",
            banner_color: "#F59E42",
            avatar_start: (245, 158, 66),
            avatar_end: (125, 62, 14),
            banner_start: (78, 36, 13),
            banner_end: (245, 158, 66),
        },
        FixtureAccount {
            username: "flutter_media_cyra",
            email: "flutter.media.cyra@fixture.invalid",
            display_name: "Cyra Loop",
            banner_color: "#7CFFDE",
            avatar_start: (124, 255, 222),
            avatar_end: (37, 87, 79),
            banner_start: (22, 45, 53),
            banner_end: (124, 255, 222),
        },
        FixtureAccount {
            username: "flutter_media_devon",
            email: "flutter.media.devon@fixture.invalid",
            display_name: "Devon Scroll",
            banner_color: "#6EA8FE",
            avatar_start: (110, 168, 254),
            avatar_end: (28, 58, 119),
            banner_start: (17, 35, 77),
            banner_end: (110, 168, 254),
        },
    ]
}

async fn list_targets(pool: &PgPool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT s.id AS server_id,
               s.name AS server_name,
               COUNT(DISTINCT sm.user_id) AS member_count,
               c.id AS channel_id,
               c.name AS channel_name
          FROM servers s
          LEFT JOIN server_members sm ON sm.server_id = s.id
          LEFT JOIN channels c ON c.server_id = s.id AND c.type = 0
         WHERE s.deleted_at_ms IS NULL
         GROUP BY s.id, s.name, c.id, c.name, c.position
         ORDER BY s.created_at_ms ASC, c.position ASC, c.id ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let server_id: i64 = row.try_get("server_id")?;
        let server_name: String = row.try_get("server_name")?;
        let member_count: i64 = row.try_get("member_count")?;
        let channel_id: Option<i64> = row.try_get("channel_id")?;
        let channel_name: Option<String> = row.try_get("channel_name")?;
        match (channel_id, channel_name) {
            (Some(channel_id), Some(channel_name)) => {
                println!(
                    "{server_id}\t{member_count}\t{server_name}\t{channel_id}\t#{channel_name}"
                );
            }
            _ => println!("{server_id}\t{member_count}\t{server_name}\t(no text channel)"),
        }
    }
    Ok(())
}

async fn resolve_text_channel(
    pool: &PgPool,
    server_id: i64,
    requested_channel_id: Option<i64>,
) -> Result<TextChannel, Box<dyn std::error::Error>> {
    let row = if let Some(channel_id) = requested_channel_id {
        sqlx::query(
            r#"
            SELECT id, COALESCE(name, '') AS name
              FROM channels
             WHERE server_id = $1 AND id = $2 AND type = 0
            "#,
        )
        .bind(server_id)
        .bind(channel_id)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query(
            r#"
            SELECT id, COALESCE(name, '') AS name
              FROM channels
             WHERE server_id = $1 AND type = 0
             ORDER BY position ASC, id ASC
             LIMIT 1
            "#,
        )
        .bind(server_id)
        .fetch_optional(pool)
        .await?
    };

    let Some(row) = row else {
        return Err("target server/channel did not resolve to a text channel".into());
    };
    Ok(TextChannel {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
    })
}

async fn seed_accounts(
    pool: &PgPool,
    s3: Option<&S3Service>,
    accounts: &[FixtureAccount],
    password_hash: &str,
    server_id: i64,
    now_ms: i64,
    snowflake: &SnowflakeGenerator,
) -> Result<Vec<SeededAccount>, Box<dyn std::error::Error>> {
    let mut seeded = Vec::with_capacity(accounts.len());
    for account in accounts {
        let user_id = match pg::users::by_username_lower(pool, account.username).await? {
            Some(user) => user.id,
            None => {
                let id = snowflake.next_id();
                pg::users::insert(
                    pool,
                    pg::users::InsertUser {
                        id,
                        email: account.email,
                        password_hash,
                        username: account.username,
                        display_name: Some(account.display_name),
                        username_set: true,
                        email_verified: true,
                        now_ms,
                    },
                )
                .await?;
                id
            }
        };

        let avatar_key = format!("avatars/{user_id}/flutter-media-fixture-avatar.png");
        let banner_key = format!("banners/{user_id}/flutter-media-fixture-banner.png");
        let member_list_banner_key =
            format!("member-list-banners/{user_id}/flutter-media-fixture-banner.png");
        if let Some(s3) = s3 {
            upload_profile_media(
                s3,
                account,
                &avatar_key,
                &banner_key,
                &member_list_banner_key,
            )
            .await?;
        }

        pg::users::update(
            pool,
            user_id,
            pg::users::UpdateUser {
                display_name: Some(account.display_name),
                avatar_url: Some(&avatar_key),
                banner_url: Some(&banner_key),
                banner_base_color: Some(account.banner_color),
                member_list_banner_url: Some(&member_list_banner_key),
                username: Some(account.username),
                email: Some(account.email),
                password_hash: Some(password_hash),
                email_verified: Some(true),
                username_set: Some(true),
                ..Default::default()
            },
        )
        .await?;
        pg::servers::add_member(pool, server_id, user_id, now_ms).await?;
        seeded.push(SeededAccount {
            id: user_id,
            username: account.username,
            display_name: account.display_name,
        });
    }
    Ok(seeded)
}

async fn upload_profile_media(
    s3: &S3Service,
    account: &FixtureAccount,
    avatar_key: &str,
    banner_key: &str,
    member_list_banner_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let avatar = png_gradient(96, 96, account.avatar_start, account.avatar_end);
    let banner = png_gradient(640, 206, account.banner_start, account.banner_end);
    let member_list_banner = png_gradient(420, 116, account.banner_start, account.banner_end);
    for (key, bytes) in [
        (avatar_key, avatar),
        (banner_key, banner),
        (member_list_banner_key, member_list_banner),
    ] {
        s3.put_object(key, bytes, "image/png")
            .await
            .map_err(|err| format!("profile media upload failed for {key}: {err}"))?;
    }
    Ok(())
}

async fn delete_existing_fixture_messages(
    pool: &PgPool,
    channel_id: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM messages
         WHERE channel_id = $1
           AND content LIKE $2
        "#,
    )
    .bind(channel_id)
    .bind(format!("%{FIXTURE_MARKER}%"))
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheInvalidationResult {
    Invalidated(i64),
    Skipped,
}

async fn invalidate_seeded_channel_cache(
    channel_id: i64,
) -> Result<CacheInvalidationResult, String> {
    let Some(redis_url) = env::var("FLUTTER_MEDIA_FIXTURE_REDIS_URL")
        .ok()
        .or_else(|| env::var("REDIS_URL").ok())
    else {
        return Ok(CacheInvalidationResult::Skipped);
    };

    let redis_config = Config::from_url(&redis_url).map_err(|_| "invalid Redis URL".to_string())?;
    let redis = Builder::from_config(redis_config)
        .with_connection_config(|config| {
            config.connection_timeout = Duration::from_secs(5);
        })
        .build()
        .map_err(|err| format!("failed to create Redis client: {err}"))?;
    redis
        .init()
        .await
        .map_err(|err| format!("failed to connect to Redis: {err}"))?;
    let deleted: i64 = redis
        .del(message_cache_keys(channel_id))
        .await
        .map_err(|err| format!("failed to delete message-cache keys: {err}"))?;
    let _ = redis.quit().await;
    Ok(CacheInvalidationResult::Invalidated(deleted))
}

fn message_cache_keys(channel_id: i64) -> Vec<String> {
    vec![
        format!("msgcache:{channel_id}:idx"),
        format!("msgcache:{channel_id}:data"),
        format!("msgcache:{channel_id}:warm"),
        format!("msgcache:{channel_id}:latest_complete"),
    ]
}

fn build_fixture_messages(
    channel_id: i64,
    accounts: &[SeededAccount],
    message_count: usize,
    klipy_urls: &[String],
    now_ms: i64,
    snowflake: &SnowflakeGenerator,
) -> Vec<pg::messages::MessageRow> {
    let safe_klipy_urls = if klipy_urls.is_empty() {
        vec![DEFAULT_KLIPY_URL.to_string()]
    } else {
        klipy_urls.to_vec()
    };
    let start_ms = now_ms - (message_count as i64 * 45_000);
    let mut rows = Vec::with_capacity(message_count);
    for index in 0..message_count {
        let account = &accounts[index % accounts.len()];
        let content = fixture_message_content(index, account, &safe_klipy_urls);
        rows.push(pg::messages::MessageRow {
            id: snowflake.next_id(),
            channel_id,
            author_id: account.id,
            r#type: 0,
            flags: 0,
            content,
            reply_to: None,
            edited_at_ms: None,
            created_at_ms: start_ms + (index as i64 * 45_000),
        });
    }
    rows
}

fn fixture_message_content(index: usize, account: &SeededAccount, klipy_urls: &[String]) -> String {
    let marker = format!("{FIXTURE_MARKER}{:03}]", index + 1);
    if index % 5 == 1 || index % 7 == 3 {
        let url = &klipy_urls[index % klipy_urls.len()];
        return format!(
            "{marker} {} animated media probe {url}",
            account.display_name
        );
    }
    if index % 11 == 0 {
        return format!(
            "{marker} {} long text row for scroll-position retention, viewport recycling, author profile media hydration, and message-row rebuild checks.",
            account.display_name
        );
    }
    format!(
        "{marker} {} text row for Flutter timeline scroll and media mount checks.",
        account.display_name
    )
}

fn validate_message_count(count: usize) -> Result<(), Box<dyn std::error::Error>> {
    if !(20..=500).contains(&count) {
        return Err("message count must be between 20 and 500".into());
    }
    Ok(())
}

fn validate_klipy_url(raw: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse(raw)?;
    if url.scheme() != "https" {
        return Err("Klipy URLs must use https".into());
    }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err("Klipy URLs must not include credentials or fragments".into());
    }
    for (key, _) in url.query_pairs() {
        let key = key.to_ascii_lowercase();
        if !matches!(
            key.as_str(),
            "size" | "format" | "width" | "height" | "w" | "h"
        ) {
            return Err("Klipy URL query strings may only contain image sizing keys".into());
        }
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host != "static.klipy.com" && host != "media.klipy.com" {
        return Err("Klipy URLs must use static.klipy.com or media.klipy.com".into());
    }
    if url.path_segments().into_iter().flatten().any(|segment| {
        let lower = segment.to_ascii_lowercase();
        lower == "attachments" || lower == "." || lower == ".." || lower.contains('\\')
    }) {
        return Err("Klipy URLs must not use unsafe path segments".into());
    }
    let path = url.path().to_ascii_lowercase();
    if !(path.ends_with(".gif")
        || path.ends_with(".webp")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg"))
    {
        return Err("Klipy URLs must point at an image media extension".into());
    }
    Ok(())
}

fn validate_apply_safety(
    args: &Args,
    database_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if args.apply && !args.allow_non_local_database && !database_url_is_local(database_url) {
        return Err(
            "refusing to seed a non-local database without --allow-non-local-database".into(),
        );
    }
    fixture_password_from_value(env::var("FLUTTER_MEDIA_FIXTURE_PASSWORD").ok(), args.apply)
}

fn fixture_password_from_value(
    value: Option<String>,
    apply: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let Some(password) = value.map(|value| value.trim().to_string()) else {
        if apply {
            return Err("FLUTTER_MEDIA_FIXTURE_PASSWORD is required when --apply is used".into());
        }
        return Ok(DEFAULT_PASSWORD.to_string());
    };
    if password.is_empty() {
        if apply {
            return Err(
                "FLUTTER_MEDIA_FIXTURE_PASSWORD must not be empty when --apply is used".into(),
            );
        }
        return Ok(DEFAULT_PASSWORD.to_string());
    }
    if apply && password == DEFAULT_PASSWORD {
        return Err("FLUTTER_MEDIA_FIXTURE_PASSWORD must not use the documented fallback password when --apply is used".into());
    }
    Ok(password)
}

fn database_url_is_local(raw: &str) -> bool {
    if let Ok(url) = Url::parse(raw) {
        if let Some(host) = url.host()
            && database_host_is_local(host)
        {
            return true;
        }
    }
    database_url_host(raw)
        .as_deref()
        .map(database_host_label_is_local)
        .unwrap_or(false)
}

fn database_host_is_local(host: Host<&str>) -> bool {
    match host {
        Host::Domain(host) if host.eq_ignore_ascii_case("localhost") => true,
        Host::Ipv4(addr) if addr.is_loopback() => true,
        Host::Ipv6(addr) if addr.is_loopback() => true,
        _ => false,
    }
}

fn database_url_host(raw: &str) -> Option<String> {
    let (_, rest) = raw.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    let host_port = authority.rsplit('@').next()?;
    if let Some(without_open) = host_port.strip_prefix('[') {
        let (host, _) = without_open.split_once(']')?;
        return Some(host.to_string());
    }
    let host = host_port.split(':').next()?.trim();
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

fn database_host_label_is_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

fn storage_from_env() -> Option<S3Service> {
    let endpoint = env::var("S3_ENDPOINT")
        .or_else(|_| env::var("DO_SPACES_ENDPOINT"))
        .ok();
    let bucket = env::var("S3_BUCKET")
        .or_else(|_| env::var("DO_SPACES_BUCKET"))
        .ok();
    let key = env::var("S3_ACCESS_KEY")
        .or_else(|_| env::var("DO_SPACES_KEY"))
        .ok();
    let secret = env::var("S3_SECRET_KEY")
        .or_else(|_| env::var("DO_SPACES_SECRET"))
        .ok();
    let path_style = env::var("STORAGE_PATH_STYLE")
        .map(|value| value == "true")
        .unwrap_or(false);
    S3Service::from_config(
        endpoint.as_deref(),
        bucket.as_deref(),
        key.as_deref(),
        secret.as_deref(),
        path_style,
    )
}

fn parse_args_from<I, S>(args: I) -> Result<Args, Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut parsed = Args {
        env_file: None,
        server_id: None,
        channel_id: None,
        message_count: DEFAULT_MESSAGE_COUNT,
        klipy_urls: vec![DEFAULT_KLIPY_URL.to_string()],
        apply: false,
        list_targets: false,
        keys_only: false,
        allow_non_local_database: false,
    };

    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--env" => parsed.env_file = Some(iter.next().ok_or("--env requires a path")?),
            "--server-id" => {
                parsed.server_id = Some(iter.next().ok_or("--server-id requires an ID")?.parse()?);
            }
            "--channel-id" => {
                parsed.channel_id =
                    Some(iter.next().ok_or("--channel-id requires an ID")?.parse()?);
            }
            "--message-count" => {
                parsed.message_count = iter
                    .next()
                    .ok_or("--message-count requires a value")?
                    .parse()?;
            }
            "--klipy-url" => {
                let url = iter.next().ok_or("--klipy-url requires a URL")?;
                validate_klipy_url(&url)?;
                if parsed.klipy_urls == [DEFAULT_KLIPY_URL] {
                    parsed.klipy_urls.clear();
                }
                parsed.klipy_urls.push(url);
            }
            "--apply" => parsed.apply = true,
            "--allow-non-local-database" => parsed.allow_non_local_database = true,
            "--list-targets" => parsed.list_targets = true,
            "--keys-only" => parsed.keys_only = true,
            "--help" | "-h" => {
                print_help();
                process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    validate_message_count(parsed.message_count)?;
    Ok(parsed)
}

fn print_help() {
    println!(
        "Usage:\n  cargo run --manifest-path server-rs/Cargo.toml --bin seed_flutter_media_fixture -- --list-targets [--env .env.dev.local]\n  cargo run --manifest-path server-rs/Cargo.toml --bin seed_flutter_media_fixture -- --server-id ID [--channel-id ID] [--message-count 180] [--klipy-url URL] [--env .env.dev.local] [--keys-only] --apply\n\nFor --apply, set FLUTTER_MEDIA_FIXTURE_PASSWORD in the environment; the documented fallback is dry-run only. Non-local DATABASE_URL targets require --allow-non-local-database. Set FLUTTER_MEDIA_FIXTURE_REDIS_URL to invalidate a production message cache without storing that URL in an env file."
    );
}

fn png_gradient(width: u32, height: u32, start: (u8, u8, u8), end: (u8, u8, u8)) -> Vec<u8> {
    let mut raw = Vec::with_capacity((height * (1 + width * 3)) as usize);
    for y in 0..height {
        raw.push(0);
        let denominator = height.saturating_sub(1).max(1);
        let r = interpolate(start.0, end.0, y, denominator);
        let g = interpolate(start.1, end.1, y, denominator);
        let b = interpolate(start.2, end.2, y, denominator);
        for x in 0..width {
            let shimmer = ((x * 19 + y * 7) % 17) as u8;
            raw.push(r.saturating_add(shimmer / 4));
            raw.push(g.saturating_add(shimmer / 5));
            raw.push(b.saturating_add(shimmer / 6));
        }
    }

    let mut png = Vec::new();
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    write_png_chunk(&mut png, b"IHDR", &ihdr);
    write_png_chunk(&mut png, b"IDAT", &zlib_store(&raw));
    write_png_chunk(&mut png, b"IEND", &[]);
    png
}

fn interpolate(start: u8, end: u8, numerator: u32, denominator: u32) -> u8 {
    let start = start as i32;
    let end = end as i32;
    let value = start + ((end - start) * numerator as i32 / denominator as i32);
    value.clamp(0, 255) as u8
}

fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    for (index, chunk) in data.chunks(u16::MAX as usize).enumerate() {
        let final_block = index == data.len().div_ceil(u16::MAX as usize) - 1;
        out.push(if final_block { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn write_png_chunk(out: &mut Vec<u8>, name: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(name.len() + data.len());
    crc_input.extend_from_slice(name);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + u32::from(*byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_seed_options() {
        let parsed = parse_args_from([
            "seed",
            "--env",
            ".env.dev.local",
            "--server-id",
            "123",
            "--channel-id",
            "456",
            "--message-count",
            "64",
            "--klipy-url",
            "https://media.klipy.com/a.gif",
            "--keys-only",
            "--apply",
        ])
        .unwrap();
        assert_eq!(parsed.env_file.as_deref(), Some(".env.dev.local"));
        assert_eq!(parsed.server_id, Some(123));
        assert_eq!(parsed.channel_id, Some(456));
        assert_eq!(parsed.message_count, 64);
        assert_eq!(parsed.klipy_urls, vec!["https://media.klipy.com/a.gif"]);
        assert!(parsed.keys_only);
        assert!(parsed.apply);
        assert!(!parsed.allow_non_local_database);
    }

    #[test]
    fn parses_non_local_database_override() {
        let parsed =
            parse_args_from(["seed", "--server-id", "123", "--allow-non-local-database"]).unwrap();

        assert_eq!(parsed.server_id, Some(123));
        assert!(parsed.allow_non_local_database);
    }

    #[test]
    fn apply_requires_explicit_non_default_password() {
        assert!(fixture_password_from_value(None, true).is_err());
        assert!(fixture_password_from_value(Some(String::new()), true).is_err());
        assert!(fixture_password_from_value(Some(DEFAULT_PASSWORD.to_string()), true).is_err());
        assert_eq!(
            fixture_password_from_value(Some("fixture-secret".to_string()), true).unwrap(),
            "fixture-secret"
        );
        assert_eq!(
            fixture_password_from_value(None, false).unwrap(),
            DEFAULT_PASSWORD
        );
    }

    #[test]
    fn apply_database_guard_accepts_only_local_urls_by_default() {
        assert!(database_url_is_local(
            "postgres://user:pass@localhost/verdant"
        ));
        assert!(database_url_is_local(
            "postgres://user:pass@127.0.0.1/verdant"
        ));
        assert!(database_url_is_local("postgres://user:pass@[::1]/verdant"));
        assert!(!database_url_is_local(
            "postgres://user:pass@db.example.com/verdant"
        ));
        assert!(!database_url_is_local("not a postgres url"));
    }

    #[test]
    fn rejects_untrusted_klipy_urls() {
        assert!(validate_klipy_url("http://media.klipy.com/a.gif").is_err());
        assert!(validate_klipy_url("https://media.klipy.com.evil/a.gif").is_err());
        assert!(validate_klipy_url("https://media.klipy.com/attachments/a.gif").is_err());
        assert!(validate_klipy_url("https://media.klipy.com/a.txt").is_err());
        assert!(validate_klipy_url("https://media.klipy.com/a.gif#token").is_err());
        assert!(validate_klipy_url("https://media.klipy.com/a.gif?token=secret").is_err());
        assert!(validate_klipy_url("https://media.klipy.com/a.gif?size=small").is_ok());
    }

    #[test]
    fn message_plan_marks_only_fixture_rows_and_avoids_attachments() {
        let accounts = vec![
            SeededAccount {
                id: 1,
                username: "flutter_media_alex",
                display_name: "Alex Media",
            },
            SeededAccount {
                id: 2,
                username: "flutter_media_blair",
                display_name: "Blair Motion",
            },
        ];
        let snowflake = SnowflakeGenerator::new(18);
        let rows = build_fixture_messages(
            42,
            &accounts,
            24,
            &["https://media.klipy.com/a.gif".to_string()],
            1_780_272_000_000,
            &snowflake,
        );
        assert_eq!(rows.len(), 24);
        assert!(rows.iter().all(|row| row.content.contains(FIXTURE_MARKER)));
        assert!(rows.iter().any(|row| row.content.contains(".gif")));
        assert!(rows.iter().all(|row| !row.content.contains("attachments/")));
    }

    #[test]
    fn message_cache_invalidation_targets_only_seeded_channel_keys() {
        assert_eq!(
            message_cache_keys(42),
            vec![
                "msgcache:42:idx",
                "msgcache:42:data",
                "msgcache:42:warm",
                "msgcache:42:latest_complete",
            ]
        );
    }

    #[test]
    fn generated_profile_media_is_png() {
        let png = png_gradient(8, 4, (1, 2, 3), (4, 5, 6));
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(png.windows(4).any(|window| window == b"IHDR"));
        assert!(png.windows(4).any(|window| window == b"IDAT"));
        assert!(png.ends_with(&[0xae, 0x42, 0x60, 0x82]));
    }
}
