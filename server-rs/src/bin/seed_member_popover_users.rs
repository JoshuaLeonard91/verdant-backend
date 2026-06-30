use std::{env, process};

use sqlx::{PgPool, Row};
use verdant_server::{
    services::{crypto, pg},
    snowflake::SnowflakeGenerator,
};

const DEFAULT_COUNT: usize = 100;
const DEFAULT_COLOR: &str = "#F58020";

#[derive(Debug)]
struct Args {
    env_file: Option<String>,
    server_ids: Vec<i64>,
    count: usize,
    apply: bool,
    list_servers: bool,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("seed_member_popover_users: {err}");
        process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    if let Some(path) = args.env_file.as_deref() {
        dotenvy::from_filename(path).ok();
    } else {
        dotenvy::from_filename(".env.dev.local").ok();
        dotenvy::dotenv().ok();
    }

    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required; pass --env or set it in the shell")?;
    let pool = PgPool::connect(&database_url).await?;

    if args.list_servers {
        list_servers(&pool).await?;
        return Ok(());
    }

    if args.server_ids.len() != 2 {
        return Err("pass exactly two --server-id values".into());
    }
    if args.count == 0 || args.count > 500 {
        return Err("count must be between 1 and 500".into());
    }

    let existing_servers = existing_server_ids(&pool, &args.server_ids).await?;
    if existing_servers.len() != args.server_ids.len() {
        return Err(format!(
            "one or more server IDs do not exist: requested={:?} found={:?}",
            args.server_ids, existing_servers
        )
        .into());
    }

    println!(
        "{} {} synthetic users into servers {:?}",
        if args.apply { "seeding" } else { "dry-run:" },
        args.count,
        args.server_ids
    );
    if !args.apply {
        println!("no rows written; rerun with --apply after confirming the target servers");
        return Ok(());
    }

    seed_users(&pool, &args.server_ids, args.count).await?;
    println!(
        "seeded {} synthetic users into {} servers",
        args.count,
        args.server_ids.len()
    );
    Ok(())
}

async fn list_servers(pool: &PgPool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT s.id, s.name, COUNT(sm.user_id) AS member_count
        FROM servers s
        LEFT JOIN server_members sm ON sm.server_id = s.id
        WHERE s.deleted_at_ms IS NULL
        GROUP BY s.id, s.name
        ORDER BY s.created_at_ms ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let id: i64 = row.try_get("id")?;
        let name: String = row.try_get("name")?;
        let member_count: i64 = row.try_get("member_count")?;
        println!("{id}\t{member_count}\t{name}");
    }
    Ok(())
}

async fn existing_server_ids(pool: &PgPool, server_ids: &[i64]) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        SELECT id
        FROM servers
        WHERE deleted_at_ms IS NULL AND id = ANY($1)
        ORDER BY id
        "#,
    )
    .bind(server_ids)
    .fetch_all(pool)
    .await
}

async fn seed_users(
    pool: &PgPool,
    server_ids: &[i64],
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let snowflake = SnowflakeGenerator::new(9);
    let password_hash = crypto::hash_password("loadtest")?;
    let now_ms = chrono::Utc::now().timestamp_millis();

    for index in 1..=count {
        let user_id = snowflake.next_id();
        let username = format!("viewport_test_{user_id}");
        let email = format!("{user_id}@viewport-test.invalid");
        let display_name = format!("Viewport Test {index:03}");

        pg::users::insert(
            pool,
            pg::users::InsertUser {
                id: user_id,
                email: &email,
                password_hash: &password_hash,
                username: &username,
                display_name: Some(&display_name),
                username_set: true,
                email_verified: true,
                now_ms,
            },
        )
        .await?;

        pg::users::update(
            pool,
            user_id,
            pg::users::UpdateUser {
                banner_base_color: Some(DEFAULT_COLOR),
                ..Default::default()
            },
        )
        .await?;

        for &server_id in server_ids {
            pg::servers::add_member(pool, server_id, user_id, now_ms).await?;
        }
    }

    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = Args {
        env_file: None,
        server_ids: Vec::new(),
        count: DEFAULT_COUNT,
        apply: false,
        list_servers: false,
    };

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--env" => {
                args.env_file = Some(iter.next().ok_or("--env requires a path")?);
            }
            "--server-id" => {
                let value = iter.next().ok_or("--server-id requires an ID")?;
                args.server_ids.push(value.parse()?);
            }
            "--count" => {
                let value = iter.next().ok_or("--count requires a value")?;
                args.count = value.parse()?;
            }
            "--apply" => args.apply = true,
            "--list-servers" => args.list_servers = true,
            "--help" | "-h" => {
                print_help();
                process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(args)
}

fn print_help() {
    println!(
        "Usage:\n  cargo run --manifest-path server-rs/Cargo.toml --bin seed_member_popover_users -- --list-servers [--env .env.dev.local]\n  cargo run --manifest-path server-rs/Cargo.toml --bin seed_member_popover_users -- --server-id ID --server-id ID [--count 100] [--env .env.dev.local] --apply"
    );
}
