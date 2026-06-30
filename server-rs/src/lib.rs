// Library crate mirror of main.rs's module tree. Exists so that
// auxiliary binaries under `src/bin/` (e.g. verdantdb_backfill) can
// reuse the same service/repo/proto code without duplicating it.
//
// All modules are declared `pub` here; main.rs imports them via a
// single `use verdant_server::{...};` line rather than re-declaring
// them with `mod` (which would create a second copy in the binary
// crate with incompatible type identities).

pub mod proto {
    include!("verdant.rs");
}

pub mod config;
pub mod error;
pub mod federation;
pub mod handlers;
pub mod middleware;
pub mod repo;
pub mod services;
pub mod snowflake;
pub mod state;
pub mod ws;
