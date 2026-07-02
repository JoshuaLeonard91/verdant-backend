use std::time::Duration;

use sqlx::PgPool;

use crate::services::field_crypto::FieldEncryptionKeyring;
use crate::state::AppState;

const DEFAULT_BACKFILL_BATCH_SIZE: i64 = 500;
const MAX_BACKFILL_BATCH_SIZE: i64 = 1_000;
const BACKFILL_BATCH_DELAY_MS: u64 = 250;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct FieldEncryptionBackfillProgress {
    pub user_emails: usize,
    pub email_verifications: usize,
}

impl FieldEncryptionBackfillProgress {
    pub fn total(self) -> usize {
        self.user_emails + self.email_verifications
    }
}

fn should_continue_backfill(progress: FieldEncryptionBackfillProgress) -> bool {
    progress.total() > 0
}

fn bounded_batch_size(requested_batch_size: i64) -> i64 {
    requested_batch_size.clamp(1, MAX_BACKFILL_BATCH_SIZE)
}

pub async fn run_field_encryption_backfill_once(
    pool: &PgPool,
    keyring: &FieldEncryptionKeyring,
    requested_batch_size: i64,
) -> Result<FieldEncryptionBackfillProgress, sqlx::Error> {
    let batch_size = bounded_batch_size(requested_batch_size);
    let user_emails =
        crate::services::pg::users::backfill_encrypted_email_batch(pool, keyring, batch_size)
            .await?;
    let email_verifications =
        crate::services::pg::auth::backfill_encrypted_email_verifications_batch(
            pool, keyring, batch_size,
        )
        .await?;

    Ok(FieldEncryptionBackfillProgress {
        user_emails,
        email_verifications,
    })
}

pub fn spawn_field_encryption_backfill_task(state: AppState) {
    let Some(keyring) = state.field_crypto.clone() else {
        return;
    };
    let pool = state.pg.clone();

    tokio::spawn(async move {
        tracing::info!("Field encryption backfill task started");
        loop {
            match run_field_encryption_backfill_once(&pool, &keyring, DEFAULT_BACKFILL_BATCH_SIZE)
                .await
            {
                Ok(progress) if should_continue_backfill(progress) => {
                    tracing::info!(
                        user_emails = progress.user_emails,
                        email_verifications = progress.email_verifications,
                        "Field encryption backfill batch complete"
                    );
                    tokio::time::sleep(Duration::from_millis(BACKFILL_BATCH_DELAY_MS)).await;
                }
                Ok(_) => {
                    tracing::info!("Field encryption backfill complete");
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Field encryption backfill stopped before completion"
                    );
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_total_counts_all_backfilled_rows() {
        let progress = FieldEncryptionBackfillProgress {
            user_emails: 2,
            email_verifications: 3,
        };

        assert_eq!(progress.total(), 5);
    }

    #[test]
    fn should_continue_only_when_a_batch_did_work() {
        assert!(should_continue_backfill(FieldEncryptionBackfillProgress {
            user_emails: 1,
            email_verifications: 0,
        }));
        assert!(!should_continue_backfill(FieldEncryptionBackfillProgress {
            user_emails: 0,
            email_verifications: 0,
        }));
    }

    #[test]
    fn batch_size_is_bounded() {
        assert_eq!(bounded_batch_size(0), 1);
        assert_eq!(bounded_batch_size(250), 250);
        assert_eq!(bounded_batch_size(10_000), MAX_BACKFILL_BATCH_SIZE);
    }
}
