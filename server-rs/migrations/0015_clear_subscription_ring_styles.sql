-- Avatar ring styles are deprecated. Keep the column for backward-compatible
-- schema shape, but clear persisted values so READY payloads and stale clients
-- cannot surface the removed feature.
UPDATE users
SET subscription_ring_style = NULL
WHERE subscription_ring_style IS NOT NULL;
