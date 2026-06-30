-- Keep the moderation queue from accumulating duplicate pending reports for
-- the same reporter and target. Historical resolved reports remain intact.

WITH duplicate_pending_reports AS (
    SELECT id
      FROM (
        SELECT id,
               row_number() OVER (
                   PARTITION BY reporter_id, target_type, target_id
                   ORDER BY created_at_ms ASC, id ASC
               ) AS rn
          FROM reports
         WHERE status = 'pending'
      ) ranked
     WHERE rn > 1
)
UPDATE reports
   SET status = 'dismissed',
       resolved_at_ms = floor(extract(epoch from now()) * 1000)::bigint
 WHERE id IN (SELECT id FROM duplicate_pending_reports);

CREATE UNIQUE INDEX IF NOT EXISTS reports_pending_reporter_target_idx
    ON reports (reporter_id, target_type, target_id)
    WHERE status = 'pending';
