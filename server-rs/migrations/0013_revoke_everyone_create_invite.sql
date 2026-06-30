-- Existing servers inherited CREATE_INVITE on @everyone from the original
-- default role. Keep invites explicit by removing that bit from default roles.
UPDATE roles
SET permissions = permissions & ~(1::bigint << 11)
WHERE name = '@everyone'
  AND (permissions & (1::bigint << 11)) <> 0;
