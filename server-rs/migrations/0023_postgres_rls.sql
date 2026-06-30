-- Re-enable PostgreSQL row-level security as defense-in-depth for runtime
-- user-scoped queries. These policies are active for non-owner database roles
-- such as verdant_app. Existing owner/migration connections continue to bypass
-- RLS unless a later, fully converted release deliberately applies policies to
-- owner connections too.

CREATE SCHEMA IF NOT EXISTS app;

CREATE OR REPLACE FUNCTION app.current_user_id()
RETURNS bigint
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    raw text;
BEGIN
    raw := current_setting('app.user_id', true);
    IF raw IS NULL OR raw = '' OR raw !~ '^[0-9]+$' THEN
        RETURN NULL;
    END IF;
    RETURN raw::bigint;
END;
$$;

CREATE OR REPLACE FUNCTION app.has_permission(perms bigint, perm bigint)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT (perms & 1024) <> 0 OR (perms & perm) = perm
$$;

CREATE OR REPLACE FUNCTION app.can_access_server(p_server_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.current_user_id() IS NOT NULL
       AND (
            EXISTS (
                SELECT 1
                  FROM servers s
                 WHERE s.id = p_server_id
                   AND s.owner_id = app.current_user_id()
                   AND s.deleted_at_ms IS NULL
            )
            OR EXISTS (
                SELECT 1
                  FROM server_members sm
                  JOIN servers s ON s.id = sm.server_id
                 WHERE sm.server_id = p_server_id
                   AND sm.user_id = app.current_user_id()
                   AND s.deleted_at_ms IS NULL
            )
       )
$$;

CREATE OR REPLACE FUNCTION app.user_server_permissions(p_user_id bigint, p_server_id bigint)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
DECLARE
    perms bigint := 0;
BEGIN
    IF p_user_id IS NULL THEN
        RETURN 0;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM servers s
         WHERE s.id = p_server_id
           AND s.owner_id = p_user_id
           AND s.deleted_at_ms IS NULL
    ) THEN
        RETURN -1;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM server_members sm
          JOIN servers s ON s.id = sm.server_id
         WHERE sm.server_id = p_server_id
           AND sm.user_id = p_user_id
           AND s.deleted_at_ms IS NULL
    ) THEN
        RETURN 0;
    END IF;

    SELECT COALESCE(bit_or(r.permissions), 0)
      INTO perms
      FROM roles r
     WHERE r.server_id = p_server_id
       AND r.color_only = false
       AND (
            r.position = 0
            OR EXISTS (
                SELECT 1
                  FROM member_roles mr
                 WHERE mr.user_id = p_user_id
                   AND mr.server_id = p_server_id
                   AND mr.role_id = r.id
            )
       );

    IF app.has_permission(perms, 1024) THEN
        RETURN -1;
    END IF;

    RETURN perms;
END;
$$;

CREATE OR REPLACE FUNCTION app.user_channel_permissions(p_user_id bigint, p_channel_id bigint)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
DECLARE
    sid bigint;
    perms bigint := 0;
    everyone_role_id bigint;
    everyone_allow bigint := 0;
    everyone_deny bigint := 0;
    role_allow bigint := 0;
    role_deny bigint := 0;
BEGIN
    IF p_user_id IS NULL THEN
        RETURN 0;
    END IF;

    SELECT c.server_id INTO sid
      FROM channels c
     WHERE c.id = p_channel_id;

    IF sid IS NULL THEN
        RETURN 0;
    END IF;

    perms := app.user_server_permissions(p_user_id, sid);
    IF perms = 0 THEN
        RETURN 0;
    END IF;

    IF app.has_permission(perms, 1024) THEN
        RETURN -1;
    END IF;

    SELECT r.id INTO everyone_role_id
      FROM roles r
     WHERE r.server_id = sid
       AND r.position = 0
       AND r.color_only = false
     ORDER BY r.id
     LIMIT 1;

    IF everyone_role_id IS NOT NULL THEN
        SELECT COALESCE(MAX(co.allow_bits), 0), COALESCE(MAX(co.deny_bits), 0)
          INTO everyone_allow, everyone_deny
          FROM channel_overrides co
         WHERE co.channel_id = p_channel_id
           AND co.role_id = everyone_role_id;

        perms := (perms & ~everyone_deny) | everyone_allow;
    END IF;

    SELECT COALESCE(bit_or(co.allow_bits), 0), COALESCE(bit_or(co.deny_bits), 0)
      INTO role_allow, role_deny
      FROM channel_overrides co
      JOIN member_roles mr
        ON mr.role_id = co.role_id
       AND mr.server_id = sid
       AND mr.user_id = p_user_id
      JOIN roles r
        ON r.id = co.role_id
       AND r.server_id = sid
       AND r.color_only = false
     WHERE co.channel_id = p_channel_id;

    perms := (perms & ~COALESCE(role_deny, 0)) | COALESCE(role_allow, 0);

    RETURN perms;
END;
$$;

CREATE OR REPLACE FUNCTION app.can_view_channel(p_channel_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.has_permission(app.user_channel_permissions(app.current_user_id(), p_channel_id), 1)
$$;

CREATE OR REPLACE FUNCTION app.can_manage_messages(p_channel_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.has_permission(app.user_channel_permissions(app.current_user_id(), p_channel_id), 4)
$$;

CREATE OR REPLACE FUNCTION app.can_view_moderation_actions(p_server_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.has_permission(app.user_server_permissions(app.current_user_id(), p_server_id), 16)
        OR app.has_permission(app.user_server_permissions(app.current_user_id(), p_server_id), 64)
        OR app.has_permission(app.user_server_permissions(app.current_user_id(), p_server_id), 128)
$$;

CREATE OR REPLACE FUNCTION app.can_access_dm_channel(p_channel_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.current_user_id() IS NOT NULL
       AND EXISTS (
            SELECT 1
              FROM dm_members dm
             WHERE dm.channel_id = p_channel_id
               AND dm.user_id = app.current_user_id()
       )
$$;

CREATE OR REPLACE FUNCTION app.can_access_channel_like(p_channel_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.can_view_channel(p_channel_id) OR app.can_access_dm_channel(p_channel_id)
$$;

CREATE OR REPLACE FUNCTION app.message_channel_id(p_message_id bigint)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT m.channel_id
      FROM messages m
     WHERE m.id = p_message_id
     ORDER BY m.created_at_ms DESC
     LIMIT 1
$$;

CREATE OR REPLACE FUNCTION app.can_access_message(p_message_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
    SELECT app.can_access_channel_like(app.message_channel_id(p_message_id))
$$;

CREATE OR REPLACE FUNCTION app.can_view_feed(p_feed_id bigint)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, app, pg_temp
AS $$
DECLARE
    sid bigint;
    allowed_roles bigint[];
BEGIN
    SELECT f.server_id, f.visible_role_ids
      INTO sid, allowed_roles
      FROM feeds f
     WHERE f.id = p_feed_id;

    IF sid IS NULL OR NOT app.can_access_server(sid) THEN
        RETURN false;
    END IF;

    IF COALESCE(cardinality(allowed_roles), 0) = 0 THEN
        RETURN true;
    END IF;

    IF app.has_permission(app.user_server_permissions(app.current_user_id(), sid), 1024) THEN
        RETURN true;
    END IF;

    RETURN EXISTS (
        SELECT 1
          FROM member_roles mr
         WHERE mr.user_id = app.current_user_id()
           AND mr.server_id = sid
           AND mr.role_id = ANY(allowed_roles)
    );
END;
$$;

GRANT USAGE ON SCHEMA app TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app TO PUBLIC;

DO $$
BEGIN
    IF to_regrole('verdant_app') IS NULL THEN
        CREATE ROLE verdant_app NOLOGIN;
    END IF;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO verdant_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO verdant_app;

ALTER TABLE IF EXISTS servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS server_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS channel_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS member_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS emojis ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS pinned_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS dm_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS dm_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS read_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS bots ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS moderation_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS reports ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'servers'::regclass AND polname = 'rls_servers_member_select') THEN
        CREATE POLICY rls_servers_member_select ON servers
            FOR SELECT USING (app.can_access_server(id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'server_members'::regclass AND polname = 'rls_server_members_visible_select') THEN
        CREATE POLICY rls_server_members_visible_select ON server_members
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'categories'::regclass AND polname = 'rls_categories_member_select') THEN
        CREATE POLICY rls_categories_member_select ON categories
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'channels'::regclass AND polname = 'rls_channels_view_select') THEN
        CREATE POLICY rls_channels_view_select ON channels
            FOR SELECT USING (app.can_view_channel(id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'channel_overrides'::regclass AND polname = 'rls_channel_overrides_view_select') THEN
        CREATE POLICY rls_channel_overrides_view_select ON channel_overrides
            FOR SELECT USING (app.can_view_channel(channel_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'roles'::regclass AND polname = 'rls_roles_member_select') THEN
        CREATE POLICY rls_roles_member_select ON roles
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'member_roles'::regclass AND polname = 'rls_member_roles_member_select') THEN
        CREATE POLICY rls_member_roles_member_select ON member_roles
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'emojis'::regclass AND polname = 'rls_emojis_member_select') THEN
        CREATE POLICY rls_emojis_member_select ON emojis
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'pinned_messages'::regclass AND polname = 'rls_pinned_messages_channel_select') THEN
        CREATE POLICY rls_pinned_messages_channel_select ON pinned_messages
            FOR SELECT USING (app.can_access_channel_like(channel_id));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'dm_channels'::regclass AND polname = 'rls_dm_channels_member_select') THEN
        CREATE POLICY rls_dm_channels_member_select ON dm_channels
            FOR SELECT USING (app.can_access_dm_channel(id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'dm_members'::regclass AND polname = 'rls_dm_members_member_select') THEN
        CREATE POLICY rls_dm_members_member_select ON dm_members
            FOR SELECT USING (app.can_access_dm_channel(channel_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'relationships'::regclass AND polname = 'rls_relationships_own_rows') THEN
        CREATE POLICY rls_relationships_own_rows ON relationships
            USING (app.current_user_id() IN (user_id, target_id))
            WITH CHECK (app.current_user_id() = user_id);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'messages'::regclass AND polname = 'rls_messages_access_select') THEN
        CREATE POLICY rls_messages_access_select ON messages
            FOR SELECT USING (app.can_access_channel_like(channel_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'messages'::regclass AND polname = 'rls_messages_author_insert') THEN
        CREATE POLICY rls_messages_author_insert ON messages
            FOR INSERT WITH CHECK (
                author_id = app.current_user_id()
                AND app.can_access_channel_like(channel_id)
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'messages'::regclass AND polname = 'rls_messages_author_or_moderator_update') THEN
        CREATE POLICY rls_messages_author_or_moderator_update ON messages
            FOR UPDATE USING (
                app.can_access_channel_like(channel_id)
                AND (author_id = app.current_user_id() OR app.can_manage_messages(channel_id))
            )
            WITH CHECK (
                app.can_access_channel_like(channel_id)
                AND (author_id = app.current_user_id() OR app.can_manage_messages(channel_id))
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'messages'::regclass AND polname = 'rls_messages_author_or_moderator_delete') THEN
        CREATE POLICY rls_messages_author_or_moderator_delete ON messages
            FOR DELETE USING (
                app.can_access_channel_like(channel_id)
                AND (author_id = app.current_user_id() OR app.can_manage_messages(channel_id))
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'attachments'::regclass AND polname = 'rls_attachments_channel_access_select') THEN
        CREATE POLICY rls_attachments_channel_access_select ON attachments
            FOR SELECT USING (app.can_access_channel_like(channel_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'attachments'::regclass AND polname = 'rls_attachments_uploader_insert') THEN
        CREATE POLICY rls_attachments_uploader_insert ON attachments
            FOR INSERT WITH CHECK (
                uploader_id = app.current_user_id()
                AND app.can_access_channel_like(channel_id)
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'attachments'::regclass AND polname = 'rls_attachments_uploader_or_manage_update') THEN
        CREATE POLICY rls_attachments_uploader_or_manage_update ON attachments
            FOR UPDATE USING (
                app.can_access_channel_like(channel_id)
                AND (uploader_id = app.current_user_id() OR app.can_manage_messages(channel_id))
            )
            WITH CHECK (
                app.can_access_channel_like(channel_id)
                AND (uploader_id = app.current_user_id() OR app.can_manage_messages(channel_id))
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'attachments'::regclass AND polname = 'rls_attachments_uploader_or_manage_delete') THEN
        CREATE POLICY rls_attachments_uploader_or_manage_delete ON attachments
            FOR DELETE USING (
                app.can_access_channel_like(channel_id)
                AND (uploader_id = app.current_user_id() OR app.can_manage_messages(channel_id))
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'reactions'::regclass AND polname = 'rls_reactions_message_access_select') THEN
        CREATE POLICY rls_reactions_message_access_select ON reactions
            FOR SELECT USING (app.can_access_message(message_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'reactions'::regclass AND polname = 'rls_reactions_own_insert') THEN
        CREATE POLICY rls_reactions_own_insert ON reactions
            FOR INSERT WITH CHECK (
                user_id = app.current_user_id()
                AND app.can_access_message(message_id)
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'reactions'::regclass AND polname = 'rls_reactions_own_or_manage_delete') THEN
        CREATE POLICY rls_reactions_own_or_manage_delete ON reactions
            FOR DELETE USING (
                app.can_access_message(message_id)
                AND (
                    user_id = app.current_user_id()
                    OR app.can_manage_messages(app.message_channel_id(message_id))
                )
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'read_states'::regclass AND polname = 'rls_read_states_own_rows') THEN
        CREATE POLICY rls_read_states_own_rows ON read_states
            USING (user_id = app.current_user_id())
            WITH CHECK (
                user_id = app.current_user_id()
                AND app.can_access_channel_like(channel_id)
            );
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'bots'::regclass AND polname = 'rls_bots_member_select') THEN
        CREATE POLICY rls_bots_member_select ON bots
            FOR SELECT USING (app.can_access_server(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'feeds'::regclass AND polname = 'rls_feeds_visible_select') THEN
        CREATE POLICY rls_feeds_visible_select ON feeds
            FOR SELECT USING (app.can_view_feed(id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'announcements'::regclass AND polname = 'rls_announcements_visible_select') THEN
        CREATE POLICY rls_announcements_visible_select ON announcements
            FOR SELECT USING (app.can_view_feed(feed_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'moderation_actions'::regclass AND polname = 'rls_moderation_member_select') THEN
        CREATE POLICY rls_moderation_member_select ON moderation_actions
            FOR SELECT USING (app.can_view_moderation_actions(server_id));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'reports'::regclass AND polname = 'rls_reports_reporter_select') THEN
        CREATE POLICY rls_reports_reporter_select ON reports
            FOR SELECT USING (reporter_id = app.current_user_id());
    END IF;
END $$;
