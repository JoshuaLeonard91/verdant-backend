ALTER TABLE users
    ADD COLUMN IF NOT EXISTS member_list_banner_url TEXT,
    ADD COLUMN IF NOT EXISTS member_list_banner_crop_x DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS member_list_banner_crop_y DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS member_list_banner_crop_width DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS member_list_banner_crop_height DOUBLE PRECISION;
