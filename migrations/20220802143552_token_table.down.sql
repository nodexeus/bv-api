ALTER TABLE hosts
    DROP COLUMN IF EXISTS token_id,
    ADD COLUMN token TEXT NOT NULL UNIQUE,
    DROP CONSTRAINT IF EXISTS fk_host_token;

ALTER TABLE users
    DROP COLUMN IF EXISTS token_id,
    ADD COLUMN token TEXT NOT NULL UNIQUE,
    ADD COLUMN role enum_user_role,
    DROP CONSTRAINT IF EXISTS fk_user_token;

DROP TABLE IF EXISTS tokens;
DROP TYPE IF EXISTS enum_token_role;
DROP INDEX IF EXISTS idx_token_strs;
CREATE TYPE enum_user_role AS ENUM ('user', 'admin');
