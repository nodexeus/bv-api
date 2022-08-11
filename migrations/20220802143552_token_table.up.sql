DO $$ BEGIN
    CREATE TYPE enum_token_role AS ENUM ('user', 'admin', 'service', 'guest');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token TEXT NOT NULL UNIQUE,
    host_id UUID NULL,
    user_id UUID NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT now() + interval '1 day' NOT NULL,
    role enum_token_role not null,
    FOREIGN KEY (host_id)
        REFERENCES hosts (id),
    FOREIGN KEY (user_id)
        REFERENCES users (id)
);
CREATE INDEX IF NOT EXISTS idx_token_strs on tokens(token);

ALTER TABLE hosts
    DROP COLUMN IF EXISTS token,
    ADD COLUMN IF NOT EXISTS token_id UUID;
    -- ADD CONSTRAINT fk_host_token FOREIGN KEY (token_id) REFERENCES tokens (id) ON DELETE CASCADE;

DO $$ BEGIN
    ALTER TABLE hosts
        ADD CONSTRAINT fk_host_token FOREIGN KEY (token_id) REFERENCES tokens (id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

ALTER TABLE users
    DROP COLUMN IF EXISTS token,
    DROP COLUMN IF EXISTS role,
    ADD COLUMN IF NOT EXISTS token_id UUID;
    -- ADD CONSTRAINT fk_user_token FOREIGN KEY (token_id) REFERENCES tokens (id) ON DELETE CASCADE;

DO $$ BEGIN
    ALTER TABLE users
        ADD CONSTRAINT fk_user_token FOREIGN KEY (token_id) REFERENCES tokens (id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DROP TYPE IF EXISTS enum_user_role;
