CREATE TYPE enum_token_role as enum ('user', 'admin', 'service', 'guest');

CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    host_id UUID,
    user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT now() + interval '1 day' NOT NULL,
    role enum_token_role not null,
    FOREIGN KEY (host_id)
        REFERENCES hosts (id),
    FOREIGN KEY (user_id)
        REFERENCES users (id)
);