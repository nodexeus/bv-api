DROP TABLE IF EXISTS token_blacklist;

CREATE TABLE IF NOT EXISTS tokens (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      token TEXT NOT NULL UNIQUE,
      host_id UUID NULL,
      user_id UUID NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
      expires_at TIMESTAMP WITH TIME ZONE DEFAULT now() + interval '1 day' NOT NULL,
      role enum_token_role not null,
      FOREIGN KEY (host_id)
          REFERENCES hosts (id) ON DELETE CASCADE,
      FOREIGN KEY (user_id)
          REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_tokens (
     user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
     token_id UUID NOT NULL REFERENCES tokens ON DELETE CASCADE,
     token_type token_type NOT NULL,
     PRIMARY KEY (user_id, token_type)
);

CREATE TABLE host_tokens (
     host_id UUID NOT NULL REFERENCES hosts ON DELETE CASCADE,
     token_id UUID NOT NULL REFERENCES tokens ON DELETE CASCADE,
     token_type token_type NOT NULL,
     PRIMARY KEY (host_id, token_type)
);
