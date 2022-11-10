DROP TABLE user_tokens;
DROP TABLE host_tokens;
DROP TABLE tokens;

CREATE TABLE IF NOT EXISTS token_blacklist (
    token TEXT PRIMARY KEY NOT NULL,
    token_type token_type NOT NULL
);
