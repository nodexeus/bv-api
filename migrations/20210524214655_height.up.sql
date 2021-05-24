-- Add up migration script here
CREATE TABLE IF NOT EXISTS info (
    block_height BIGINT PRIMARY KEY NOT NULL DEFAULT 0
);

INSERT INTO info (block_height) VALUES (0);