-- Add up migration script here

ALTER TABLE users ADD COLUMN staking_quota BIGINT NOT NULL default 3;