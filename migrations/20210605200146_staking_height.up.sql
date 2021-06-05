-- Add up migration script here

ALTER TABLE validators ADD COLUMN staking_height BIGINT;
