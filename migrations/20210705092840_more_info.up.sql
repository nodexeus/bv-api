-- Add up migration script here
ALTER TABLE info ADD COLUMN staked_count BIGINT;
ALTER TABLE info ADD COLUMN staked_total_hnt BIGINT;
ALTER TABLE info ADD COLUMN staked_total_usd BIGINT;