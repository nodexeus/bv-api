-- Add up migration script here
ALTER TABLE info ADD COLUMN staked_count BIGINT DEFAULT 0;
ALTER TABLE info ADD COLUMN oracle_price BIGINT DEFAULT 0; -- Divide by 100000000 to get USD value