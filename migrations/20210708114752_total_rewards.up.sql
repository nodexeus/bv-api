-- Add up migration script here
ALTER TABLE info
ADD COLUMN total_rewards BIGINT DEFAULT 0;