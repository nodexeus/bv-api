-- Add down migration script here

ALTER TABLE validators ADD COLUMN score BIGINT NOT NULL DEFAULT 0;
ALTER TABLE validators DROP COLUMN tenure_penalty;
ALTER TABLE validators DROP COLUMN dkg_penalty;
ALTER TABLE validators DROP COLUMN performance_penalty;
ALTER TABLE validators DROP COLUMN total_penalty;