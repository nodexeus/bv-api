-- Add up migration script here

ALTER TABLE validators DROP COLUMN score;
ALTER TABLE validators ADD COLUMN tenure_penalty FLOAT NOT NULL DEFAULT 0;
ALTER TABLE validators ADD COLUMN dkg_penalty FLOAT NOT NULL DEFAULT 0;
ALTER TABLE validators ADD COLUMN performance_penalty FLOAT NOT NULL DEFAULT 0;
ALTER TABLE validators ADD COLUMN total_penalty FLOAT NOT NULL DEFAULT 0;