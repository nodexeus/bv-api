-- Add up migration script here

ALTER TABLE validators ADD COLUMN owner_address TEXT;
