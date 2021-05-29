-- Add up migration script here

ALTER TABLE validators ADD COLUMN address_name TEXT;
CREATE INDEX IF NOT EXISTS idx_validators_address_name on validators(address_name);
