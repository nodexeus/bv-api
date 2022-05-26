ALTER TABLE broadcast_filters DROP COLUMN IF EXISTS addresses;
ALTER TABLE broadcast_filters DROP COLUMN IF EXISTS txn_types;

ALTER TABLE broadcast_filters ADD COLUMN addresses TEXT;
ALTER TABLE broadcast_filters ADD COLUMN txn_types TEXT NOT NULL;