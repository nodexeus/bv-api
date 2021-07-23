-- Add down migration script here
ALTER TABLE invoices DROP COLUMN IF EXISTS earnings;
ALTER TABLE invoices DROP COLUMN IF EXISTS fee_bps;