-- Add up migration script here
ALTER TABLE invoices ADD COLUMN earnings BIGINT NOT NULL DEFAULT 0;
ALTER TABLE invoices ADD COLUMN fee_bps BIGINT NOT NULL;