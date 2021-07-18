-- Add down migration script her
DROP TABLE IF EXISTS invoices;
ALTER TABLE users DROP COLUMN pay_address;