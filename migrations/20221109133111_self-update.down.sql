-- Add down migration script here

ALTER TABLE nodes DROP COLUMN self_update;
