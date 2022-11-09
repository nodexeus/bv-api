-- Add up migration script here

ALTER TABLE nodes ADD COLUMN self_update BOOLEAN NOT NULL DEFAULT FALSE;
