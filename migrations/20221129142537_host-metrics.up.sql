-- Add up migration script here

ALTER TABLE hosts
    ADD COLUMN used_cpu INT NULL,
    ADD COLUMN used_memory BIGINT NULL,
    ADD COLUMN used_disk_space BIGINT NULL,
    ADD COLUMN load_one DOUBLE PRECISION NULL,
    ADD COLUMN load_five DOUBLE PRECISION NULL,
    ADD COLUMN load_fifteen DOUBLE PRECISION NULL,
    ADD COLUMN network_received BIGINT NULL,
    ADD COLUMN network_sent BIGINT NULL,
    ADD COLUMN uptime BIGINT NULL;
