-- Add down migration script here

ALTER TABLE hosts
    DROP COLUMN used_cpu,
    DROP COLUMN used_memory,
    DROP COLUMN used_disk_space,
    DROP COLUMN load_one,
    DROP COLUMN load_five,
    DROP COLUMN load_fifteen,
    DROP COLUMN network_received,
    DROP COLUMN network_sent,
    DROP COLUMN uptime;
