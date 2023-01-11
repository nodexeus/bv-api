ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS vcpu_count bigint default 0 not null,
    ADD COLUMN IF NOT EXISTS mem_size_mb bigint default 0 not null,
    ADD COLUMN IF NOT EXISTS disk_size_gb bigint default 0 not null;
