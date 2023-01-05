ALTER TABLE nodes
    DROP COLUMN IF EXISTS vcpu_count,
    DROP COLUMN IF EXISTS mem_size_mb,
    DROP COLUMN IF EXISTS disk_size_gb;
