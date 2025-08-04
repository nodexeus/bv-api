-- Resource Tracking Repair Script
-- This script repairs resource tracking inconsistencies in the database
-- Run this script if you need to manually fix resource tracking issues

-- WARNING: This script modifies data. Make sure to backup your database first!

BEGIN;

-- Step 1: Update node resource fields to match their configurations
-- This query finds nodes where the stored resource values don't match their config
WITH node_config_resources AS (
    SELECT 
        n.id as node_id,
        n.node_name,
        n.cpu_cores as stored_cpu,
        n.memory_bytes as stored_memory,
        n.disk_bytes as stored_disk,
        -- Extract resource requirements from config JSON
        CAST((c.config::jsonb->'vm'->>'cpu_cores')::text AS bigint) as config_cpu,
        CAST((c.config::jsonb->'vm'->>'memory_bytes')::text AS bigint) as config_memory,
        CAST((c.config::jsonb->'vm'->>'disk_bytes')::text AS bigint) as config_disk
    FROM nodes n
    INNER JOIN configs c ON n.config_id = c.id
    WHERE n.deleted_at IS NULL
),
node_inconsistencies AS (
    SELECT *
    FROM node_config_resources
    WHERE stored_cpu != config_cpu 
       OR stored_memory != config_memory 
       OR stored_disk != config_disk
)
UPDATE nodes 
SET 
    cpu_cores = ni.config_cpu,
    memory_bytes = ni.config_memory,
    disk_bytes = ni.config_disk
FROM node_inconsistencies ni
WHERE nodes.id = ni.node_id;

-- Log the number of nodes updated
SELECT 
    COUNT(*) as nodes_updated,
    'Node resource fields updated to match configurations' as description
FROM (
    SELECT n.id
    FROM nodes n
    INNER JOIN configs c ON n.config_id = c.id
    WHERE n.deleted_at IS NULL
    AND (
        n.cpu_cores != CAST((c.config::jsonb->'vm'->>'cpu_cores')::text AS bigint)
        OR n.memory_bytes != CAST((c.config::jsonb->'vm'->>'memory_bytes')::text AS bigint)
        OR n.disk_bytes != CAST((c.config::jsonb->'vm'->>'disk_bytes')::text AS bigint)
    )
) updated_nodes;

-- Step 2: Update host resource counters to match actual node allocations
-- This query recalculates host counters from the sum of node allocations
WITH host_actual_resources AS (
    SELECT 
        h.id as host_id,
        h.network_name as host_name,
        h.node_cpu_cores as stored_cpu,
        h.node_memory_bytes as stored_memory,
        h.node_disk_bytes as stored_disk,
        COALESCE(SUM(n.cpu_cores), 0) as actual_cpu,
        COALESCE(SUM(n.memory_bytes), 0) as actual_memory,
        COALESCE(SUM(n.disk_bytes), 0) as actual_disk
    FROM hosts h
    LEFT JOIN nodes n ON h.id = n.host_id AND n.deleted_at IS NULL
    WHERE h.deleted_at IS NULL
    GROUP BY h.id, h.network_name, h.node_cpu_cores, h.node_memory_bytes, h.node_disk_bytes
),
host_inconsistencies AS (
    SELECT *
    FROM host_actual_resources
    WHERE stored_cpu != actual_cpu 
       OR stored_memory != actual_memory 
       OR stored_disk != actual_disk
)
UPDATE hosts 
SET 
    node_cpu_cores = hi.actual_cpu,
    node_memory_bytes = hi.actual_memory,
    node_disk_bytes = hi.actual_disk
FROM host_inconsistencies hi
WHERE hosts.id = hi.host_id;

-- Log the number of hosts updated
SELECT 
    COUNT(*) as hosts_updated,
    'Host resource counters updated to match actual node allocations' as description
FROM (
    SELECT h.id
    FROM hosts h
    LEFT JOIN (
        SELECT 
            host_id,
            SUM(cpu_cores) as total_cpu,
            SUM(memory_bytes) as total_memory,
            SUM(disk_bytes) as total_disk
        FROM nodes 
        WHERE deleted_at IS NULL 
        GROUP BY host_id
    ) node_totals ON h.id = node_totals.host_id
    WHERE h.deleted_at IS NULL
    AND (
        h.node_cpu_cores != COALESCE(node_totals.total_cpu, 0)
        OR h.node_memory_bytes != COALESCE(node_totals.total_memory, 0)
        OR h.node_disk_bytes != COALESCE(node_totals.total_disk, 0)
    )
) updated_hosts;

-- Step 3: Validation queries to verify the repairs worked
-- These queries should return 0 rows if everything is consistent

-- Check for remaining node resource inconsistencies
SELECT 
    'Node resource inconsistencies remaining' as check_type,
    COUNT(*) as inconsistency_count
FROM (
    SELECT n.id
    FROM nodes n
    INNER JOIN configs c ON n.config_id = c.id
    WHERE n.deleted_at IS NULL
    AND (
        n.cpu_cores != CAST((c.config::jsonb->'vm'->>'cpu_cores')::text AS bigint)
        OR n.memory_bytes != CAST((c.config::jsonb->'vm'->>'memory_bytes')::text AS bigint)
        OR n.disk_bytes != CAST((c.config::jsonb->'vm'->>'disk_bytes')::text AS bigint)
    )
) remaining_node_issues;

-- Check for remaining host counter inconsistencies
SELECT 
    'Host counter inconsistencies remaining' as check_type,
    COUNT(*) as inconsistency_count
FROM (
    SELECT h.id
    FROM hosts h
    LEFT JOIN (
        SELECT 
            host_id,
            SUM(cpu_cores) as total_cpu,
            SUM(memory_bytes) as total_memory,
            SUM(disk_bytes) as total_disk
        FROM nodes 
        WHERE deleted_at IS NULL 
        GROUP BY host_id
    ) node_totals ON h.id = node_totals.host_id
    WHERE h.deleted_at IS NULL
    AND (
        h.node_cpu_cores != COALESCE(node_totals.total_cpu, 0)
        OR h.node_memory_bytes != COALESCE(node_totals.total_memory, 0)
        OR h.node_disk_bytes != COALESCE(node_totals.total_disk, 0)
    )
) remaining_host_issues;

-- Summary of database state after repair
SELECT 
    'Database summary after repair' as summary_type,
    (SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL) as total_active_nodes,
    (SELECT COUNT(*) FROM hosts WHERE deleted_at IS NULL) as total_active_hosts,
    (SELECT SUM(cpu_cores) FROM nodes WHERE deleted_at IS NULL) as total_node_cpu_allocated,
    (SELECT SUM(node_cpu_cores) FROM hosts WHERE deleted_at IS NULL) as total_host_cpu_counters;

COMMIT;

-- If you want to see detailed information about what was repaired, uncomment these queries:

/*
-- Show nodes that had resource inconsistencies (before repair)
WITH node_config_resources AS (
    SELECT 
        n.id as node_id,
        n.node_name,
        n.cpu_cores as stored_cpu,
        n.memory_bytes as stored_memory,
        n.disk_bytes as stored_disk,
        CAST((c.config::jsonb->'vm'->>'cpu_cores')::text AS bigint) as config_cpu,
        CAST((c.config::jsonb->'vm'->>'memory_bytes')::text AS bigint) as config_memory,
        CAST((c.config::jsonb->'vm'->>'disk_bytes')::text AS bigint) as config_disk
    FROM nodes n
    INNER JOIN configs c ON n.config_id = c.id
    WHERE n.deleted_at IS NULL
)
SELECT 
    'Node inconsistencies that were repaired' as report_type,
    node_id,
    node_name,
    stored_cpu,
    stored_memory,
    stored_disk,
    config_cpu,
    config_memory,
    config_disk
FROM node_config_resources
WHERE stored_cpu != config_cpu 
   OR stored_memory != config_memory 
   OR stored_disk != config_disk;

-- Show hosts that had counter inconsistencies (before repair)
WITH host_actual_resources AS (
    SELECT 
        h.id as host_id,
        h.network_name as host_name,
        h.node_cpu_cores as stored_cpu,
        h.node_memory_bytes as stored_memory,
        h.node_disk_bytes as stored_disk,
        COALESCE(SUM(n.cpu_cores), 0) as actual_cpu,
        COALESCE(SUM(n.memory_bytes), 0) as actual_memory,
        COALESCE(SUM(n.disk_bytes), 0) as actual_disk
    FROM hosts h
    LEFT JOIN nodes n ON h.id = n.host_id AND n.deleted_at IS NULL
    WHERE h.deleted_at IS NULL
    GROUP BY h.id, h.network_name, h.node_cpu_cores, h.node_memory_bytes, h.node_disk_bytes
)
SELECT 
    'Host inconsistencies that were repaired' as report_type,
    host_id,
    host_name,
    stored_cpu,
    stored_memory,
    stored_disk,
    actual_cpu,
    actual_memory,
    actual_disk
FROM host_actual_resources
WHERE stored_cpu != actual_cpu 
   OR stored_memory != actual_memory 
   OR stored_disk != actual_disk;
*/