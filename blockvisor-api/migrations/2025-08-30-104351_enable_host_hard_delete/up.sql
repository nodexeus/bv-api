-- Enable permanent deletion of hosts by ensuring proper cascade constraints
-- This allows hosts to be completely removed from the database

-- First, handle the foreign key constraints ON the hosts table itself
-- Drop existing constraints and recreate with SET NULL to prevent unwanted cascade deletion
ALTER TABLE hosts
    DROP CONSTRAINT IF EXISTS hosts_org_id_fkey1,
    DROP CONSTRAINT IF EXISTS fk_hosts_region_id;

-- Add new constraints with SET NULL behavior to prevent cascade deletion of parent records
ALTER TABLE hosts
    ADD CONSTRAINT hosts_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE SET NULL,
    ADD CONSTRAINT hosts_region_id_fkey FOREIGN KEY (region_id) REFERENCES regions(id) ON DELETE SET NULL;

-- Make the foreign key columns nullable to support SET NULL behavior
ALTER TABLE hosts ALTER COLUMN org_id DROP NOT NULL;
-- region_id should remain NOT NULL as regions are required for hosts

-- Ensure child tables will properly cascade delete when hosts are deleted
-- Commands should cascade delete when host is deleted
ALTER TABLE commands 
    DROP CONSTRAINT IF EXISTS fk_host_commands_hosts,
    ADD CONSTRAINT commands_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

-- IP addresses should cascade delete when host is deleted
ALTER TABLE ip_addresses
    DROP CONSTRAINT IF EXISTS ip_addresses_host_id_fkey,
    ADD CONSTRAINT ip_addresses_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

-- Node logs should cascade delete when host is deleted
ALTER TABLE node_logs
    DROP CONSTRAINT IF EXISTS node_logs_host_id_fkey,
    ADD CONSTRAINT node_logs_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

-- Host provisions should cascade delete when host is deleted (if table exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'host_provisions') THEN
        ALTER TABLE host_provisions 
            DROP CONSTRAINT IF EXISTS host_provisions_host_id_fkey,
            ADD CONSTRAINT host_provisions_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;
    END IF;
END$$;

-- NOTE: nodes.host_id already has ON DELETE SET NULL from the previous migration
-- This is correct - we don't want to delete nodes when a host is deleted,
-- just set their host_id to NULL so they can be rescheduled