-- Enable hard deletion of nodes by modifying foreign key constraints
-- This allows nodes to be completely removed from the database rather than just soft-deleted

-- Drop existing RESTRICT constraints on nodes table
ALTER TABLE nodes
    DROP CONSTRAINT nodes_host_id_fkey,
    DROP CONSTRAINT nodes_org_id_fkey,
    DROP CONSTRAINT nodes_blockchain_id_fkey;

-- Add new constraints with CASCADE for hard deletion support
-- Note: We use SET NULL for some relationships to prevent unwanted cascade deletion
-- of important parent records (hosts, orgs, blockchains)
ALTER TABLE nodes
    ADD CONSTRAINT nodes_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_blockchain_id_fkey FOREIGN KEY (blockchain_id) REFERENCES blockchains(id) ON DELETE SET NULL;

-- Make the foreign key columns nullable to support SET NULL behavior
ALTER TABLE nodes ALTER COLUMN host_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN blockchain_id DROP NOT NULL;

-- Ensure child tables will properly cascade delete when nodes are hard deleted
-- These should already have CASCADE, but let's verify and update if needed

-- Commands should cascade delete when node is deleted
ALTER TABLE commands 
    DROP CONSTRAINT IF EXISTS commands_node_id_fkey,
    ADD CONSTRAINT commands_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;

-- Node key files should cascade delete when node is deleted  
ALTER TABLE node_key_files
    DROP CONSTRAINT IF EXISTS node_key_files_node_id_fkey,
    ADD CONSTRAINT node_key_files_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;

-- Node reports should cascade delete when node is deleted
ALTER TABLE node_reports
    DROP CONSTRAINT IF EXISTS node_reports_node_id_fkey,
    ADD CONSTRAINT node_reports_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;

-- Node properties should cascade delete when node is deleted (if table exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'node_properties') THEN
        ALTER TABLE node_properties 
            DROP CONSTRAINT IF EXISTS node_properties_node_id_fkey,
            ADD CONSTRAINT node_properties_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
    END IF;
END$$;

-- Node logs should cascade delete when node is deleted
ALTER TABLE node_logs
    DROP CONSTRAINT IF EXISTS node_logs_node_id_fkey,
    ADD CONSTRAINT node_logs_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;