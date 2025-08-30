-- Enable hard deletion of nodes by modifying foreign key constraints
-- This allows nodes to be completely removed from the database rather than just soft-deleted

-- Drop existing RESTRICT constraints on nodes table (use IF EXISTS to handle missing constraints)
ALTER TABLE nodes
    DROP CONSTRAINT IF EXISTS nodes_host_id_fkey1,
    DROP CONSTRAINT IF EXISTS nodes_org_id_fkey1,
    DROP CONSTRAINT IF EXISTS nodes_image_id_fkey,
    DROP CONSTRAINT IF EXISTS nodes_config_id_fkey,
    DROP CONSTRAINT IF EXISTS nodes_protocol_id_fkey,
    DROP CONSTRAINT IF EXISTS nodes_protocol_version_id_fkey,
    DROP CONSTRAINT IF EXISTS nodes_scheduler_region_id_fkey;

-- Add new constraints with CASCADE for hard deletion support
-- Note: We use SET NULL for some relationships to prevent unwanted cascade deletion
-- of important parent records (hosts, orgs, protocols, images, configs, regions)
ALTER TABLE nodes
    ADD CONSTRAINT nodes_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_image_id_fkey FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_config_id_fkey FOREIGN KEY (config_id) REFERENCES configs(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_protocol_id_fkey FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_protocol_version_id_fkey FOREIGN KEY (protocol_version_id) REFERENCES protocol_versions(id) ON DELETE SET NULL,
    ADD CONSTRAINT nodes_scheduler_region_id_fkey FOREIGN KEY (scheduler_region_id) REFERENCES regions(id) ON DELETE SET NULL;

-- Make the foreign key columns nullable to support SET NULL behavior
ALTER TABLE nodes ALTER COLUMN host_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN image_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN config_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN protocol_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN protocol_version_id DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN scheduler_region_id DROP NOT NULL;

-- Ensure child tables will properly cascade delete when nodes are hard deleted
-- These should already have CASCADE, but let's verify and update if needed

-- Commands should cascade delete when node is deleted
ALTER TABLE commands 
    DROP CONSTRAINT IF EXISTS fk_commands_node_id,
    DROP CONSTRAINT IF EXISTS commands_node_id_fkey,
    ADD CONSTRAINT commands_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;

-- Node reports should cascade delete when node is deleted
ALTER TABLE node_reports
    DROP CONSTRAINT IF EXISTS node_reports_node_id_fkey,
    ADD CONSTRAINT node_reports_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;

-- Node logs should cascade delete when node is deleted
ALTER TABLE node_logs
    DROP CONSTRAINT IF EXISTS node_logs_node_id_fkey,
    ADD CONSTRAINT node_logs_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;