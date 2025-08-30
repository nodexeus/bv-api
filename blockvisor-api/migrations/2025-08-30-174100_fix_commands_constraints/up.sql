-- Fix commands table foreign key constraints for proper cascade deletion
-- This migration addresses the duplicate and incorrectly named constraints

-- Drop all existing foreign key constraints on commands table
ALTER TABLE commands 
    DROP CONSTRAINT IF EXISTS fk_commands_node_id,
    DROP CONSTRAINT IF EXISTS commands_node_id_fkey,
    DROP CONSTRAINT IF EXISTS fk_commands_host_id,
    DROP CONSTRAINT IF EXISTS commands_host_id_fkey,
    DROP CONSTRAINT IF EXISTS fk_host_commands_hosts;

-- Recreate constraints with proper CASCADE behavior
ALTER TABLE commands
    ADD CONSTRAINT commands_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    ADD CONSTRAINT commands_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;