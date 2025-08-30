-- Rollback commands table foreign key constraint fixes
-- This restores the original duplicate constraints (not recommended)

-- Drop the clean constraints
ALTER TABLE commands 
    DROP CONSTRAINT IF EXISTS commands_node_id_fkey,
    DROP CONSTRAINT IF EXISTS commands_host_id_fkey;

-- Restore the original duplicate constraints
ALTER TABLE commands
    ADD CONSTRAINT fk_commands_node_id FOREIGN KEY (node_id) REFERENCES nodes(id),
    ADD CONSTRAINT commands_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id),
    ADD CONSTRAINT fk_commands_host_id FOREIGN KEY (host_id) REFERENCES hosts(id),
    ADD CONSTRAINT commands_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id);