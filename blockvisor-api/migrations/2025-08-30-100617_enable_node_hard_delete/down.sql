-- Revert hard deletion changes - restore original RESTRICT constraints

-- Make foreign key columns NOT NULL again
ALTER TABLE nodes ALTER COLUMN host_id SET NOT NULL;
ALTER TABLE nodes ALTER COLUMN org_id SET NOT NULL; 
ALTER TABLE nodes ALTER COLUMN blockchain_id SET NOT NULL;

-- Restore RESTRICT constraints on nodes table
ALTER TABLE nodes
    DROP CONSTRAINT nodes_host_id_fkey,
    DROP CONSTRAINT nodes_org_id_fkey,
    DROP CONSTRAINT nodes_blockchain_id_fkey;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
    ADD CONSTRAINT nodes_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE RESTRICT,
    ADD CONSTRAINT nodes_blockchain_id_fkey FOREIGN KEY (blockchain_id) REFERENCES blockchains(id) ON DELETE RESTRICT;