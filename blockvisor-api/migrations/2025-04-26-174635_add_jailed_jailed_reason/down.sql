-- Drop the Jailed and JailedReason columns from nodes table
ALTER TABLE nodes
DROP COLUMN jailed;
ALTER TABLE nodes
DROP COLUMN jailed_reason;

-- Drop the index for efficient sorting by jailed status
DROP INDEX idx_nodes_jailed;