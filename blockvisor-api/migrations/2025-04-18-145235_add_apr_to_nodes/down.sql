-- Drop the APR column from nodes table
ALTER TABLE nodes
DROP COLUMN apr;

-- Drop the index for efficient sorting by APR
DROP INDEX idx_nodes_apr;
