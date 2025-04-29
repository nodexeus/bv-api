-- Drop the SQD Name column from nodes table
ALTER TABLE nodes
DROP COLUMN sqd_name;

-- Drop the index for efficient sorting by SQD Name
DROP INDEX idx_nodes_sqd_name;