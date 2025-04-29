-- Add SQD Name field to nodes table
ALTER TABLE nodes
ADD COLUMN sqd_name VARCHAR(255);

-- Create an index for efficient sorting by SQD Name
CREATE INDEX idx_nodes_sqd_name ON nodes USING btree (sqd_name);
