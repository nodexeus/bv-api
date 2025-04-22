-- Add APR field to nodes table
ALTER TABLE nodes
ADD COLUMN apr DOUBLE PRECISION;

-- Create an index for efficient sorting by APR
CREATE INDEX idx_nodes_apr ON nodes USING btree (apr);
