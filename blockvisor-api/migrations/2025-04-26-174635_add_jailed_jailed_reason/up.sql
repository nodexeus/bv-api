-- Add Jailed and JailedReason fields to nodes table
ALTER TABLE nodes
ADD COLUMN jailed BOOLEAN;
ALTER TABLE nodes
ADD COLUMN jailed_reason VARCHAR(255);

-- Create an index for efficient sorting by jailed status
CREATE INDEX idx_nodes_jailed ON nodes USING btree (jailed);
