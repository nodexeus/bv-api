ALTER TABLE blockchains DROP COLUMN supported_node_types;
ALTER TABLE nodes DROP COLUMN node_type;

ALTER TABLE blockchains ADD COLUMN supported_node_types jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE nodes ADD COLUMN node_type jsonb NOT NULL DEFAULT '{}'::jsonb;
