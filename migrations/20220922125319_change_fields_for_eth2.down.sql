ALTER TABLE blockchains DROP COLUMN supported_node_types;
ALTER TABLE nodes DROP COLUMN node_type;

ALTER TABLE blockchains ADD COLUMN supported_node_types enum_node_type[] NOT NULL DEFAULT '{"undefined"}';
ALTER TABLE nodes ADD COLUMN node_type enum_node_type NOT NULL DEFAULT 'undefined'::enum_node_type;
