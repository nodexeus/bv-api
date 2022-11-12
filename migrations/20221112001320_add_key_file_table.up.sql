CREATE TABLE IF NOT EXISTS node_key_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4() NOT NULL,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    node_id UUID NOT NULL REFERENCES nodes ON DELETE CASCADE
);
