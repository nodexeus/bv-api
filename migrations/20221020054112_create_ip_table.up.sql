CREATE TABLE IF NOT EXISTS ip_addresses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip inet UNIQUE NOT NULL,
    host_id UUID NULL,
    is_assigned bool NOT NULL DEFAULT false,
    FOREIGN KEY (host_id) REFERENCES hosts ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ip_addrs on ip_addresses(ip);
