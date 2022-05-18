DROP INDEX IF EXISTS idx_hosts_name;

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_name_key;

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_ip_addr_key;

CREATE UNIQUE INDEX idx_orgs_name_unique on hosts(org_id, name);