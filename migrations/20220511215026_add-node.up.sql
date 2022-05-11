CREATE TYPE enum_node_type AS ENUM (
	'api',
	'node',
	'oracle',
	'relay',
	'validator'
);

CREATE TYPE enum_node_status AS ENUM (
	'available',
	'broadcasting',
	'cancelled',
	'consensus',
	'creating',
	'delegating',
	'delinquent',
	'disabled',
	'earning',
	'electing',
	'elected',
	'exporting',
	'ingesting',
	'installing',
	'migrating',
	'mining',
	'minting',
	'processing',
	'relaying',
	'removed',
	'removing',
	'running',
	'snapshoting',
	'staked',
	'staking',
	'started',
	'starting',
	'stopped',
	'stopping',
	'synced',
	'syncing',
	'upgrading',
	'validating'
);

CREATE TABLE IF NOT EXISTS nodes (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	name Text,
	groups Text,
	version Text,
	ip_addr Text,
	chain_type Text NOT NULL,
	node_type enum_node_type NOT NULL,
	address Text,
	wallet_address Text,
	block_height BIGINT,
	node_data JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	status enum_node_status NOT NULL DEFAULT 'creating',
	is_online BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_nodes_org_id on nodes(org_id);

CREATE INDEX IF NOT EXISTS idx_nodes_host_id on nodes(host_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_org_id_name on nodes(org_id, lower(name));

CREATE INDEX IF NOT EXISTS idx_nodes_groups on nodes(lower(groups));

CREATE INDEX IF NOT EXISTS idx_nodes_node_data on nodes(node_data);

CREATE INDEX IF NOT EXISTS idx_nodes_chain_type_version on nodes(chain_type, version);

CREATE INDEX IF NOT EXISTS idx_nodes_chain_type_node_type on nodes(chain_type, node_type);

CREATE INDEX IF NOT EXISTS idx_nodes_created_at on nodes(created_at);

CREATE INDEX IF NOT EXISTS idx_nodes_status on nodes(status);

CREATE INDEX IF NOT EXISTS idx_nodes_is_online on nodes(is_online);