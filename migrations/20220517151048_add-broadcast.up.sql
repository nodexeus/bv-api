CREATE TYPE enum_blockchain_status AS ENUM (
	'development',
	'alpha',
	'beta',
	'production',
	'deleted'
);

CREATE TABLE IF NOT EXISTS blockchains (
	id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	name Text NOT NULL,
	description TEXT,
	status enum_blockchain_status NOT NULL DEFAULT 'development',
	project_url TEXT,
	repo_url TEXT,
	supports_etl BOOLEAN NOT NULL DEFAULT true,
	supports_api BOOLEAN NOT NULL DEFAULT true,
	supports_staking BOOLEAN NOT NULL DEFAULT true,
	supports_broadcast BOOLEAN NOT NULL DEFAULT true,
	is_dev_only BOOLEAN NOT NULL DEFAULT false,
	version Text,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_blockchains_name on nodes(lower(name));

CREATE TABLE IF NOT EXISTS broadcast_filters (
	id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	blockchain_id UUID NOT NULL REFERENCES blockchains(id) ON DELETE CASCADE,
	org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	addresses TEXT,
	callback_url TEXT NOT NULL,
	auth_token TEXT NOT NULL,
	txn_types TEXT NOT NULL,
	is_active BOOLEAN NOT NULL DEFAULT true,
	last_processed_height BIGINT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_broadcast_filters_org_id_name on nodes(org_id, lower(name));

CREATE INDEX IF NOT EXISTS idx_broadcast_filters_blockchain_id on broadcast_filters(blockchain_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_filters_org_id on broadcast_filters(org_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_filters_blockchain_id on broadcast_filters(blockchain_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_filters_is_active on broadcast_filters(is_active);

CREATE INDEX IF NOT EXISTS idx_broadcast_filters_created_at on broadcast_filters(created_at);

CREATE INDEX IF NOT EXISTS idx_broadcast_filters_updated_at on broadcast_filters(updated_at);

CREATE TABLE IF NOT EXISTS broadcast_logs (
	id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	blockchain_id UUID NOT NULL,
	org_id UUID NOT NULL,
	broadcast_filter_id UUID NOT NULL,
	address_count BIGINT NOT NULL DEFAULT 0,
	txn_count BIGINT NOT NULL DEFAULT 0,
	event_type TEXT NOT NULL,
	event_msg TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_broadcast_logs_blockchain_id on broadcast_logs(blockchain_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_logs_org_id on broadcast_logs(org_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_logs_broadcast_filter_id on broadcast_logs(broadcast_filter_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_logs_event_type on broadcast_logs(blockchain_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_logs_created_at on broadcast_logs(created_at);