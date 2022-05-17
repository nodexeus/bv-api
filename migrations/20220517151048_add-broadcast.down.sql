ALTER TABLE nodes DROP COLUMN IF EXISTS blockchain_id;

ALTER TABLE
	nodes
ADD
	COLUMN IF NOT EXISTS chain_type TEXT NOT NULL;

DROP TABLE IF EXISTS broadcast_logs;

DROP TABLE IF EXISTS broadcast_filters;

DROP TABLE IF EXISTS blockchains;

DROP TYPE IF EXISTS enum_blockchain_status;