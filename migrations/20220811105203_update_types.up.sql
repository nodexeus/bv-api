-- add node types
ALTER TYPE enum_node_type ADD VALUE IF NOT EXISTS 'undefined' BEFORE 'api';
ALTER TYPE enum_node_type ADD VALUE IF NOT EXISTS 'miner';

-- add node states
CREATE TYPE enum_node_sync_status AS ENUM ('unknown', 'syncing', 'synced');
CREATE TYPE enum_node_staking_status AS ENUM
    (
        'unknown', 'follower', 'staked', 'staking', 'validating', 'consensus', 'unstaked'
    );
CREATE TYPE enum_node_chain_status AS ENUM
    (
        'unknown', 'broadcasting', 'cancelled', 'delegating', 'delinquent', 'disabled', 'earning', 'electing', 'elected',
        'exported', 'ingesting', 'mining', 'minting', 'processing', 'relaying', 'removed', 'removing'
    );
CREATE TYPE enum_container_status AS ENUM
    (
        'unknown', 'creating', 'running', 'starting', 'stopping', 'stopped', 'upgrading', 'upgraded', 'deleting', 'deleted',
        'installing', 'snapshotting'
    );

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS sync_status enum_node_sync_status DEFAULT 'unknown'::enum_node_sync_status NOT NULL,
    ADD COLUMN IF NOT EXISTS chain_status enum_node_chain_status DEFAULT 'unknown'::enum_node_chain_status NOT NULL,
    ADD COLUMN IF NOT EXISTS staking_status enum_node_staking_status DEFAULT 'unknown'::enum_node_staking_status,
    ADD COLUMN IF NOT EXISTS container_status enum_container_status DEFAULT 'unknown'::enum_container_status NOT NULL,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS is_online;

DROP TYPE IF EXISTS enum_node_status;
