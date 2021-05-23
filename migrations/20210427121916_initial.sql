-- Add migration script here
-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE enum_conn_status AS ENUM ('online', 'offline');
CREATE TYPE enum_validator_status AS ENUM ('provisioning', 'syncing', 'upgrading', 'synced', 'consensus', 'stopped');
CREATE TYPE enum_stake_status AS ENUM ('available', 'staking', 'staked', 'delinquent', 'disabled');
CREATE TYPE enum_host_cmd AS ENUM ('restart_miner', 'restart_jail', 'get_miner_name', 'get_block_height', 'all');
CREATE TYPE enum_user_role AS ENUM ('user', 'admin');

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    hashword TEXT NOT NULL,
    salt TEXT NOT NULL,
    token TEXT UNIQUE,
    refresh TEXT UNIQUE DEFAULT uuid_generate_v4(),
    role enum_user_role NOT NULL DEFAULT 'user',
    fee_bps BIGINT NOT NULL DEFAULT 500,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email on users (email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_refresh on users (refresh);

CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version TEXT,
    name TEXT UNIQUE NOT NULL,
    location TEXT,
    ip_addr TEXT UNIQUE NOT NULL,
    val_ip_addrs TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    status enum_conn_status NOT NULL DEFAULT 'offline',
    created_at TIMESTAMPTZ NOT NULL default now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_name on hosts (name);

CREATE TABLE IF NOT EXISTS validators (
    id UUID PRIMARY KEY  DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL,
    version TEXT,
    host_id UUID NOT NULL,
    user_id UUID,
    ip_addr TEXT UNIQUE NOT NULL,
    address TEXT UNIQUE,
    swarm_key TEXT,
    block_height BIGINT,
    stake_status enum_stake_status NOT NULL DEFAULT 'available',
    status enum_validator_status NOT NULL DEFAULT 'provisioning',
    score BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_validators_hosts FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    CONSTRAINT fk_validators_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_validators_user_id on validators(user_id);
CREATE INDEX IF NOT EXISTS idx_validators_host_id on validators(host_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_validators_address on validators(address);
CREATE INDEX IF NOT EXISTS idx_validators_status on validators(status);
CREATE INDEX IF NOT EXISTS idx_validators_stake_status on validators(stake_status);
CREATE INDEX IF NOT EXISTS idx_validators_created_at on validators(created_at);

CREATE TABLE IF NOT EXISTS commands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id UUID NOT NULL,
    cmd enum_host_cmd NOT NULL,
    sub_cmd TEXT,
    response TEXT,
    exit_status INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT fk_host_commands_hosts FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_commands_host_id on commands(host_id);
CREATE INDEX IF NOT EXISTS idx_commands_created_at on commands(created_at);
CREATE INDEX IF NOT EXISTS idx_commands_completed_at on commands(completed_at);

CREATE TABLE IF NOT EXISTS rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    block BIGINT NOT NULL,
    transaction_hash TEXT NOT NULL,
    time BIGINT NOT NULL,
    validator_id UUID NOT NULL,
    account TEXT NOT NULL,
    amount BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rewards_block on rewards(block);
CREATE INDEX IF NOT EXISTS idx_rewards_validator_id on rewards(validator_id);
CREATE INDEX IF NOT EXISTS idx_rewards_account on rewards(account);

