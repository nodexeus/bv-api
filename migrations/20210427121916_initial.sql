-- Add migration script here
-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE enum_conn_status AS ENUM ('online', 'offline');
CREATE TYPE enum_validator_status AS ENUM ('provisioning', 'syncing', 'upgrading', 'synced', 'consensus', 'stopped');
CREATE TYPE enum_stake_status AS ENUM ('available', 'staking', 'staked', 'delinquent', 'disabled');
 
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    hashword TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email on users (email);

CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version TEXT,
    name TEXT UNIQUE NOT NULL,
    location TEXT,
    ip_addr INET UNIQUE NOT NULL,
    val_ip_addr_start INET UNIQUE NOT NULL,
    val_count INT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    status enum_conn_status NOT NULL DEFAULT 'offline',
    created_at TIMESTAMP NOT NULL default now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_name on hosts (name);

CREATE TABLE IF NOT EXISTS validators (
    id UUID PRIMARY KEY  DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL,
    version TEXT,
    host_id UUID NOT NULL,
    user_id UUID,
    ip_addr INET UNIQUE NOT NULL,
    address TEXT UNIQUE,
    swarm_key TEXT,
    stake_status enum_stake_status NOT NULL DEFAULT 'available',
    status enum_validator_status NOT NULL DEFAULT 'provisioning',
    score BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT fk_validators_hosts FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    CONSTRAINT fk_validators_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_validators_user_id on validators(user_id);
CREATE INDEX IF NOT EXISTS idx_validators_host_id on validators(host_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_validators_address on validators(address);
CREATE INDEX IF NOT EXISTS idx_validators_status on validators(status);
CREATE INDEX IF NOT EXISTS idx_validators_stake_status on validators(stake_status);

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

