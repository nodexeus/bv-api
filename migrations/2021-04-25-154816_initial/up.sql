-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
 
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    hashword TEXT NOT NULL,
    salt TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_users_email on users (email);

CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL
);
CREATE UNIQUE INDEX idx_hosts_name on hosts (name);

CREATE TABLE validators (
    id UUID PRIMARY KEY  DEFAULT uuid_generate_v4(),
    host_id UUID NOT NULL,
    user_id UUID,
    address TEXT UNIQUE NOT NULL,
    swarm TEXT NOT NULL,
    is_staked BOOLEAN DEFAULT 'f',
    is_consensus BOOLEAN DEFAULT 'f',
    is_enabled BOOLEAN DEFAULT 't',
    status TEXT,
    CONSTRAINT fk_validators_hosts FOREIGN KEY (host_id) REFERENCES hosts(id),
    CONSTRAINT fk_validators_users FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX idx_validators_user_id on validators(user_id);
CREATE INDEX idx_validators_host_id on validators(host_id);
CREATE UNIQUE INDEX idx_validators_address on validators(address);
CREATE INDEX idx_validators_is_staked on validators(is_staked);
CREATE INDEX idx_validators_is_enabled on validators(is_enabled);

CREATE TABLE rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    block BIGINT NOT NULL,
    transaction_hash TEXT,
    time BIGINT NOT NULL,
    validator_id UUID NOT NULL,
    account TEXT NOT NULL,
    amount BIGINT NOT NULL
);
CREATE INDEX idx_rewards_block on rewards(block);
CREATE INDEX idx_rewards_validator_id on rewards(validator_id);
CREATE INDEX idx_rewards_account on rewards(account);
