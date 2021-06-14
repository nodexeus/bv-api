-- Add up migration script here

ALTER TABLE rewards RENAME COLUMN transaction_hash TO hash;
ALTER TABLE rewards ADD CONSTRAINT const_rewards_hash_u UNIQUE (hash);
ALTER TABLE rewards DROP COLUMN IF EXISTS time;
ALTER TABLE rewards ADD COLUMN txn_time TIMESTAMPTZ NOT NULL;
ALTER TABLE rewards ADD COLUMN created_at TIMESTAMPTZ NOT NULL default now();
ALTER TABLE rewards ADD COLUMN user_id UUID;
ALTER TABLE rewards ADD COLUMN validator TEXT NOT NULL;


CREATE INDEX IF NOT EXISTS idx_rewards_user_id on rewards(user_id);
CREATE INDEX IF NOT EXISTS idx_rewards_txn_time on rewards(txn_time);
CREATE INDEX IF NOT EXISTS idx_rewards_created_at on rewards(created_at);
