-- Add up migration script here

ALTER TABLE rewards DROP CONSTRAINT const_rewards_hash_u;
ALTER TABLE rewards ADD CONSTRAINT const_rewards_val_hash_u UNIQUE(validator, hash);