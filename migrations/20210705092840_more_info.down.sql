-- Add down migration script here
ALTER TABLE info DROP COLUMN staked_count;
ALTER TABLE info DROP COLUMN staked_total_hnt;
ALTER TABLE info DROP COLUMN staked_total_usd;