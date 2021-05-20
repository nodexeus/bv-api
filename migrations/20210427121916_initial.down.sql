-- Add migration script here
-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS rewards;
DROP TABLE IF EXISTS commands;
DROP TABLE IF EXISTS validators;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS enum_conn_status;
DROP TYPE IF EXISTS enum_validator_status;
DROP TYPE IF EXISTS enum_stake_status;
DROP TYPE IF EXISTS enum_host_cmd;
DROP TYPE IF EXISTS enum_user_role;