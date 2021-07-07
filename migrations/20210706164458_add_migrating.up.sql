-- Add up migration script here
ALTER TYPE enum_validator_status ADD VALUE 'migrating' AFTER 'upgrading';