CREATE TYPE enum_org_role AS ENUM ('admin', 'owner', 'member');

CREATE TABLE IF NOT EXISTS orgs (
	id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	name TEXT UNIQUE NOT NULL,
	is_personal BOOLEAN NOT NULL DEFAULT 't',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_orgs_name ON orgs ((lower(name)));

CREATE INDEX IF NOT EXISTS idx_orgs_is_personal on orgs (is_personal);

INSERT INTO orgs name, is_personal values ('BlockJoy', false);

INSERT INTO
	orgs(name, is_personal)
select
	lower(email) as name,
	true as is_personal
from
	users;

CREATE TABLE IF NOT EXISTS orgs_users (
	orgs_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	users_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role enum_org_role,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (orgs_id, users_id)
);

CREATE TABLE IF NOT EXISTS host_provisions (
	id TEXT PRIMARY KEY NOT NULL,
	org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	claimed_at TIMESTAMPTZ,
) CREATE INDEX IF NOT EXISTS idx_host_provisions_created_at on host_provisions(created_at);

CREATE INDEX IF NOT EXISTS idx_host_provisions_claimed_at on host_provisions(claimed_at);