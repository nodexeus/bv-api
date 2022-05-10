CREATE TYPE enum_org_role AS ENUM ('admin', 'owner', 'member');

CREATE TABLE IF NOT EXISTS orgs (
	id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	name TEXT NOT NULL,
	is_personal BOOLEAN NOT NULL DEFAULT 't',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_orgs_name ON orgs ((lower(name)));

CREATE INDEX IF NOT EXISTS idx_orgs_is_personal on orgs (is_personal);

INSERT INTO orgs (name, is_personal) values ('BlockJoy', false);

CREATE TABLE IF NOT EXISTS orgs_users (
	org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role enum_org_role,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (org_id, user_id)
);

INSERT INTO
	orgs(name, is_personal)
select
	lower(email) as name,
	true as is_personal
from
	users;

INSERT INTO
	orgs_users(org_id, user_id, role)
SELECT
	orgs.id as org_id,
	users.id as user_id,
	'owner' as role
FROM
	orgs
	INNER JOIN users on orgs.name = lower(users.email);

CREATE TABLE IF NOT EXISTS host_provisions (
	id TEXT PRIMARY KEY NOT NULL,
	org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	claimed_at TIMESTAMPTZ,
	host_id UUID REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_host_provisions_created_at on host_provisions(created_at);

CREATE INDEX IF NOT EXISTS idx_host_provisions_claimed_at on host_provisions(claimed_at);

CREATE INDEX IF NOT EXISTS idx_host_provisions_host_id on host_provisions(host_id);