ALTER TABLE invitations
    ADD COLUMN IF NOT EXISTS created_by_user_name text not null default '',
    ADD COLUMN IF NOT EXISTS created_for_org_name text not null default '';
