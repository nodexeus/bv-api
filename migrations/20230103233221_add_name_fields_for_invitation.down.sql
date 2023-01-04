ALTER TABLE invitations
    DROP COLUMN IF EXISTS created_by_user_name,
    DROP COLUMN IF EXISTS created_for_org_name;
