CREATE TABLE IF NOT EXISTS invitations (
    token text primary key not null,
    created_by_user uuid references users on delete cascade,
    created_for_org uuid references orgs on delete cascade,
    invitee_email text not null,
    created_at timestamp with time zone default now(),
    accepted_at timestamp with time zone default null,
    declined_at timestamp with time zone default null,
    expires_at timestamp with time zone default null
);
