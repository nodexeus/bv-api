CREATE TABLE IF NOT EXISTS invitations (
    id uuid primary key not null default uuid_generate_v4(),
    created_by_user uuid references users on delete cascade,
    created_for_org uuid references orgs on delete cascade,
    invitee_email text not null,
    created_at timestamp with time zone default now(),
    accepted_at timestamp with time zone default null,
    declined_at timestamp with time zone default null
);
