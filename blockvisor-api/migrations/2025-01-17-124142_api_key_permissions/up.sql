alter table api_keys
    drop column created_at,
    drop column updated_at;

alter table api_keys
    add column permissions text[] not null,
    add column created_at timestamp with time zone default now() not null;
