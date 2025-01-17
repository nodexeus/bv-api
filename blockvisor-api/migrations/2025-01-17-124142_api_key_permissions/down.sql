alter table api_keys
    drop column permissions;

alter table api_keys
    add column updated_at timestamp with time zone;
