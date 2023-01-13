create unique index if not exists idx_orgs_name
    on orgs (lower(name));
