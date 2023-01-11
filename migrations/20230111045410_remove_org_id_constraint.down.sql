alter table host_provisions
    add column if not exists org_id uuid not null
        references orgs
            on delete cascade;

alter table hosts
    add column if not exists val_ip_addrs text,
    add column if not exists org_id uuid;

DROP type if exists enum_host_type;
