DO $$ BEGIN
    CREATE TYPE enum_host_type AS ENUM ('cloud', 'enterprise');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

alter table host_provisions
    drop column if exists org_id;

alter table hosts
    drop column if exists val_ip_addrs,
    drop column if exists org_id,
    add column if not exists host_type enum_host_type default 'cloud'::enum_host_type;

drop table if exists validators;
