alter table host_provisions
    drop column if exists org_id;

alter table hosts
    drop column if exists val_ip_addrs,
    drop column if exists org_id;

DO $$ BEGIN
    CREATE TYPE enum_host_type AS ENUM ('cloud', 'enterprise');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

drop table if exists validators;
