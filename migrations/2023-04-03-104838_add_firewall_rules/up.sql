alter table nodes add column if not exists allow_ips jsonb;
alter table nodes add column if not exists deny_ips jsonb;
