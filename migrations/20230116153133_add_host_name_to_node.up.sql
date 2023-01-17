alter table nodes
    add column if not exists host_name text default '' not null;
