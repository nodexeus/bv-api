alter table nodes
    add column if not exists network text default '' not null;
