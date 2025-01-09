alter table hosts
    alter column region_id drop not null;

alter table hosts
    drop constraint fk_hosts_region_id;

alter table hosts
    add constraint hosts_region_id_fkey1 foreign key (region_id) references regions (id) on delete set null;

alter table regions rename column sku_code to pricing_tier;
