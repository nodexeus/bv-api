alter table hosts
    alter column region_id set not null;

alter table hosts
    drop constraint hosts_region_id_fkey1;

alter table hosts
    add constraint "fk_hosts_region_id" foreign key (region_id) references regions (id);

alter table regions rename column pricing_tier to sku_code;
