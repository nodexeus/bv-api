alter table regions
    add column name text;

update
    regions
set
    name = display_name;

alter table regions
    alter column name set not null;

alter table regions
    add constraint regions_name_key unique (name);

drop index if exists idx_regions_key;

alter table regions
    drop constraint regions_key_unique;

alter table regions
    drop column key;

alter table regions
    drop column display_name;
