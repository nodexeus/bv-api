alter table regions
    add column key text;

alter table regions
    add column display_name text;

update
    regions
set
    display_name = name;

update
    regions
set
    key = regexp_replace(regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g'), '(^-+|-+$)', '', 'g');

alter table regions
    alter column key set not null;

alter table regions
    alter column display_name set not null;

alter table regions
    add constraint regions_key_unique unique (key);

alter table regions
    drop constraint regions_name_key;

alter table regions
    drop column name;

create index idx_regions_key on regions (key);
