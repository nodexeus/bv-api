alter table image_properties
    drop column display_name;

alter table image_properties
    drop column display_group;

alter table nodes
    alter column display_name drop not null;
