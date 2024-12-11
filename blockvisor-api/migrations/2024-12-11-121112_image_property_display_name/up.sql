alter table image_properties
    add column display_name text;

alter table image_properties
    add column display_group text;

alter table nodes
    alter column display_name set not null;

alter type enum_command_exit_code
    add value if not exists 'node_upgrade_rollback';

alter type enum_command_exit_code
    add value if not exists 'node_upgrade_failure';
