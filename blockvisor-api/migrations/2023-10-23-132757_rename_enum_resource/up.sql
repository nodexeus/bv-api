alter type enum_api_resource rename to enum_resource_type;

alter table invitations
rename column created_by to invited_by;

alter table invitations
add column if not exists invited_by_resource enum_resource_type not null
default 'user'::enum_resource_type;

alter table invitations
alter column invited_by_resource drop default;
