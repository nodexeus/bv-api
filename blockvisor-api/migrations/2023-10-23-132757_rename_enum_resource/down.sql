alter type enum_resource_type rename to enum_api_resource;

alter table invitations
rename column invited_by to created_by;

alter table invitations
drop column if exists invited_by_resource;
