alter table nodes add column created_by_resource enum_api_resource null;

update nodes
set created_by_resource = 'user'::enum_api_resource
where created_by is not null;
