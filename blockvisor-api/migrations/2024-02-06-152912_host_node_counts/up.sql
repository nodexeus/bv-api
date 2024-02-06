alter table hosts
add column node_count integer null;

update hosts
set node_count = (
  select count(*)
  from nodes
  where hosts.id = nodes.host_id
    and nodes.deleted_at is null
);

update hosts set node_count = 0 where node_count is null;

alter table hosts
alter column node_count set not null,
alter column node_count set default 0;
