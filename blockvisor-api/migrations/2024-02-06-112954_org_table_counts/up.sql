alter table orgs
add column host_count integer null,
add column node_count integer null,
add column member_count integer null;

update orgs
set host_count = (
  select count(*)
  from hosts
  where orgs.id = hosts.org_id
    and hosts.deleted_at is not null
);

update orgs
set node_count = (
  select count(*)
  from nodes
  where orgs.id = nodes.org_id
    and nodes.deleted_at is not null
);

update orgs
set member_count = q.users
from (
  select org_id, count(distinct user_id) as users
  from user_roles
  group by org_id
) as q
where orgs.id = q.org_id;

alter table orgs
alter column host_count set not null,
alter column host_count set default 0,
alter column node_count set not null,
alter column node_count set default 0,
alter column member_count set not null,
alter column member_count set default 0;
