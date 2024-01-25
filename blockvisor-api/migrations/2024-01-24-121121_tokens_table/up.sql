create type enum_token_type as enum (
  'host_provision'
);

create table if not exists tokens (
  id uuid primary key default uuid_generate_v4(),
  token_type enum_token_type not null,
  token text not null,
  created_by_resource enum_resource_type not null,
  created_by uuid not null,
  org_id uuid,
  created_at timestamp with time zone default now() not null,
  updated_at timestamp with time zone
);

insert into tokens (token_type, token, created_by_resource, created_by, org_id, created_at)
select
  'host_provision'::enum_token_type,
  host_provision_token,
  'user'::enum_resource_type,
  user_id,
  org_id,
  created_at
from orgs_users;

drop table if exists orgs_users;
drop table if exists token_blacklist;

drop type token_type;
drop type enum_token_role;
