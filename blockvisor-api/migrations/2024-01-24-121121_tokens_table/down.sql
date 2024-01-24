create table if not exists orgs_users (
  org_id uuid not null,
  user_id uuid not null,
  created_at timestamp with time zone default now() not null,
  updated_at timestamp with time zone default now() not null,
  host_provision_token varchar(32) not null,
  primary key (org_id, user_id)
);

insert into orgs_users (org_id, user_id, created_at, updated_at, host_provision_token)
select
  org_id,
  created_by,
  created_at,
  created_at,
  token
from tokens
where token_type = 'host_provision'::enum_token_type;

create type token_type as enum (
  'login',
  'refresh',
  'pwd_reset',
  'user_auth',
  'host_auth',
  'user_refresh',
  'host_refresh'
);

create table if not exists token_blacklist (
  token text not null primary key,
  token_type token_type not null
);

create type enum_token_role as enum (
  'user',
  'admin',
  'service',
  'guest',
  'pwd_reset'
);

drop table if exists tokens;
drop type enum_token_type;
