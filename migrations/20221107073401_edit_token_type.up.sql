ALTER TYPE token_type ADD VALUE IF NOT EXISTS 'user_auth';
ALTER TYPE token_type ADD VALUE IF NOT EXISTS 'host_auth';
ALTER TYPE token_type ADD VALUE IF NOT EXISTS 'user_refresh';
ALTER TYPE token_type ADD VALUE IF NOT EXISTS 'host_refresh';
