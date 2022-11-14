ALTER TABLE users
    ADD COLUMN confirmed_at timestamp with time zone default null;
