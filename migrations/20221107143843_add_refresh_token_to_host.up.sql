ALTER TABLE hosts
    ADD COLUMN refresh text default uuid_generate_v4() unique;
