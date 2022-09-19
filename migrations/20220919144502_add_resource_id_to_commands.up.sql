ALTER TABLE commands ADD COLUMN resource_id uuid NOT NULL DEFAULT uuid_generate_v4();
