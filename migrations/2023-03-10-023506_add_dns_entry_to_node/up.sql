ALTER TABLE nodes add column if not exists dns_record_id varchar(50) default '' not null;
