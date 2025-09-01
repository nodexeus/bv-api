-- Fix the ip_addresses foreign key constraint to properly cascade delete when hosts are deleted
-- This was accidentally removed by the image model migration

ALTER TABLE ip_addresses
  DROP CONSTRAINT fk_ip_addresses_host_id,
  ADD CONSTRAINT fk_ip_addresses_host_id FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE;