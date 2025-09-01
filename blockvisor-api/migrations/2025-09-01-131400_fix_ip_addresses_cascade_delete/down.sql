-- Revert the foreign key constraint back to non-cascading (as it was in the image model migration)

ALTER TABLE ip_addresses
  DROP CONSTRAINT fk_ip_addresses_host_id,
  ADD CONSTRAINT fk_ip_addresses_host_id FOREIGN KEY (host_id) REFERENCES hosts (id);