-- Revert host deletion changes - restore original constraints

-- Restore original commands constraint (if any specific behavior was needed)
ALTER TABLE commands 
    DROP CONSTRAINT IF EXISTS fk_host_commands_hosts,
    ADD CONSTRAINT fk_host_commands_hosts FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

-- Restore original ip_addresses constraint
ALTER TABLE ip_addresses
    DROP CONSTRAINT IF EXISTS ip_addresses_host_id_fkey,
    ADD CONSTRAINT ip_addresses_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

-- Restore original node_logs constraint
ALTER TABLE node_logs
    DROP CONSTRAINT IF EXISTS node_logs_host_id_fkey,
    ADD CONSTRAINT node_logs_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

-- Restore original host_provisions constraint (if table exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'host_provisions') THEN
        ALTER TABLE host_provisions 
            DROP CONSTRAINT IF EXISTS host_provisions_host_id_fkey,
            ADD CONSTRAINT host_provisions_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;
    END IF;
END$$;