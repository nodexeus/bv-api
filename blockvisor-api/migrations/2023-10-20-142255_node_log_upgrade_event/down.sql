-- we cannot drop values from an enum (without creating a new type)
alter type enum_node_log_event rename value 'create_succeeded' to 'succeeded';
alter type enum_node_log_event rename value 'create_failed' to 'failed';
