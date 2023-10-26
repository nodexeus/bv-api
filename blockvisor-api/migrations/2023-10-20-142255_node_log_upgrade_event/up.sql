alter type enum_node_log_event add value if not exists 'upgraded';
alter type enum_node_log_event add value if not exists 'upgrade_succeeded';
alter type enum_node_log_event add value if not exists 'upgrade_failed';

alter type enum_node_log_event rename value 'succeeded' to 'create_succeeded';
alter type enum_node_log_event rename value 'failed' to 'create_failed';
