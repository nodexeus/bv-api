DELETE FROM COMMANDS;

CREATE TYPE enum_host_cmd_temp AS ENUM (
	'create_node',
	'restart_node',
	'kill_node',
	'shutdown_node',
	'delete_node',
	'update_node',
	'migrate_node',
	'get_node_version',
	'get_bvs_version',
	'update_bvs',
	'restart_bvs',
	'remove_bvs'
);

ALTER TABLE
	commands
ALTER COLUMN
	cmd TYPE enum_host_cmd_temp USING(cmd :: text :: enum_host_cmd_temp);

DROP TYPE enum_host_cmd;

ALTER TYPE enum_host_cmd_temp RENAME TO enum_host_cmd;