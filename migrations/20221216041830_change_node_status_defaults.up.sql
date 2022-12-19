-- TODO change default values for other status fields as well?
ALTER TABLE nodes ALTER COLUMN chain_status SET default 'provisioning'::enum_node_chain_status;
