CREATE FUNCTION notify_new_command()
    RETURNS TRIGGER
AS $$
BEGIN
    PERFORM pg_notify('new_commands'::text, NEW.id::text);
    RETURN NULL;
END;
$$
    LANGUAGE plpgsql;

CREATE TRIGGER trigger_new_command
    AFTER INSERT
    ON commands
    FOR EACH ROW
EXECUTE PROCEDURE notify_new_command();

CREATE CAST (text AS uuid)
    WITH INOUT
    AS IMPLICIT;
