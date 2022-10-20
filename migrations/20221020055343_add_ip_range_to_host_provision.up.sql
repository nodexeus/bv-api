ALTER TABLE host_provisions
    ADD COLUMN ip_range_from inet default null,
    ADD COLUMN ip_range_to inet default null,
    ADD COLUMN ip_gateway inet default null;
