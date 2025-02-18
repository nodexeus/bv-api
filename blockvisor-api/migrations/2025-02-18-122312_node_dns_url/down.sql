alter table images
    drop column dns_scheme;

update
    nodes
set
    dns_name = regexp_replace(dns_name, '\.n0des\.xyz$', '');
