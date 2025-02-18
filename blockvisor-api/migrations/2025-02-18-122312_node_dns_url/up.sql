alter table images
    add column dns_scheme text;

update
    nodes
set
    dns_name = dns_name || '.n0des.xyz';
