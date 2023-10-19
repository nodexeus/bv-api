alter table nodes add constraint nodes_created_by_fkey
foreign key (created_by) references users(id) on delete set null;
