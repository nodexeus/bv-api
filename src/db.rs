use anyhow::Result;
use diesel::prelude::*;
use uuid::Uuid;

use crate::models;

pub fn insert_host(host_name: &str, db: &PgConnection) -> Result<models::Host> {
    use crate::schema::hosts::dsl::*;

    let new_host = models::Host {
        id: Uuid::new_v4(),
        name: host_name.to_string(),
    };

    diesel::insert_into(hosts).values(&new_host).execute(db)?;

    Ok(new_host)
}

pub fn find_host_by_id(uid: Uuid, db: &PgConnection) -> Result<Option<models::Host>> {
    use crate::schema::hosts::dsl::*;

    let host = hosts
        .filter(id.eq(uid))
        .first::<models::Host>(db)
        .optional()?;

    Ok(host)
}
