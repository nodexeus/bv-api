use std::collections::HashSet;

use derive_more::{Deref, Display, From, FromStr};
use diesel::prelude::*;
use diesel::result::DatabaseErrorKind::UniqueViolation;
use diesel::result::Error::{DatabaseError, NotFound};
use diesel_async::RunQueryDsl;
use diesel_derive_newtype::DieselNewType;
use displaydoc::Display as DisplayDoc;
use thiserror::Error;
use uuid::Uuid;

use crate::database::Conn;
use crate::grpc::{api, Status};

use super::schema::regions;

#[derive(Debug, DisplayDoc, Error)]
pub enum Error {
    /// Failed to create region: {0}
    Create(diesel::result::Error),
    /// Failed to get regions for id `{0}`: {1}
    ById(RegionId, diesel::result::Error),
    /// Failed to get regions by ids `{0:?}`: {1}
    ByIds(HashSet<RegionId>, diesel::result::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            Create(DatabaseError(UniqueViolation, _)) => Status::already_exists("Already exists."),
            ById(_, NotFound) | ByIds(_, NotFound) => Status::not_found("Not found."),
            _ => Status::internal("Internal error."),
        }
    }
}

#[derive(Clone, Copy, Debug, Display, Hash, PartialEq, Eq, DieselNewType, Deref, From, FromStr)]
pub struct RegionId(Uuid);

#[derive(Clone, Debug, Queryable)]
pub struct Region {
    pub id: RegionId,
    pub name: String,
    pub sku_code: Option<String>,
}

impl Region {
    pub async fn by_id(id: RegionId, conn: &mut Conn<'_>) -> Result<Self, Error> {
        regions::table
            .find(id)
            .get_result(conn)
            .await
            .map_err(|err| Error::ById(id, err))
    }

    pub async fn by_ids(
        region_ids: &HashSet<RegionId>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        regions::table
            .filter(regions::id.eq_any(region_ids))
            .get_results(conn)
            .await
            .map_err(|err| Error::ByIds(region_ids.clone(), err))
    }
}

#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = regions)]
pub struct NewRegion<'a> {
    pub name: &'a str,
    pub sku_code: Option<&'a str>,
}

impl NewRegion<'_> {
    pub async fn create(self, conn: &mut Conn<'_>) -> Result<Region, Error> {
        diesel::insert_into(regions::table)
            .values(self)
            .get_result(conn)
            .await
            .map_err(Error::Create)
    }
}

impl From<Region> for api::Region {
    fn from(region: Region) -> Self {
        api::Region {
            region_id: region.id.to_string(),
            name: region.name,
            sku_code: region.sku_code,
        }
    }
}
