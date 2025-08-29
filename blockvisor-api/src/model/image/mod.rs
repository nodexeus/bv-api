pub mod archive;

pub use archive::{Archive, ArchiveId};

pub mod config;
pub use config::{Config, ConfigId, NewConfig, NodeConfig};

pub mod property;
pub use property::{ImageProperty, ImagePropertyId, NewProperty, UiType};

pub mod property_inheritance;
pub use property_inheritance::{PropertyInheritanceManager, PropertyInheritanceError};

pub mod rule;
pub use rule::{FirewallRule, ImageRule, ImageRuleId, NewImageRule};

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use derive_more::{Deref, Display, From, FromStr};
use diesel::prelude::*;
use diesel::result::Error::NotFound;
use diesel_async::RunQueryDsl;
use diesel_derive_newtype::DieselNewType;
use displaydoc::Display as DisplayDoc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::AuthZ;
use crate::auth::resource::OrgId;
use crate::database::Conn;
use crate::grpc::Status;
use crate::model::protocol::{VersionId, Visibility};
use crate::model::schema::images;
use crate::model::sql::Version;

use self::config::Ramdisks;
use self::rule::FirewallAction;

#[derive(Debug, DisplayDoc, Error)]
pub enum Error {
    /// Failed to find image for protocol version `{0}` (org: {1:?}), build: {2}: {3}
    ByBuild(VersionId, Option<OrgId>, i64, diesel::result::Error),
    /// Failed to find image id `{0}`: {1}
    ById(ImageId, diesel::result::Error),
    /// Failed to find image for protocol version `{0}` (org: {1:?}): {2}
    ByVersion(VersionId, Option<OrgId>, diesel::result::Error),
    /// Failed to find image for protocol versions `{0:?}` (org: {1:?}): {2}
    ByVersions(HashSet<VersionId>, Option<OrgId>, diesel::result::Error),
    /// Failed to create image: {0}
    Create(diesel::result::Error),
    /// Failed to get the last build for protocol version `{0}`: {1}
    LatestBuild(VersionId, diesel::result::Error),
    /// Failed to update image id {0}: {1}
    Update(ImageId, diesel::result::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            ById(_, NotFound) => Status::not_found("Image not found."),
            ByBuild(_, _, _, NotFound) => Status::not_found("No image for that build."),
            Update(_, NotFound) => Status::not_found("No image updated."),
            _ => Status::internal("Internal error."),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Display,
    Hash,
    PartialEq,
    Eq,
    DieselNewType,
    Deref,
    From,
    FromStr,
    Serialize,
    Deserialize,
)]
pub struct ImageId(Uuid);

#[derive(Clone, Debug, Queryable)]
pub struct Image {
    pub id: ImageId,
    pub org_id: Option<OrgId>,
    pub protocol_version_id: VersionId,
    pub image_uri: String,
    pub build_version: i64,
    pub description: Option<String>,
    pub min_cpu_cores: i64,
    pub min_memory_bytes: i64,
    pub min_disk_bytes: i64,
    pub ramdisks: Ramdisks,
    pub default_firewall_in: FirewallAction,
    pub default_firewall_out: FirewallAction,
    pub visibility: Visibility,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub min_babel_version: Version,
    pub dns_scheme: Option<String>,
}

impl Image {
    pub async fn by_id(
        id: ImageId,
        org_id: Option<OrgId>,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        images::table
            .find(id)
            .filter(images::org_id.eq(org_id).or(images::org_id.is_null()))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .get_result(conn)
            .await
            .map_err(|err| Error::ById(id, err))
    }

    pub async fn by_version(
        version_id: VersionId,
        org_id: Option<OrgId>,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        images::table
            .filter(images::protocol_version_id.eq(version_id))
            .filter(images::org_id.eq(org_id).or(images::org_id.is_null()))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .order_by(images::build_version.desc())
            .get_results(conn)
            .await
            .map_err(|err| Error::ByVersion(version_id, org_id, err))
    }

    pub async fn latest_build(
        version_id: VersionId,
        org_id: Option<OrgId>,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Option<Self>, Error> {
        images::table
            .filter(images::protocol_version_id.eq(version_id))
            .filter(images::org_id.eq(org_id).or(images::org_id.is_null()))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .order_by(images::build_version.desc())
            .first(conn)
            .await
            .optional()
            .map_err(|err| Error::LatestBuild(version_id, err))
    }

    pub async fn by_versions(
        version_ids: &HashSet<VersionId>,
        org_id: Option<OrgId>,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        images::table
            .filter(images::protocol_version_id.eq_any(version_ids))
            .filter(images::org_id.eq(org_id).or(images::org_id.is_null()))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .get_results(conn)
            .await
            .map_err(|err| Error::ByVersions(version_ids.clone(), org_id, err))
    }

    pub async fn by_build(
        version_id: VersionId,
        org_id: Option<OrgId>,
        build: i64,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        images::table
            .filter(images::protocol_version_id.eq(version_id))
            .filter(images::org_id.eq(org_id).or(images::org_id.is_null()))
            .filter(images::build_version.eq(build))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .get_result(conn)
            .await
            .map_err(|err| Error::ByBuild(version_id, org_id, build, err))
    }

    pub async fn list_for_admin(
        search: Option<&str>,
        protocol_filter: Option<&str>,
        org_filter: Option<OrgId>,
        offset: u32,
        limit: u32,
        authz: &AuthZ,
        conn: &mut Conn<'_>,
    ) -> Result<(Vec<(Self, String, String, u32)>, u32), Error> {
        use crate::model::schema::{protocols, protocol_versions, image_properties};
        use diesel::dsl::{count_distinct, count};
        
        // First, get the total count
        let mut count_query = images::table
            .inner_join(protocol_versions::table.on(images::protocol_version_id.eq(protocol_versions::id)))
            .inner_join(protocols::table.on(protocol_versions::protocol_id.eq(protocols::id)))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .into_boxed();

        // Apply org filter
        if let Some(org_id) = org_filter {
            count_query = count_query.filter(images::org_id.eq(org_id));
        }

        // Apply protocol filter
        if let Some(protocol_name) = protocol_filter {
            count_query = count_query.filter(protocols::name.ilike(format!("%{}%", protocol_name)));
        }

        // Apply search filter
        if let Some(search_term) = search {
            count_query = count_query.filter(
                protocols::name.ilike(format!("%{}%", search_term))
                    .or(images::description.ilike(format!("%{}%", search_term)))
            );
        }

        let total_count: i64 = count_query
            .select(count_distinct(images::id))
            .first(conn)
            .await
            .map_err(|err| Error::ByVersions(HashSet::new(), org_filter, err))?;

        // Now get the paginated results with property counts
        let mut results_query = images::table
            .inner_join(protocol_versions::table.on(images::protocol_version_id.eq(protocol_versions::id)))
            .inner_join(protocols::table.on(protocol_versions::protocol_id.eq(protocols::id)))
            .left_join(image_properties::table.on(images::id.eq(image_properties::image_id)))
            .filter(images::visibility.eq_any(<&[Visibility]>::from(authz)))
            .into_boxed();

        // Apply same filters
        if let Some(org_id) = org_filter {
            results_query = results_query.filter(images::org_id.eq(org_id));
        }

        if let Some(protocol_name) = protocol_filter {
            results_query = results_query.filter(protocols::name.ilike(format!("%{}%", protocol_name)));
        }

        if let Some(search_term) = search {
            results_query = results_query.filter(
                protocols::name.ilike(format!("%{}%", search_term))
                    .or(images::description.ilike(format!("%{}%", search_term)))
            );
        }

        let results: Vec<(Image, String, String, i64)> = results_query
            .select((
                images::all_columns,
                protocols::name,
                protocol_versions::variant_key,
                count(image_properties::id.nullable())
            ))
            .group_by((images::all_columns, protocols::name, protocol_versions::variant_key))
            .order_by((protocols::name.asc(), images::build_version.desc()))
            .offset(offset as i64)
            .limit(limit as i64)
            .load(conn)
            .await
            .map_err(|err| Error::ByVersions(HashSet::new(), org_filter, err))?;

        let formatted_results = results
            .into_iter()
            .map(|(image, protocol_name, variant_key, property_count)| {
                (image, protocol_name, variant_key, property_count as u32)
            })
            .collect();

        Ok((formatted_results, total_count as u32))
    }
}

#[derive(Debug, Insertable)]
#[diesel(table_name = images)]
pub struct NewImage {
    pub protocol_version_id: VersionId,
    pub org_id: Option<OrgId>,
    pub image_uri: String,
    pub build_version: i64,
    pub description: Option<String>,
    pub min_cpu_cores: i64,
    pub min_memory_bytes: i64,
    pub min_disk_bytes: i64,
    pub min_babel_version: Version,
    pub ramdisks: Ramdisks,
    pub default_firewall_in: FirewallAction,
    pub default_firewall_out: FirewallAction,
    pub dns_scheme: Option<String>,
}

impl NewImage {
    pub async fn create(self, conn: &mut Conn<'_>) -> Result<Image, Error> {
        diesel::insert_into(images::table)
            .values(self)
            .get_result(conn)
            .await
            .map_err(Error::Create)
    }
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = images)]
pub struct UpdateImage {
    pub id: ImageId,
    pub visibility: Option<Visibility>,
}

impl UpdateImage {
    pub async fn update(self, conn: &mut Conn<'_>) -> Result<Image, Error> {
        let id = self.id;
        diesel::update(images::table.find(id))
            .set(self)
            .get_result(conn)
            .await
            .map_err(|err| Error::Update(id, err))
    }
}
