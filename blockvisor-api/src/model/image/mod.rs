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

use std::collections::{HashMap, HashSet};

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
    ) -> Result<(Vec<(Self, String, String, String, u32)>, u32), Error> {
        use crate::model::schema::{protocols, protocol_versions, image_properties};
        use diesel::dsl::count;
        
        // Get all images first, then filter to latest per variant in Rust
        // This approach is simpler than complex SQL with window functions

        // Build the main query that joins with the subquery results
        let mut results_query = images::table
            .inner_join(protocol_versions::table.on(images::protocol_version_id.eq(protocol_versions::id)))
            .inner_join(protocols::table.on(protocol_versions::protocol_id.eq(protocols::id)))
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

        // Get all images, then filter in Rust to keep only the latest per variant
        let all_images: Vec<(Image, String, String, String)> = results_query
            .select((
                images::all_columns,
                protocols::name,
                protocol_versions::variant_key,
                protocol_versions::semantic_version,
            ))
            .order_by((protocols::name.asc(), protocol_versions::variant_key.asc(), images::build_version.desc()))
            .load(conn)
            .await
            .map_err(|err| Error::ByVersions(HashSet::new(), org_filter, err))?;

        // Keep only the latest build version for each (protocol_name, variant_key) combination
        let mut latest_per_variant = std::collections::HashMap::new();
        for (image, protocol_name, variant_key, semantic_version) in all_images {
            let key = (protocol_name.clone(), variant_key.clone());
            match latest_per_variant.get(&key) {
                None => {
                    latest_per_variant.insert(key, (image, protocol_name, variant_key, semantic_version));
                }
                Some((existing_image, _, _, _)) => {
                    if image.build_version > existing_image.build_version {
                        latest_per_variant.insert(key, (image, protocol_name, variant_key, semantic_version));
                    }
                }
            }
        }

        // Convert back to Vec and apply pagination
        let mut filtered_images: Vec<(Image, String, String, String)> = latest_per_variant.into_values().collect();
        filtered_images.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2))); // Sort by protocol name, then variant key
        
        let total_filtered = filtered_images.len();
        let images_with_protocol: Vec<(Image, String, String, String)> = filtered_images
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        // Get property counts for each image
        let image_ids: Vec<_> = images_with_protocol.iter().map(|(img, _, _, _)| img.id).collect();
        let property_counts: Vec<(ImageId, i64)> = if !image_ids.is_empty() {
            image_properties::table
                .filter(image_properties::image_id.eq_any(&image_ids))
                .group_by(image_properties::image_id)
                .select((image_properties::image_id, count(image_properties::id)))
                .load(conn)
                .await
                .map_err(|err| Error::ByVersions(HashSet::new(), org_filter, err))?
        } else {
            Vec::new()
        };

        // Create a map for quick lookup
        let property_count_map: std::collections::HashMap<ImageId, i64> = property_counts.into_iter().collect();

        // Combine the results
        let results: Vec<(Image, String, String, String, u32)> = images_with_protocol
            .into_iter()
            .map(|(image, protocol_name, variant_key, semantic_version)| {
                let property_count = property_count_map.get(&image.id).copied().unwrap_or(0) as u32;
                (image, protocol_name, variant_key, semantic_version, property_count)
            })
            .collect();

        Ok((results, total_filtered as u32))
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
