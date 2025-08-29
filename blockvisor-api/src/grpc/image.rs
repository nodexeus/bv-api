use std::collections::HashSet;

use diesel_async::scoped_futures::ScopedFutureExt;
use displaydoc::Display;
use prost_wkt_types::Empty;
use thiserror::Error;
use tonic::{Request, Response};
use tracing::error;

use crate::auth::Authorize;
use crate::auth::rbac::{ImageAdminPerm, ImagePerm, Perm};
use crate::database::{ReadConn, Transaction, WriteConn};
use crate::model::image::archive::{NewArchive, UpdateArchive};
use crate::model::image::config::Ramdisks;
use crate::model::image::property::ImagePropertyKey;
use crate::model::image::rule::{ImageRule, NewImageRule};
use crate::model::image::{Archive, Image, ImageProperty, NewImage, NewProperty, UpdateImage, PropertyInheritanceManager};
use crate::model::protocol::VersionKey;
use crate::model::sql::Version;
use crate::model::{Node, ProtocolVersion};
use crate::store::StoreKey;
use crate::util::{HashVec, NanosUtc};

use super::api::image_service_server::ImageService;
use super::{Grpc, Metadata, Status, api, common};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Image archive error: {0}
    Archive(#[from] crate::model::image::archive::Error),
    /// Auth check failed: {0}
    Auth(#[from] crate::auth::Error),
    /// Failed to parse build_version: {0}
    BuildVersion(std::num::TryFromIntError),
    /// Claims check failed: {0}
    Claims(#[from] crate::auth::claims::Error),
    /// Diesel failure: {0}
    Diesel(#[from] diesel::result::Error),
    /// Failed to find semantic version: {0}
    FindVersion(Version),
    /// Image model error: {0}
    Image(#[from] crate::model::image::Error),
    /// Invalid new_archive_keys combination: {0:?}
    InvalidKeyCombo(HashSet<ImagePropertyKey>),
    /// Failed to parse minimum babel version: {0}
    MinBabel(crate::model::sql::Error),
    /// Failed to parse minimum cpu count: {0}
    MinCpu(std::num::TryFromIntError),
    /// Failed to parse minimum disk space: {0}
    MinDisk(std::num::TryFromIntError),
    /// Failed to parse minimum memory: {0}
    MinMemory(std::num::TryFromIntError),
    /// Missing firewall config.
    MissingFirewallConfig,
    /// Missing expected new_archive key combos: {0:?}
    MissingKeyCombos(Vec<HashSet<ImagePropertyKey>>),
    /// Missing image property key: {0}
    MissingPropertyKey(ImagePropertyKey),
    /// Missing StoreKey pointer.
    MissingStorePointer,
    /// Missing version key.
    MissingVersionKey,
    /// No builds found.
    NoBuilds,
    /// Node error: {0}
    Node(#[from] crate::model::node::Error),
    /// No versions found.
    NoVersions,
    /// Failed to parse ArchiveId: {0}
    ParseArchiveId(uuid::Error),
    /// Failed to parse ImageId: {0}
    ParseImageId(uuid::Error),
    /// Failed to parse OrgId: {0}
    ParseOrgId(uuid::Error),
    /// Failed to parse ProtocolId: {0}
    ParseProtocolId(uuid::Error),
    /// Failed to parse protocol version: {0}
    ParseVersion(crate::model::sql::Error),
    /// Failed to parse VersionId: {0}
    ParseVersionId(uuid::Error),
    /// Image property error: {0}
    Property(#[from] crate::model::image::property::Error),
    /// Property inheritance error: {0}
    PropertyInheritance(#[from] crate::model::image::PropertyInheritanceError),
    /// Image protocol error: {0}
    Protocol(#[from] crate::model::protocol::Error),
    /// Image firewall rule error: {0}
    Rule(#[from] crate::model::image::rule::Error),
    /// Image store error: {0}
    Store(#[from] crate::store::Error),
    /// Image protocol version error: {0}
    Version(#[from] crate::model::protocol::version::Error),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        error!("{err}");
        match err {
            Diesel(_) => Status::internal("Internal error."),
            FindVersion(_) | NoBuilds | NoVersions => Status::not_found("Not found."),
            BuildVersion(_) => Status::invalid_argument("build_version"),
            InvalidKeyCombo(set) => {
                // safety: keys are from the client
                Status::invalid_argument(format!("invalid archive_pointer key combo: {set:?}"))
            }
            MinBabel(_) => Status::invalid_argument("min_babel_version"),
            MinCpu(_) => Status::invalid_argument("min_cpu_cores"),
            MinDisk(_) => Status::invalid_argument("min_disk_bytes"),
            MinMemory(_) => Status::invalid_argument("min_memory_bytes"),
            MissingFirewallConfig => Status::invalid_argument("firewall"),
            MissingKeyCombos(set) => {
                // safety: keys are from properties the client provided
                Status::invalid_argument(format!("missing archive_pointer key combos: {set:?}"))
            }
            MissingPropertyKey(key) => {
                // safety: keys is from the client
                Status::invalid_argument(format!("missing archive_pointer key: {key}"))
            }
            MissingStorePointer => Status::invalid_argument("archive_pointer.pointer"),
            MissingVersionKey => Status::invalid_argument("version_key"),
            ParseArchiveId(_) => Status::invalid_argument("id"),
            ParseImageId(_) => Status::invalid_argument("image_id"),
            ParseOrgId(_) => Status::invalid_argument("org_id"),
            ParseProtocolId(_) => Status::invalid_argument("protocol_id"),
            ParseVersion(_) => Status::invalid_argument("protocol_version"),
            ParseVersionId(_) => Status::invalid_argument("protocol_version_id"),
            Archive(err) => err.into(),
            Auth(err) => err.into(),
            Claims(err) => err.into(),
            Image(err) => err.into(),
            Node(err) => err.into(),
            Property(err) => err.into(),
            PropertyInheritance(_) => Status::internal("Property inheritance failed."),
            Protocol(err) => err.into(),
            Rule(err) => err.into(),
            Store(err) => err.into(),
            Version(err) => err.into(),
        }
    }
}

#[tonic::async_trait]
impl ImageService for Grpc {
    async fn add_image(
        &self,
        req: Request<api::ImageServiceAddImageRequest>,
    ) -> Result<Response<api::ImageServiceAddImageResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| add_image(req, meta.into(), write).scope_boxed())
            .await
    }

    async fn get_image(
        &self,
        req: Request<api::ImageServiceGetImageRequest>,
    ) -> Result<Response<api::ImageServiceGetImageResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| get_image(req, meta.into(), read).scope_boxed())
            .await
    }

    async fn list_archives(
        &self,
        req: Request<api::ImageServiceListArchivesRequest>,
    ) -> Result<Response<api::ImageServiceListArchivesResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| list_archives(req, meta.into(), read).scope_boxed())
            .await
    }

    async fn update_archive(
        &self,
        req: Request<api::ImageServiceUpdateArchiveRequest>,
    ) -> Result<Response<api::ImageServiceUpdateArchiveResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| update_archive(req, meta.into(), write).scope_boxed())
            .await
    }

    async fn update_image(
        &self,
        req: Request<api::ImageServiceUpdateImageRequest>,
    ) -> Result<Response<api::ImageServiceUpdateImageResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| update_image(req, meta.into(), write).scope_boxed())
            .await
    }

    async fn list_images(
        &self,
        req: Request<api::ImageServiceListImagesRequest>,
    ) -> Result<Response<api::ImageServiceListImagesResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| list_images(req, meta.into(), read).scope_boxed())
            .await
    }

    async fn get_image_details(
        &self,
        req: Request<api::ImageServiceGetImageDetailsRequest>,
    ) -> Result<Response<api::ImageServiceGetImageDetailsResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.read(|read| get_image_details(req, meta.into(), read).scope_boxed())
            .await
    }

    async fn add_image_property(
        &self,
        req: Request<api::ImageServiceAddImagePropertyRequest>,
    ) -> Result<Response<api::ImageServiceAddImagePropertyResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| add_image_property(req, meta.into(), write).scope_boxed())
            .await
    }

    async fn update_image_property(
        &self,
        req: Request<api::ImageServiceUpdateImagePropertyRequest>,
    ) -> Result<Response<api::ImageServiceUpdateImagePropertyResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| update_image_property(req, meta.into(), write).scope_boxed())
            .await
    }

    async fn delete_image_property(
        &self,
        req: Request<api::ImageServiceDeleteImagePropertyRequest>,
    ) -> Result<Response<api::ImageServiceDeleteImagePropertyResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| delete_image_property(req, meta.into(), write).scope_boxed())
            .await
    }

    async fn copy_image_properties(
        &self,
        req: Request<api::ImageServiceCopyImagePropertiesRequest>,
    ) -> Result<Response<api::ImageServiceCopyImagePropertiesResponse>, tonic::Status> {
        let (meta, _, req) = req.into_parts();
        self.write(|write| copy_image_properties(req, meta.into(), write).scope_boxed())
            .await
    }
}

async fn add_image(
    req: api::ImageServiceAddImageRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceAddImageResponse, Error> {
    let authz = write.auth(&meta, ImageAdminPerm::Add).await?;

    let version_id = req
        .protocol_version_id
        .parse()
        .map_err(Error::ParseVersionId)?;
    let org_id = req
        .org_id
        .as_ref()
        .map(|id| id.parse().map_err(Error::ParseOrgId))
        .transpose()?;

    let version = ProtocolVersion::by_id(version_id, org_id, &authz, &mut write).await?;
    let latest = Image::latest_build(version_id, org_id, &authz, &mut write).await?;

    let firewall = req.firewall.ok_or(Error::MissingFirewallConfig)?;
    let new_image = NewImage {
        protocol_version_id: version.id,
        org_id: version.org_id.or(org_id),
        image_uri: req.image_uri,
        build_version: latest.as_ref().map_or(1, |image| image.build_version + 1),
        description: req.description,
        min_cpu_cores: i64::try_from(req.min_cpu_cores).map_err(Error::MinCpu)?,
        min_memory_bytes: i64::try_from(req.min_memory_bytes).map_err(Error::MinMemory)?,
        min_disk_bytes: i64::try_from(req.min_disk_bytes).map_err(Error::MinDisk)?,
        min_babel_version: req.min_babel_version.parse().map_err(Error::MinBabel)?,
        ramdisks: Ramdisks(req.ramdisks.into_iter().map(Into::into).collect()),
        default_firewall_in: firewall.default_in().try_into()?,
        default_firewall_out: firewall.default_out().try_into()?,
        dns_scheme: req.dns_scheme,
    };
    let image = new_image.create(&mut write).await?;

    let new_rules = firewall
        .rules
        .into_iter()
        .map(|rule| NewImageRule::from_api(image.id, rule))
        .collect::<Result<_, _>>()?;
    let rules = NewImageRule::bulk_create(new_rules, &mut write).await?;

    // First, inherit properties from the latest image version
    // This ensures property continuity across image versions
    let inherited_properties = PropertyInheritanceManager::inherit_properties_for_new_image(
        version.id,
        version.org_id.or(org_id),
        image.id,
        &mut write,
    ).await.map_err(|err| {
        tracing::warn!("Property inheritance failed for new image {}: {}. Continuing with request properties only.", image.id, err);
        // Don't fail the entire operation if inheritance fails - just log and continue
        err
    }).unwrap_or_else(|_| Vec::new());

    // Then, create any additional properties from the request
    // These will be added to the inherited properties
    let mut properties = inherited_properties;
    if !req.properties.is_empty() {
        let new_properties = req
            .properties
            .into_iter()
            .map(|prop| NewProperty::from(image.id, prop))
            .collect::<Result<_, _>>()?;
        let additional_properties = NewProperty::bulk_create(new_properties, &mut write).await?;
        properties.extend(additional_properties);
    }
    let key_to_property_id = properties
        .iter()
        .to_map_keep_last(|prop| (prop.key.clone(), prop.id));

    // find all possible new_archive key combinations
    let mut new_archive_powerset = properties
        .iter()
        .filter_map(|prop| prop.new_archive.then_some(prop.key.clone()))
        .fold(vec![hashset! {}], |sets, key| {
            sets.iter()
                .cloned()
                .chain(sets.iter().map(|set| {
                    let mut new_set = set.clone();
                    new_set.insert(key.clone());
                    new_set
                }))
                .collect()
        });

    // get the store pointers for all requested new_archive combinations
    let archive_pointers = req
        .archive_pointers
        .into_iter()
        .map(|pointer| {
            let keys = pointer
                .new_archive_keys
                .into_iter()
                .map(ImagePropertyKey::new)
                .collect::<Result<HashSet<_>, _>>()?;
            let ids = keys
                .iter()
                .map(|key| {
                    key_to_property_id
                        .get(key)
                        .copied()
                        .ok_or_else(|| Error::MissingPropertyKey(key.clone()))
                })
                .collect::<Result<HashSet<_>, _>>()?;
            let pointer = match pointer.pointer.ok_or(Error::MissingStorePointer)? {
                api::archive_pointer::Pointer::StoreKey(id) => Some(StoreKey::new(id)?),
                api::archive_pointer::Pointer::Disallowed(Empty {}) => None,
            };
            Ok((keys, ids, pointer))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    // create new archives for all valid new_archive key combinations
    let mut new_archives = Vec::with_capacity(archive_pointers.len());
    for (keys, ids, pointer) in archive_pointers {
        let mut found = None;
        for (index, set) in new_archive_powerset.iter().enumerate() {
            if keys == *set {
                found = Some(index);
                if let Some(ref store_key) = pointer {
                    new_archives.push(NewArchive::new(image.id, store_key.clone(), &ids));
                }
            }
        }

        if let Some(index) = found {
            new_archive_powerset.swap_remove(index);
        } else {
            return Err(Error::InvalidKeyCombo(keys));
        }
    }

    // ensure all possible new_archive key combinations are provided
    let archives = if new_archive_powerset.is_empty() {
        NewArchive::bulk_create(new_archives, &mut write).await?
    } else {
        return Err(Error::MissingKeyCombos(new_archive_powerset));
    };

    Node::notify_auto_upgrades(&image, &version, org_id, &authz, &mut write).await?;

    Ok(api::ImageServiceAddImageResponse {
        image: Some(api::Image::from(image, properties, rules)?),
        archives: archives.into_iter().map(Into::into).collect(),
    })
}

async fn get_image(
    req: api::ImageServiceGetImageRequest,
    meta: Metadata,
    mut read: ReadConn<'_, '_>,
) -> Result<api::ImageServiceGetImageResponse, Error> {
    let admin_perm: Perm = ImageAdminPerm::Get.into();
    let user_perm: Perm = ImagePerm::Get.into();

    let (org_id, authz) = if let Some(ref org_id) = req.org_id {
        let org_id = org_id.parse().map_err(Error::ParseOrgId)?;
        let authz = read
            .auth_or_for(&meta, admin_perm, user_perm, org_id)
            .await?;
        (Some(org_id), authz)
    } else {
        let authz = read.auth_any(&meta, [admin_perm, user_perm]).await?;
        (None, authz)
    };

    let version_key = VersionKey::try_from(req.version_key.ok_or(Error::MissingVersionKey)?)?;
    let mut versions = ProtocolVersion::by_key(&version_key, org_id, &authz, &mut read).await?;

    let version = if let Some(version) = req.semantic_version {
        let version: Version = version.parse().map_err(Error::ParseVersion)?;
        versions
            .into_iter()
            .find(|v| v.semantic_version == version)
            .ok_or(Error::FindVersion(version))?
    } else {
        versions.pop().ok_or(Error::NoVersions)?
    };

    let build = if let Some(build) = req.build_version {
        i64::try_from(build).map_err(Error::BuildVersion)?
    } else {
        Image::latest_build(version.id, org_id, &authz, &mut read)
            .await?
            .ok_or(Error::NoBuilds)?
            .build_version
    };

    let image = Image::by_build(version.id, org_id, build, &authz, &mut read).await?;
    let properties = ImageProperty::by_image_id(image.id, &mut read).await?;
    let rules = ImageRule::by_image_id(image.id, &mut read).await?;

    Ok(api::ImageServiceGetImageResponse {
        image: Some(api::Image::from(image, properties, rules)?),
    })
}

async fn list_archives(
    req: api::ImageServiceListArchivesRequest,
    meta: Metadata,
    mut read: ReadConn<'_, '_>,
) -> Result<api::ImageServiceListArchivesResponse, Error> {
    let admin_perm: Perm = ImageAdminPerm::ListArchives.into();
    let user_perm: Perm = ImagePerm::ListArchives.into();

    let (org_id, authz) = if let Some(ref org_id) = req.org_id {
        let org_id = org_id.parse().map_err(Error::ParseOrgId)?;
        let authz = read
            .auth_or_for(&meta, admin_perm, user_perm, org_id)
            .await?;
        (Some(org_id), authz)
    } else {
        let authz = read.auth_any(&meta, [admin_perm, user_perm]).await?;
        (None, authz)
    };

    let image_id = req.image_id.parse().map_err(Error::ParseImageId)?;
    let image = Image::by_id(image_id, org_id, &authz, &mut read).await?;
    let archives = Archive::by_image_id(image.id, org_id, &mut read).await?;

    Ok(api::ImageServiceListArchivesResponse {
        archives: archives.into_iter().map(Into::into).collect(),
    })
}

async fn update_archive(
    req: api::ImageServiceUpdateArchiveRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceUpdateArchiveResponse, Error> {
    let _authz = write.auth(&meta, ImageAdminPerm::UpdateArchive).await?;

    let id = req.archive_id.parse().map_err(Error::ParseArchiveId)?;
    let store_key = req.store_key.map(StoreKey::new).transpose()?;

    let update = UpdateArchive { id, store_key };
    let archive = update.update(&mut write).await?;

    Ok(api::ImageServiceUpdateArchiveResponse {
        archive: Some(archive.into()),
    })
}

async fn update_image(
    req: api::ImageServiceUpdateImageRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceUpdateImageResponse, Error> {
    let _authz = write.auth(&meta, ImageAdminPerm::UpdateImage).await?;

    let id = req.image_id.parse().map_err(Error::ParseImageId)?;
    let visibility = req
        .visibility
        .map(|_| req.visibility().try_into())
        .transpose()?;

    let update = UpdateImage { id, visibility };
    let image = update.update(&mut write).await?;

    let properties = ImageProperty::by_image_id(image.id, &mut write).await?;
    let rules = ImageRule::by_image_id(image.id, &mut write).await?;

    Ok(api::ImageServiceUpdateImageResponse {
        image: Some(api::Image::from(image, properties, rules)?),
    })
}

async fn list_images(
    req: api::ImageServiceListImagesRequest,
    meta: Metadata,
    mut read: ReadConn<'_, '_>,
) -> Result<api::ImageServiceListImagesResponse, Error> {
    let authz = read.auth(&meta, ImageAdminPerm::List).await?;

    let page = req.page.max(1);
    let page_size = req.page_size.clamp(1, 100);
    let offset = (page - 1) * page_size;

    let org_filter = req
        .org_filter
        .as_ref()
        .map(|id| id.parse().map_err(Error::ParseOrgId))
        .transpose()?;

    let (images, total_count) = Image::list_for_admin(
        req.search.as_deref(),
        req.protocol_filter.as_deref(),
        org_filter,
        offset,
        page_size,
        &authz,
        &mut read,
    ).await?;

    let image_summaries = images
        .into_iter()
        .map(|(image, protocol_name, variant_key, property_count)| {
            Ok(api::ImageSummary {
                image_id: image.id.to_string(),
                protocol_name: protocol_name.clone(),
                version_key: Some(common::ProtocolVersionKey {
                    protocol_key: protocol_name,
                    variant_key,
                }),
                build_version: u64::try_from(image.build_version).map_err(Error::BuildVersion)?,
                property_count,
                created_at: Some(NanosUtc::from(image.created_at).into()),
                org_id: image.org_id.map(|id| id.to_string()),
                description: image.description,
                visibility: common::Visibility::from(image.visibility).into(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    Ok(api::ImageServiceListImagesResponse {
        images: image_summaries,
        total_count,
    })
}

async fn get_image_details(
    req: api::ImageServiceGetImageDetailsRequest,
    meta: Metadata,
    mut read: ReadConn<'_, '_>,
) -> Result<api::ImageServiceGetImageDetailsResponse, Error> {
    let org_id = req
        .org_id
        .as_ref()
        .map(|id| id.parse().map_err(Error::ParseOrgId))
        .transpose()?;
    let authz = read.auth(&meta, ImageAdminPerm::Get).await?;

    let image_id = req.image_id.parse().map_err(Error::ParseImageId)?;
    let image = Image::by_id(image_id, org_id, &authz, &mut read).await?;
    let properties = ImageProperty::by_image_id(image.id, &mut read).await?;
    let rules = ImageRule::by_image_id(image.id, &mut read).await?;

    Ok(api::ImageServiceGetImageDetailsResponse {
        image: Some(api::Image::from(image, properties, rules)?),
    })
}

async fn add_image_property(
    req: api::ImageServiceAddImagePropertyRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceAddImagePropertyResponse, Error> {
    let authz = write.auth(&meta, ImageAdminPerm::AddProperty).await?;

    let image_id = req.image_id.parse().map_err(Error::ParseImageId)?;
    
    // Verify the image exists and user has access
    let image = Image::by_id(image_id, None, &authz, &mut write).await?;
    
    // Create the new property
    let property_req = req.property.ok_or_else(|| Error::Property(crate::model::image::property::Error::Admin(crate::model::image::property::ImagePropertyAdminError::ValidationFailed("property is required".to_string()))))?;
    let property = ImageProperty::create_for_image(image_id, property_req.clone(), &mut write).await?;
    
    let mut affected_image_ids = vec![image_id.to_string()];
    
    // If apply_to_newer_versions is true, sync to newer versions
    if req.apply_to_newer_versions {
        let newer_images = PropertyInheritanceManager::find_newer_image_versions(&image, &mut write).await?;
        
        for newer_image in newer_images {
            // Create the property in the newer image
            let _newer_property = ImageProperty::create_for_image(newer_image.id, property_req.clone(), &mut write).await?;
            affected_image_ids.push(newer_image.id.to_string());
        }
    }

    Ok(api::ImageServiceAddImagePropertyResponse {
        property: Some(property.into()),
        affected_image_ids,
    })
}

async fn update_image_property(
    req: api::ImageServiceUpdateImagePropertyRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceUpdateImagePropertyResponse, Error> {
    let authz = write.auth(&meta, ImageAdminPerm::UpdateProperty).await?;

    let property_id = req.image_property_id.parse().map_err(Error::ParseImageId)?;
    
    // Get the existing property to find the image
    let existing_property = ImageProperty::by_id(property_id, &mut write).await?;
    let image = Image::by_id(existing_property.image_id, None, &authz, &mut write).await?;
    
    // Update the property
    let property_req = req.property.ok_or_else(|| Error::Property(crate::model::image::property::Error::Admin(crate::model::image::property::ImagePropertyAdminError::ValidationFailed("property is required".to_string()))))?;
    let updated_property = ImageProperty::update_by_id(property_id, property_req, &mut write).await?;
    
    let mut affected_image_ids = vec![existing_property.image_id.to_string()];
    
    // If apply_to_newer_versions is true, sync to newer versions
    if req.apply_to_newer_versions {
        let newer_images = PropertyInheritanceManager::find_newer_image_versions(&image, &mut write).await?;
        
        PropertyInheritanceManager::sync_property_across_versions(
            &updated_property,
            &newer_images.iter().map(|img| img.id).collect::<Vec<_>>(),
            &mut write,
        ).await?;
        
        affected_image_ids.extend(newer_images.iter().map(|img| img.id.to_string()));
    }

    Ok(api::ImageServiceUpdateImagePropertyResponse {
        property: Some(updated_property.into()),
        affected_image_ids,
    })
}

async fn delete_image_property(
    req: api::ImageServiceDeleteImagePropertyRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceDeleteImagePropertyResponse, Error> {
    let authz = write.auth(&meta, ImageAdminPerm::DeleteProperty).await?;

    let property_id = req.image_property_id.parse().map_err(Error::ParseImageId)?;
    
    // Get the existing property to find the image
    let existing_property = ImageProperty::by_id(property_id, &mut write).await?;
    let image = Image::by_id(existing_property.image_id, None, &authz, &mut write).await?;
    
    // Delete the property
    ImageProperty::delete_by_id(property_id, &mut write).await?;
    
    let mut affected_image_ids = vec![existing_property.image_id.to_string()];
    
    // If apply_to_newer_versions is true, delete from newer versions
    if req.apply_to_newer_versions {
        let newer_images = PropertyInheritanceManager::find_newer_image_versions(&image, &mut write).await?;
        
        for newer_image in newer_images {
            // Find and delete the corresponding property in newer images
            let properties = ImageProperty::by_image_id(newer_image.id, &mut write).await?;
            if let Some(prop) = properties.iter().find(|p| p.key == existing_property.key) {
                ImageProperty::delete_by_id(prop.id, &mut write).await?;
                affected_image_ids.push(newer_image.id.to_string());
            }
        }
    }

    Ok(api::ImageServiceDeleteImagePropertyResponse {
        affected_image_ids,
    })
}

async fn copy_image_properties(
    req: api::ImageServiceCopyImagePropertiesRequest,
    meta: Metadata,
    mut write: WriteConn<'_, '_>,
) -> Result<api::ImageServiceCopyImagePropertiesResponse, Error> {
    let authz = write.auth(&meta, ImageAdminPerm::CopyProperties).await?;

    let source_image_id = req.source_image_id.parse().map_err(Error::ParseImageId)?;
    let target_image_ids: Result<Vec<_>, _> = req
        .target_image_ids
        .iter()
        .map(|id| id.parse().map_err(Error::ParseImageId))
        .collect();
    let target_image_ids = target_image_ids?;

    // Verify source image exists and user has access
    let source_image = Image::by_id(source_image_id, None, &authz, &mut write).await?;
    
    let mut affected_image_ids = Vec::new();
    let mut total_properties_copied = 0;
    
    for target_image_id in target_image_ids {
        // Verify target image exists and user has access
        let _target_image = Image::by_id(target_image_id, None, &authz, &mut write).await?;
        
        let copied_properties = PropertyInheritanceManager::copy_properties_to_new_version(
            &source_image,
            target_image_id,
            &mut write,
        ).await?;
        
        if !copied_properties.is_empty() {
            affected_image_ids.push(target_image_id.to_string());
            total_properties_copied += copied_properties.len() as u32;
        }
    }

    Ok(api::ImageServiceCopyImagePropertiesResponse {
        affected_image_ids,
        properties_copied: total_properties_copied,
    })
}

impl api::Image {
    pub fn from(
        image: Image,
        properties: Vec<ImageProperty>,
        rules: Vec<ImageRule>,
    ) -> Result<Self, Error> {
        Ok(api::Image {
            image_id: image.id.to_string(),
            protocol_version_id: image.protocol_version_id.to_string(),
            org_id: image.org_id.map(|id| id.to_string()),
            image_uri: image.image_uri,
            build_version: u64::try_from(image.build_version).map_err(Error::BuildVersion)?,
            description: image.description,
            properties: properties.into_iter().map(Into::into).collect(),
            firewall: Some(common::FirewallConfig {
                default_in: common::FirewallAction::from(image.default_firewall_in).into(),
                default_out: common::FirewallAction::from(image.default_firewall_out).into(),
                rules: rules.into_iter().map(Into::into).collect(),
            }),
            min_cpu_cores: u64::try_from(image.min_cpu_cores).map_err(Error::MinCpu)?,
            min_memory_bytes: u64::try_from(image.min_memory_bytes).map_err(Error::MinMemory)?,
            min_disk_bytes: u64::try_from(image.min_disk_bytes).map_err(Error::MinDisk)?,
            min_babel_version: image.min_babel_version.to_string(),
            ramdisks: image.ramdisks.into_iter().map(Into::into).collect(),
            visibility: common::Visibility::from(image.visibility).into(),
            created_at: Some(NanosUtc::from(image.created_at).into()),
            updated_at: image.updated_at.map(NanosUtc::from).map(Into::into),
            dns_scheme: image.dns_scheme,
        })
    }
}
