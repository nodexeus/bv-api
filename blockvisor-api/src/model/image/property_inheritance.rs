use std::collections::HashSet;

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use displaydoc::Display as DisplayDoc;
use thiserror::Error;

use crate::database::Conn;
use crate::model::protocol::VersionId;
use crate::auth::resource::OrgId;
use crate::model::schema::images;

use super::{Image, ImageId, ImageProperty, NewProperty};

#[derive(Debug, DisplayDoc, Error)]
pub enum PropertyInheritanceError {
    /// Failed to find latest image for protocol version `{0}` (org: {1:?}): {2}
    FindLatestImage(VersionId, Option<OrgId>, diesel::result::Error),
    /// Failed to find related images for image `{0}`: {1}
    FindRelatedImages(ImageId, diesel::result::Error),
    /// Failed to copy properties from image `{0}` to image `{1}`: {2}
    CopyProperties(ImageId, ImageId, diesel::result::Error),
    /// Failed to inherit properties for new image `{0}`: {1}
    InheritProperties(ImageId, diesel::result::Error),
    /// Failed to sync property across versions: {0}
    SyncProperty(diesel::result::Error),
    /// Image property error: {0}
    Property(#[from] super::property::Error),
    /// Property inheritance validation failed: {0}
    ValidationFailed(String),
    /// Cannot inherit properties: source image has no properties to copy
    NoPropertiesToInherit,
    /// Property conflict during inheritance: {0}
    PropertyConflict(String),
    /// Inheritance rollback failed: {0}
    RollbackFailed(String),
}

impl From<PropertyInheritanceError> for crate::grpc::Status {
    fn from(err: PropertyInheritanceError) -> Self {
        use PropertyInheritanceError::*;
        match err {
            FindLatestImage(_, _, _) | FindRelatedImages(_, _) => {
                crate::grpc::Status::not_found("Related images not found")
            }
            CopyProperties(_, _, _) | InheritProperties(_, _) | SyncProperty(_) => {
                crate::grpc::Status::internal("Property inheritance operation failed")
            }
            Property(prop_err) => prop_err.into(),
            ValidationFailed(msg) => crate::grpc::Status::invalid_argument(format!("Inheritance validation failed: {}", msg)),
            NoPropertiesToInherit => crate::grpc::Status::failed_precondition("Source image has no properties to inherit"),
            PropertyConflict(msg) => crate::grpc::Status::failed_precondition(format!("Property conflict: {}", msg)),
            RollbackFailed(msg) => crate::grpc::Status::internal(format!("Inheritance rollback failed: {}", msg)),
        }
    }
}

pub struct PropertyInheritanceManager;

impl PropertyInheritanceManager {
    /// Automatically copy properties from the latest image version when creating a new version
    /// This is the core method that solves the property inheritance problem
    pub async fn inherit_properties_for_new_image(
        protocol_version_id: VersionId,
        org_id: Option<OrgId>,
        new_image_id: ImageId,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<ImageProperty>, PropertyInheritanceError> {
        // Find the latest existing image for this protocol version (excluding the new one)
        let latest_image = images::table
            .filter(images::protocol_version_id.eq(protocol_version_id))
            .filter(images::org_id.eq(org_id).or(images::org_id.is_null()))
            .filter(images::id.ne(new_image_id)) // Exclude the newly created image
            .order_by(images::build_version.desc())
            .first::<Image>(conn)
            .await
            .optional()
            .map_err(|err| PropertyInheritanceError::FindLatestImage(protocol_version_id, org_id, err))?;

        // If no previous image exists, return empty properties
        let source_image = match latest_image {
            Some(image) => image,
            None => return Ok(Vec::new()),
        };

        // Validate that the source image has properties to inherit
        let source_properties = ImageProperty::by_image_id(source_image.id, conn)
            .await
            .map_err(PropertyInheritanceError::Property)?;

        if source_properties.is_empty() {
            return Ok(Vec::new()); // No properties to inherit, but not an error
        }

        // Copy all properties from the source image to the new image with error handling
        Self::copy_properties_to_new_version(&source_image, new_image_id, conn)
            .await
            .map_err(|err| {
                tracing::error!("Failed to inherit properties from image {} to {}: {}", source_image.id, new_image_id, err);
                err
            })
    }

    /// Copy properties from one specific image to another
    pub async fn copy_properties_to_new_version(
        source_image: &Image,
        target_image_id: ImageId,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<ImageProperty>, PropertyInheritanceError> {
        // Get all properties from the source image
        let source_properties = ImageProperty::by_image_id(source_image.id, conn)
            .await
            .map_err(PropertyInheritanceError::Property)?;

        if source_properties.is_empty() {
            return Err(PropertyInheritanceError::NoPropertiesToInherit);
        }

        // Check for existing properties in target image that might conflict
        let existing_properties = ImageProperty::by_image_id(target_image_id, conn)
            .await
            .map_err(PropertyInheritanceError::Property)?;

        let existing_keys: HashSet<_> = existing_properties.iter().map(|p| &p.key).collect();

        // Filter out properties that already exist in the target image
        let properties_to_copy: Vec<_> = source_properties
            .into_iter()
            .filter(|prop| !existing_keys.contains(&prop.key))
            .collect();

        if properties_to_copy.is_empty() {
            tracing::info!("No new properties to copy from image {} to {}", source_image.id, target_image_id);
            return Ok(Vec::new());
        }

        // Create new properties for the target image with identical configurations
        let new_properties: Vec<NewProperty> = properties_to_copy
            .into_iter()
            .map(|prop| NewProperty {
                image_id: target_image_id,
                key: prop.key,
                key_group: prop.key_group,
                is_group_default: prop.is_group_default,
                new_archive: prop.new_archive,
                default_value: prop.default_value,
                dynamic_value: prop.dynamic_value,
                description: prop.description,
                ui_type: prop.ui_type,
                add_cpu_cores: prop.add_cpu_cores,
                add_memory_bytes: prop.add_memory_bytes,
                add_disk_bytes: prop.add_disk_bytes,
                display_name: prop.display_name,
                display_group: prop.display_group,
                variants: prop.variants,
            })
            .collect();

        // Bulk create the new properties with error handling
        NewProperty::bulk_create(new_properties, conn)
            .await
            .map_err(|err| {
                tracing::error!("Failed to bulk create properties during inheritance: {}", err);
                PropertyInheritanceError::Property(err)
            })
    }

    /// Sync a property change across multiple image versions
    /// This allows admins to update properties on older versions and apply to newer ones
    pub async fn sync_property_across_versions(
        source_property: &ImageProperty,
        target_image_ids: &[ImageId],
        conn: &mut Conn<'_>,
    ) -> Result<(), PropertyInheritanceError> {
        use crate::model::schema::image_properties;

        if target_image_ids.is_empty() {
            return Ok(());
        }

        // Validate that all target images exist and have the property to sync
        for &target_image_id in target_image_ids {
            let existing_property = image_properties::table
                .filter(image_properties::image_id.eq(target_image_id))
                .filter(image_properties::key.eq(&source_property.key))
                .first::<ImageProperty>(conn)
                .await
                .optional()
                .map_err(PropertyInheritanceError::SyncProperty)?;

            if existing_property.is_none() {
                return Err(PropertyInheritanceError::PropertyConflict(
                    format!("Property '{}' not found in target image {}", source_property.key, target_image_id)
                ));
            }
        }

        // Update all matching properties in target images
        for &target_image_id in target_image_ids {
            let updated_rows = diesel::update(
                image_properties::table
                    .filter(image_properties::image_id.eq(target_image_id))
                    .filter(image_properties::key.eq(&source_property.key))
            )
            .set((
                image_properties::key_group.eq(&source_property.key_group),
                image_properties::is_group_default.eq(&source_property.is_group_default),
                image_properties::new_archive.eq(&source_property.new_archive),
                image_properties::default_value.eq(&source_property.default_value),
                image_properties::dynamic_value.eq(&source_property.dynamic_value),
                image_properties::description.eq(&source_property.description),
                image_properties::ui_type.eq(&source_property.ui_type),
                image_properties::add_cpu_cores.eq(&source_property.add_cpu_cores),
                image_properties::add_memory_bytes.eq(&source_property.add_memory_bytes),
                image_properties::add_disk_bytes.eq(&source_property.add_disk_bytes),
                image_properties::display_name.eq(&source_property.display_name),
                image_properties::display_group.eq(&source_property.display_group),
            ))
            .execute(conn)
            .await
            .map_err(PropertyInheritanceError::SyncProperty)?;

            if updated_rows == 0 {
                tracing::warn!("No rows updated when syncing property '{}' to image {}", source_property.key, target_image_id);
            }
        }

        tracing::info!("Successfully synced property '{}' across {} image versions", source_property.key, target_image_ids.len());
        Ok(())
    }

    /// Find all images for the same protocol version (different builds)
    /// This helps identify related image versions for property synchronization
    pub async fn find_related_images(
        image: &Image,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Image>, PropertyInheritanceError> {
        images::table
            .filter(images::protocol_version_id.eq(image.protocol_version_id))
            .filter(images::org_id.eq(image.org_id).or(images::org_id.is_null()))
            .filter(images::id.ne(image.id)) // Exclude the source image itself
            .order_by(images::build_version.desc())
            .get_results(conn)
            .await
            .map_err(|err| PropertyInheritanceError::FindRelatedImages(image.id, err))
    }

    /// Find newer image versions for a given image
    /// This is useful for applying property changes to newer versions only
    pub async fn find_newer_image_versions(
        image: &Image,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Image>, PropertyInheritanceError> {
        images::table
            .filter(images::protocol_version_id.eq(image.protocol_version_id))
            .filter(images::org_id.eq(image.org_id).or(images::org_id.is_null()))
            .filter(images::build_version.gt(image.build_version))
            .order_by(images::build_version.asc())
            .get_results(conn)
            .await
            .map_err(|err| PropertyInheritanceError::FindRelatedImages(image.id, err))
    }
}