use std::collections::{HashMap, HashSet};

use derive_more::{Deref, Display, From, Into};
use diesel::prelude::*;
use diesel::result::Error::NotFound;
use diesel_async::RunQueryDsl;
use diesel_derive_enum::DbEnum;
use diesel_derive_newtype::DieselNewType;
use displaydoc::Display as DisplayDoc;
use thiserror::Error;
use uuid::Uuid;

use crate::database::Conn;
use crate::grpc::{Status, api, common};
use crate::model::schema::{image_properties, sql_types};
use crate::util::LOWER_KEBAB_CASE;

use super::ImageId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, DbEnum)]
#[ExistingTypePath = "sql_types::EnumUiType"]
pub enum UiType {
    #[db_rename = "switch"]
    Switch,
    #[db_rename = "text"]
    Text,
    #[db_rename = "password"]
    Password,
    #[db_rename = "enum"]
    Enum,
}

impl TryFrom<common::UiType> for UiType {
    type Error = Error;

    fn try_from(ui_type: common::UiType) -> Result<Self, Self::Error> {
        match ui_type {
            common::UiType::Switch => Ok(UiType::Switch),
            common::UiType::Text => Ok(UiType::Text),
            common::UiType::Password => Ok(UiType::Password),
            common::UiType::Enum => Ok(UiType::Enum),
            common::UiType::Unspecified => Err(Error::UnknownUiType),
        }
    }
}

impl From<UiType> for common::UiType {
    fn from(ui_type: UiType) -> Self {
        match ui_type {
            UiType::Switch => common::UiType::Switch,
            UiType::Text => common::UiType::Text,
            UiType::Password => common::UiType::Password,
            UiType::Enum => common::UiType::Enum,
        }
    }
}

#[derive(Debug, DisplayDoc, Error)]
pub enum Error {
    /// Failed to bulk create image properties: {0}
    BulkCreate(diesel::result::Error),
    /// Failed to find image property for id `{0}`: {1}
    ById(ImagePropertyId, diesel::result::Error),
    /// Failed to find image properties for property ids `{0:?}`: {1}
    ByIds(HashSet<ImagePropertyId>, diesel::result::Error),
    /// Failed to find image properties for image id `{0:?}`: {1}
    ByImageId(ImageId, diesel::result::Error),
    /// Failed to find image properties for image ids `{0:?}`: {1}
    ByImageIds(HashSet<ImageId>, diesel::result::Error),
    /// Multiple defaults set for image property key group `{0}`.
    GroupMultipleDefaults(ImagePropertyGroup),
    /// No default set for image property key group `{0}`.
    GroupNoDefault(ImagePropertyGroup),
    /// ImagePropertyGroup is not lower-kebab-case: {0}
    PropertyGroupChars(String),
    /// ImagePropertyGroup must be at least 3 characters: {0}
    PropertyGroupLen(String),
    /// ImagePropertyKey is not lower-kebab-case: {0}
    PropertyKeyChars(String),
    /// ImagePropertyKey must be at least 3 characters: {0}
    PropertyKeyLen(String),
    /// Unknown UiType.
    UnknownUiType,
    /// Admin error: {0}
    Admin(#[from] ImagePropertyAdminError),
}

/// Specific error types for image property admin operations
#[derive(Debug, DisplayDoc, Error)]
pub enum ImagePropertyAdminError {
    /// Property key '{0}' already exists for this image
    DuplicateKey(String),
    /// Cannot delete property '{0}': {1} nodes are currently using this image
    PropertyInUse(String, usize),
    /// Invalid property configuration: {0}
    InvalidConfiguration(String),
    /// Property inheritance failed: {0}
    InheritanceFailed(String),
    /// Property validation failed: {0}
    ValidationFailed(String),
    /// Cannot modify property '{0}': it is required by the protocol
    RequiredProperty(String),
    /// Property '{0}' not found in image
    PropertyNotFound(String),
    /// Invalid resource configuration: {0}
    InvalidResourceConfig(String),
    /// Property group '{0}' has conflicting configurations
    GroupConflict(String),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            ById(_, NotFound) => Status::not_found("Image property not found."),
            GroupMultipleDefaults(_) | GroupNoDefault(_) => {
                Status::failed_precondition("is_group_default")
            }
            UnknownUiType => Status::invalid_argument("ui_type"),
            Admin(admin_err) => admin_err.into(),
            _ => Status::internal("Internal error."),
        }
    }
}

impl From<ImagePropertyAdminError> for Status {
    fn from(err: ImagePropertyAdminError) -> Self {
        use ImagePropertyAdminError::*;
        match err {
            DuplicateKey(key) => Status::already_exists(format!("Property key '{}' already exists for this image", key)),
            PropertyInUse(key, count) => Status::failed_precondition(
                format!("Cannot delete property '{}': {} nodes are currently using this image", key, count)
            ),
            InvalidConfiguration(msg) => Status::invalid_argument(format!("Invalid property configuration: {}", msg)),
            InheritanceFailed(msg) => Status::internal(format!("Property inheritance failed: {}", msg)),
            ValidationFailed(msg) => Status::invalid_argument(format!("Property validation failed: {}", msg)),
            RequiredProperty(key) => Status::failed_precondition(
                format!("Cannot modify property '{}': it is required by the protocol", key)
            ),
            PropertyNotFound(key) => Status::not_found(format!("Property '{}' not found in image", key)),
            InvalidResourceConfig(msg) => Status::invalid_argument(format!("Invalid resource configuration: {}", msg)),
            GroupConflict(group) => Status::failed_precondition(
                format!("Property group '{}' has conflicting configurations", group)
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Display, Hash, PartialEq, Eq, DieselNewType, Deref, From)]
pub struct ImagePropertyId(Uuid);

impl std::str::FromStr for ImagePropertyId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ImagePropertyId(Uuid::parse_str(s)?))
    }
}

#[derive(Clone, derive_more::Debug, Display, Hash, PartialEq, Eq, DieselNewType, Deref, Into)]
#[debug("{_0}")]
pub struct ImagePropertyKey(String);

impl ImagePropertyKey {
    pub fn new(key: String) -> Result<Self, Error> {
        if key.len() < 3 {
            Err(Error::PropertyKeyLen(key))
        } else if !key.chars().all(|c| LOWER_KEBAB_CASE.contains(c)) {
            Err(Error::PropertyKeyChars(key))
        } else {
            Ok(ImagePropertyKey(key))
        }
    }
}

#[derive(Clone, derive_more::Debug, Display, Hash, PartialEq, Eq, DieselNewType, Deref, Into)]
#[debug("{_0}")]
pub struct ImagePropertyGroup(String);

impl ImagePropertyGroup {
    pub fn new(key: String) -> Result<Self, Error> {
        if key.len() < 3 {
            Err(Error::PropertyGroupLen(key))
        } else if !key.chars().all(|c| LOWER_KEBAB_CASE.contains(c)) {
            Err(Error::PropertyGroupChars(key))
        } else {
            Ok(ImagePropertyGroup(key))
        }
    }
}

#[derive(Clone, Debug, Queryable)]
#[diesel(table_name = image_properties)]
pub struct ImageProperty {
    pub id: ImagePropertyId,
    pub image_id: ImageId,
    pub key: ImagePropertyKey,
    pub key_group: Option<ImagePropertyGroup>,
    pub is_group_default: Option<bool>,
    pub new_archive: bool,
    pub default_value: String,
    pub dynamic_value: bool,
    pub description: Option<String>,
    pub ui_type: UiType,
    pub add_cpu_cores: Option<i64>,
    pub add_memory_bytes: Option<i64>,
    pub add_disk_bytes: Option<i64>,
    pub display_name: Option<String>,
    pub display_group: Option<String>,
    pub variants: Option<serde_json::Value>,
}

impl ImageProperty {
    pub async fn by_id(id: ImagePropertyId, conn: &mut Conn<'_>) -> Result<Self, Error> {
        image_properties::table
            .find(id)
            .get_result(conn)
            .await
            .map_err(|err| Error::ById(id, err))
    }

    /// Validate property configuration for admin operations
    pub fn validate_admin_config(property: &api::AddImageProperty) -> Result<(), ImagePropertyAdminError> {
        // Validate property key format
        if property.key.is_empty() {
            return Err(ImagePropertyAdminError::ValidationFailed("Property key cannot be empty".to_string()));
        }

        // Validate resource configurations are non-negative
        if let Some(cpu) = property.add_cpu_cores {
            if cpu < 0 {
                return Err(ImagePropertyAdminError::InvalidResourceConfig("CPU cores cannot be negative".to_string()));
            }
        }

        if let Some(memory) = property.add_memory_bytes {
            if memory < 0 {
                return Err(ImagePropertyAdminError::InvalidResourceConfig("Memory bytes cannot be negative".to_string()));
            }
        }

        if let Some(disk) = property.add_disk_bytes {
            if disk < 0 {
                return Err(ImagePropertyAdminError::InvalidResourceConfig("Disk bytes cannot be negative".to_string()));
            }
        }

        // Validate UI type specific configurations
        match property.ui_type() {
            common::UiType::Enum => {
                if property.default_value.is_empty() {
                    return Err(ImagePropertyAdminError::ValidationFailed(
                        "Enum properties must have a default value".to_string()
                    ));
                }
            }
            common::UiType::Switch => {
                if !["true", "false"].contains(&property.default_value.as_str()) {
                    return Err(ImagePropertyAdminError::ValidationFailed(
                        "Switch properties must have 'true' or 'false' as default value".to_string()
                    ));
                }
            }
            _ => {}
        }

        // Validate group configuration
        if let Some(ref group) = property.key_group {
            if group.is_empty() {
                return Err(ImagePropertyAdminError::ValidationFailed("Property group cannot be empty".to_string()));
            }
        }

        // Validate variants if present
        if let Some(ref variants_str) = property.variants {
            if let Ok(variants_json) = serde_json::from_str::<serde_json::Value>(variants_str) {
                if let Some(variants_array) = variants_json.as_array() {
                    if variants_array.is_empty() {
                        return Err(ImagePropertyAdminError::ValidationFailed("Variants array cannot be empty".to_string()));
                    }
                    
                    // Validate each variant key format
                    for variant in variants_array {
                        if let Some(variant_str) = variant.as_str() {
                            if variant_str.len() < 3 {
                                return Err(ImagePropertyAdminError::ValidationFailed(
                                    format!("Variant key '{}' must be at least 3 characters", variant_str)
                                ));
                            }
                            if !variant_str.chars().all(|c| crate::util::LOWER_KEBAB_CASE.contains(c)) {
                                return Err(ImagePropertyAdminError::ValidationFailed(
                                    format!("Variant key '{}' must be lower-kebab-case", variant_str)
                                ));
                            }
                        } else {
                            return Err(ImagePropertyAdminError::ValidationFailed("Variant keys must be strings".to_string()));
                        }
                    }
                } else {
                    return Err(ImagePropertyAdminError::ValidationFailed("Variants must be an array".to_string()));
                }
            } else {
                return Err(ImagePropertyAdminError::ValidationFailed("Invalid JSON format for variants".to_string()));
            }
        }

        Ok(())
    }

    /// Check if a property is in use by any nodes
    pub async fn check_property_usage(
        image_id: ImageId,
        _property_key: &ImagePropertyKey,
        conn: &mut Conn<'_>,
    ) -> Result<usize, Error> {
        use crate::model::schema::nodes;
        
        // Count nodes using this image
        let node_count = nodes::table
            .filter(nodes::image_id.eq(image_id))
            .count()
            .get_result::<i64>(conn)
            .await
            .map_err(|err| Error::ByImageId(image_id, err))?;

        Ok(node_count as usize)
    }

    pub async fn by_ids(
        ids: &HashSet<ImagePropertyId>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        image_properties::table
            .filter(image_properties::id.eq_any(ids))
            .get_results(conn)
            .await
            .map_err(|err| Error::ByIds(ids.clone(), err))
    }

    pub async fn by_image_id(image_id: ImageId, conn: &mut Conn<'_>) -> Result<Vec<Self>, Error> {
        image_properties::table
            .filter(image_properties::image_id.eq(image_id))
            .get_results(conn)
            .await
            .map_err(|err| Error::ByImageId(image_id, err))
    }

    /// Get image properties filtered by variant key
    pub async fn by_image_id_and_variant(
        image_id: ImageId, 
        variant_key: Option<&str>,
        conn: &mut Conn<'_>
    ) -> Result<Vec<Self>, Error> {
        let mut query = image_properties::table
            .filter(image_properties::image_id.eq(image_id))
            .into_boxed();

        if let Some(variant) = variant_key {
            // Filter properties that either:
            // 1. Have no variant restriction (variants is null)
            // 2. Include this variant in their variants array
            // Use PostgreSQL's JSONB ? operator to check if the variant exists as a string in the array
            query = query.filter(
                image_properties::variants.is_null()
                .or(diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                    "variants ? '{}'", variant.replace("'", "''")
                )))
            );
        }

        query
            .get_results(conn)
            .await
            .map_err(|err| Error::ByImageId(image_id, err))
    }

    pub async fn by_image_ids(
        image_ids: &HashSet<ImageId>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        image_properties::table
            .filter(image_properties::image_id.eq_any(image_ids))
            .get_results(conn)
            .await
            .map_err(|err| Error::ByImageIds(image_ids.clone(), err))
    }

    /// Create a new property for a specific image (admin operation)
    pub async fn create_for_image(
        image_id: ImageId,
        property: api::AddImageProperty,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        // Validate property configuration
        Self::validate_admin_config(&property)
            .map_err(Error::Admin)?;

        // Check for duplicate keys within the same image
        let existing = image_properties::table
            .filter(image_properties::image_id.eq(image_id))
            .filter(image_properties::key.eq(&property.key))
            .first::<Self>(conn)
            .await
            .optional()
            .map_err(|err| Error::ByImageId(image_id, err))?;

        if existing.is_some() {
            return Err(Error::Admin(ImagePropertyAdminError::DuplicateKey(property.key.clone())));
        }

        let new_property = NewProperty::from(image_id, property)?;
        
        diesel::insert_into(image_properties::table)
            .values(new_property)
            .get_result(conn)
            .await
            .map_err(Error::BulkCreate)
    }

    /// Update an existing image property by ID (admin operation)
    pub async fn update_by_id(
        id: ImagePropertyId,
        property: api::AddImageProperty,
        conn: &mut Conn<'_>,
    ) -> Result<Self, Error> {
        // Validate property configuration
        Self::validate_admin_config(&property)
            .map_err(Error::Admin)?;

        // Get the existing property to check image_id for duplicate key validation
        let existing = Self::by_id(id, conn).await?;
        
        // Check for duplicate keys within the same image (excluding the current property)
        let duplicate = image_properties::table
            .filter(image_properties::image_id.eq(existing.image_id))
            .filter(image_properties::key.eq(&property.key))
            .filter(image_properties::id.ne(id))
            .first::<Self>(conn)
            .await
            .optional()
            .map_err(|err| Error::ByImageId(existing.image_id, err))?;

        if duplicate.is_some() {
            return Err(Error::Admin(ImagePropertyAdminError::DuplicateKey(property.key.clone())));
        }

        let ui_type = UiType::try_from(property.ui_type())?;
        let key = ImagePropertyKey::new(property.key)?;
        let key_group = property.key_group.map(ImagePropertyGroup::new).transpose()?;
        let variants = property.variants.and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok());

        diesel::update(image_properties::table.find(id))
            .set((
                image_properties::key.eq(key),
                image_properties::key_group.eq(key_group),
                image_properties::is_group_default.eq(property.is_group_default),
                image_properties::new_archive.eq(property.new_archive),
                image_properties::default_value.eq(property.default_value),
                image_properties::dynamic_value.eq(property.dynamic_value),
                image_properties::description.eq(property.description),
                image_properties::ui_type.eq(ui_type),
                image_properties::add_cpu_cores.eq(property.add_cpu_cores),
                image_properties::add_memory_bytes.eq(property.add_memory_bytes),
                image_properties::add_disk_bytes.eq(property.add_disk_bytes),
                image_properties::display_name.eq(property.display_name),
                image_properties::display_group.eq(property.display_group),
                image_properties::variants.eq(variants),
            ))
            .get_result(conn)
            .await
            .map_err(|err| Error::ById(id, err))
    }

    /// Delete an image property by ID (admin operation)
    pub async fn delete_by_id(
        id: ImagePropertyId,
        conn: &mut Conn<'_>,
    ) -> Result<(), Error> {
        // Get the existing property to check usage
        let existing = Self::by_id(id, conn).await?;
        
        // Check if the property is in use by any nodes
        let usage_count = Self::check_property_usage(existing.image_id, &existing.key, conn).await?;
        if usage_count > 0 {
            return Err(Error::Admin(ImagePropertyAdminError::PropertyInUse(
                existing.key.to_string(),
                usage_count,
            )));
        }

        diesel::delete(image_properties::table.find(id))
            .execute(conn)
            .await
            .map_err(|err| Error::ById(id, err))?;
        
        Ok(())
    }

    /// Copy properties from one image to another (for inheritance)
    pub async fn copy_to_image(
        source_image_id: ImageId,
        target_image_id: ImageId,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<Self>, Error> {
        // Get all properties from the source image
        let source_properties = Self::by_image_id(source_image_id, conn).await?;

        // Create new properties for the target image
        let new_properties: Vec<NewProperty> = source_properties
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

        // Bulk create the new properties
        NewProperty::bulk_create(new_properties, conn).await
    }
}

impl From<ImageProperty> for api::ImageProperty {
    fn from(property: ImageProperty) -> Self {
        api::ImageProperty {
            image_property_id: property.id.to_string(),
            image_id: property.image_id.to_string(),
            key: property.key.into(),
            key_group: property.key_group.map(Into::into),
            is_group_default: property.is_group_default,
            new_archive: property.new_archive,
            default_value: property.default_value,
            dynamic_value: property.dynamic_value,
            ui_type: common::UiType::from(property.ui_type).into(),
            display_name: property.display_name,
            display_group: property.display_group,
            description: property.description,
            add_cpu_cores: property.add_cpu_cores,
            add_memory_bytes: property.add_memory_bytes,
            add_disk_bytes: property.add_disk_bytes,
            variants: property.variants.map(|v| v.to_string()),
        }
    }
}

#[derive(Debug, Insertable)]
#[diesel(table_name = image_properties)]
pub struct NewProperty {
    pub image_id: ImageId,
    pub key: ImagePropertyKey,
    pub key_group: Option<ImagePropertyGroup>,
    pub is_group_default: Option<bool>,
    pub new_archive: bool,
    pub default_value: String,
    pub dynamic_value: bool,
    pub description: Option<String>,
    pub ui_type: UiType,
    pub add_cpu_cores: Option<i64>,
    pub add_memory_bytes: Option<i64>,
    pub add_disk_bytes: Option<i64>,
    pub display_name: Option<String>,
    pub display_group: Option<String>,
    pub variants: Option<serde_json::Value>,
}

impl NewProperty {
    pub fn new(image_id: ImageId, property: ImageProperty) -> Self {
        NewProperty {
            image_id,
            key: property.key,
            key_group: property.key_group,
            is_group_default: property.is_group_default,
            new_archive: property.new_archive,
            default_value: property.default_value,
            dynamic_value: property.dynamic_value,
            description: property.description,
            ui_type: property.ui_type,
            add_cpu_cores: property.add_cpu_cores,
            add_memory_bytes: property.add_memory_bytes,
            add_disk_bytes: property.add_disk_bytes,
            display_name: property.display_name,
            display_group: property.display_group,
            variants: property.variants,
        }
    }

    pub fn from(image_id: ImageId, property: api::AddImageProperty) -> Result<Self, Error> {
        let ui_type = UiType::try_from(property.ui_type())?;

        Ok(NewProperty {
            image_id,
            key: ImagePropertyKey::new(property.key)?,
            key_group: property
                .key_group
                .map(ImagePropertyGroup::new)
                .transpose()?,
            is_group_default: property.is_group_default,
            new_archive: property.new_archive,
            default_value: property.default_value,
            dynamic_value: property.dynamic_value,
            description: property.description,
            ui_type,
            add_cpu_cores: property.add_cpu_cores,
            add_memory_bytes: property.add_memory_bytes,
            add_disk_bytes: property.add_disk_bytes,
            display_name: property.display_name,
            display_group: property.display_group,
            variants: property.variants.and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok()),
        })
    }

    pub async fn bulk_create(
        properties: Vec<Self>,
        conn: &mut Conn<'_>,
    ) -> Result<Vec<ImageProperty>, Error> {
        let mut groups = HashSet::new();
        let mut defaults = HashSet::new();
        for property in &properties {
            if let Some(group) = &property.key_group {
                groups.insert(group.clone());
                if property.is_group_default.unwrap_or(false) && !defaults.insert(group.clone()) {
                    return Err(Error::GroupMultipleDefaults(group.clone()));
                }
            }
        }

        for group in groups {
            if !defaults.contains(&group) {
                return Err(Error::GroupNoDefault(group));
            }
        }

        diesel::insert_into(image_properties::table)
            .values(properties)
            .get_results(conn)
            .await
            .map_err(Error::BulkCreate)
    }
}

#[derive(Clone, Debug)]
pub struct NewImagePropertyValue {
    pub key: ImagePropertyKey,
    pub value: String,
    pub has_changed: bool,
}

impl From<ImageProperty> for NewImagePropertyValue {
    fn from(property: ImageProperty) -> Self {
        NewImagePropertyValue {
            key: property.key,
            value: property.default_value,
            has_changed: false,
        }
    }
}

impl From<NewImagePropertyValue> for api::NewImagePropertyValue {
    fn from(value: NewImagePropertyValue) -> Self {
        api::NewImagePropertyValue {
            key: value.key.0,
            value: value.value,
        }
    }
}

impl TryFrom<api::NewImagePropertyValue> for NewImagePropertyValue {
    type Error = Error;

    fn try_from(value: api::NewImagePropertyValue) -> Result<Self, Self::Error> {
        Ok(NewImagePropertyValue {
            key: ImagePropertyKey::new(value.key)?,
            value: value.value,
            has_changed: true,
        })
    }
}

impl From<PropertyValueConfig> for NewImagePropertyValue {
    fn from(property: PropertyValueConfig) -> Self {
        NewImagePropertyValue {
            key: property.key,
            value: property.value,
            has_changed: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PropertyValueConfig {
    pub key: ImagePropertyKey,
    pub key_group: Option<ImagePropertyGroup>,
    pub value: String,
    pub has_changed: bool,
}

impl From<ImageProperty> for PropertyValueConfig {
    fn from(property: ImageProperty) -> Self {
        PropertyValueConfig {
            key: property.key,
            key_group: property.key_group,
            value: property.default_value,
            has_changed: false,
        }
    }
}

impl From<PropertyValueConfig> for common::PropertyValueConfig {
    fn from(value: PropertyValueConfig) -> Self {
        common::PropertyValueConfig {
            key: value.key.0,
            key_group: value.key_group.map(|group| group.0),
            value: value.value,
        }
    }
}

impl TryFrom<common::PropertyValueConfig> for PropertyValueConfig {
    type Error = Error;

    fn try_from(value: common::PropertyValueConfig) -> Result<Self, Self::Error> {
        Ok(PropertyValueConfig {
            key: ImagePropertyKey::new(value.key)?,
            key_group: value.key_group.map(ImagePropertyGroup::new).transpose()?,
            value: value.value,
            has_changed: true,
        })
    }
}



pub struct PropertyMap {
    pub key_to_value: HashMap<ImagePropertyKey, NewImagePropertyValue>,
    pub key_to_group: HashMap<ImagePropertyKey, ImagePropertyGroup>,
    pub group_to_keys: HashMap<ImagePropertyGroup, Vec<ImagePropertyKey>>,
}

impl PropertyMap {
    pub fn new(properties: Vec<ImageProperty>) -> Self {
        let mut key_to_value = HashMap::new();
        let mut key_to_group = HashMap::new();
        let mut group_to_keys = HashMap::<_, Vec<_>>::new();

        for property in properties {
            if let Some(group) = &property.key_group {
                key_to_group.insert(property.key.clone(), group.clone());
                group_to_keys
                    .entry(group.clone())
                    .or_default()
                    .push(property.key.clone());

                if property.is_group_default == Some(true) {
                    key_to_value.insert(property.key.clone(), property.into());
                }
            } else {
                key_to_value.insert(property.key.clone(), property.into());
            }
        }

        PropertyMap {
            key_to_value,
            key_to_group,
            group_to_keys,
        }
    }

    /// Create a PropertyMap with properties filtered by variant
    pub fn new_with_variant(properties: Vec<ImageProperty>, variant_key: Option<&str>) -> Self {
        let filtered_properties = if let Some(variant) = variant_key {
            properties
                .into_iter()
                .filter(|prop| {
                    // Include property if:
                    // 1. No variant restriction (variants is null)
                    // 2. Variant is included in variants array
                    prop.variants.is_none() || 
                    prop.variants
                        .as_ref()
                        .and_then(|v| v.as_array())
                        .map_or(false, |arr| {
                            arr.iter().any(|v| v.as_str() == Some(variant))
                        })
                })
                .collect()
        } else {
            properties
        };

        Self::new(filtered_properties)
    }

    pub fn apply_overrides(
        mut self,
        overrides: Vec<NewImagePropertyValue>,
    ) -> Vec<PropertyValueConfig> {
        for value in overrides {
            if let Some(group) = self.key_to_group.get(&value.key) {
                if let Some(keys) = self.group_to_keys.get(group) {
                    for key in keys {
                        self.key_to_value.remove(key);
                    }
                }
            }

            self.key_to_value.insert(value.key.clone(), value);
        }

        self.key_to_value
            .into_values()
            .map(|new_value| {
                let key_group = self.key_to_group.get(&new_value.key).cloned();
                PropertyValueConfig {
                    key: new_value.key,
                    key_group,
                    value: new_value.value,
                    has_changed: new_value.has_changed,
                }
            })
            .collect()
    }
}
