use crate::grpc::api;
use crate::models::node::{NodeType, NodeVersion};

use displaydoc::Display;
use semver::Version;
use thiserror::Error;

use super::{BUNDLE_NAME, KERNEL_NAME};

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to parse NodeType: {0}
    ParseNodeType(crate::models::node::node_type::Error),
    /// Failed to parse semantic Version from NodeVersion: {0}
    ParseVersion(semver::Error),
    /// Key `{0}` is not splittable into at least 4 `/` separated parts.
    SplitKey(String),
    /// File name should end in `/{BUNDLE_NAME:?}` but is `{0}`.
    SuffixBundle(String),
    /// File name should end in `/{KERNEL_NAME:?}` but is `{0}`.
    SuffixKernel(String),
}

/// A Cookbook plugin identifier.
#[derive(Clone, Debug)]
pub struct Identifier {
    pub protocol: String,
    pub node_type: NodeType,
    pub node_version: Version,
}

impl Identifier {
    pub fn new<S: Into<String>>(
        protocol: S,
        node_type: NodeType,
        node_version: &str,
    ) -> Result<Self, Error> {
        Ok(Identifier {
            protocol: protocol.into(),
            node_type,
            node_version: Version::parse(node_version).map_err(Error::ParseVersion)?,
        })
    }

    pub fn node_version(&self) -> NodeVersion {
        self.node_version.to_string().into()
    }
}

impl TryFrom<api::ConfigIdentifier> for Identifier {
    type Error = Error;

    fn try_from(api: api::ConfigIdentifier) -> Result<Self, Self::Error> {
        let node_type = api.node_type().into_model();

        Ok(Identifier {
            protocol: api.protocol,
            node_type,
            node_version: Version::parse(&api.node_version).map_err(Error::ParseVersion)?,
        })
    }
}

impl From<Identifier> for api::ConfigIdentifier {
    fn from(id: Identifier) -> Self {
        api::ConfigIdentifier {
            protocol: id.protocol,
            node_type: api::NodeType::from_model(id.node_type) as i32,
            node_version: id.node_version.to_string(),
        }
    }
}

impl api::ConfigIdentifier {
    /// Parse a `ConfigIdentifier` from a file path.
    ///
    /// The key format looks like:
    /// `/prefix/ethereum/validator/0.0.3/babel.rhai`.
    pub fn from_key<K: AsRef<str>>(key: K) -> Result<Self, Error> {
        let parts: Vec<_> = key.as_ref().split('/').collect();

        let [_prefix, protocol, node_type, node_version, ..] = &parts[..] else {
            return Err(Error::SplitKey(key.as_ref().into()));
        };

        let node_type = node_type
            .parse()
            .map(api::NodeType::from_model)
            .map_err(Error::ParseNodeType)?;

        Ok(api::ConfigIdentifier {
            protocol: protocol.to_string(),
            node_type: node_type as i32,
            node_version: node_version.to_string(),
        })
    }
}

impl api::BundleIdentifier {
    /// Extract the bundle version from a key.
    ///
    /// The key format looks like:
    /// `.../0.1.0/bvd-bundle.tgz`
    pub fn from_key<K: AsRef<str>>(key: K) -> Result<Self, Error> {
        let version = key
            .as_ref()
            .strip_suffix(&format!("/{BUNDLE_NAME}"))
            .ok_or_else(|| Error::SuffixBundle(key.as_ref().into()))?;

        let _ = Version::parse(version).map_err(Error::ParseVersion)?;

        Ok(api::BundleIdentifier {
            version: version.to_owned(),
        })
    }
}

impl api::KernelIdentifier {
    /// Extract the kernel version from a key.
    ///
    /// The key format looks like:
    /// `.../5.10.174-build.1+fc.ufw/kernel.gz`
    pub fn from_key<K: AsRef<str>>(key: K) -> Result<Self, Error> {
        let version = key
            .as_ref()
            .strip_suffix(&format!("/{KERNEL_NAME}"))
            .ok_or_else(|| Error::SuffixKernel(key.as_ref().into()))?;

        Ok(api::KernelIdentifier {
            version: version.to_owned(),
        })
    }
}
