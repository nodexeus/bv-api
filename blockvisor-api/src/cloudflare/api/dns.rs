use std::any::type_name;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::DateTime;
use chrono::offset::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{Endpoint, OrderDirection, SearchMatch};

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Extra Cloudflare-specific information about the record
    pub meta: Meta,
    /// Whether this record can be modified/deleted (true means it's managed by Cloudflare)
    pub locked: Option<bool>,
    /// DNS record name
    pub name: String,
    /// Time to live for DNS record. Value of 1 is 'automatic'
    pub ttl: u32,
    /// Zone identifier tag
    pub zone_id: Option<String>,
    /// When the record was last modified
    pub modified_on: DateTime<Utc>,
    /// When the record was created
    pub created_on: DateTime<Utc>,
    /// Whether this record can be modified/deleted (true means it's managed by Cloudflare)
    pub proxiable: bool,
    /// Type of the DNS record that also holds the record value
    #[serde(flatten)]
    pub content: DnsContent,
    /// DNS record identifier tag
    pub id: String,
    /// Whether the record is receiving the performance and security benefits of Cloudflare
    pub proxied: bool,
    /// The domain of the record
    pub zone_name: Option<String>,
}

/// Extra Cloudflare-specific information about the record
#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    /// Will exist if Cloudflare automatically added this DNS record during initial setup.
    pub auto_added: Option<bool>,
}

/// Type of the DNS record, along with the associated value.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
pub enum DnsContent {
    A { content: Ipv4Addr },
    AAAA { content: Ipv6Addr },
    CNAME { content: String },
    NS { content: String },
    MX { content: String, priority: u16 },
    TXT { content: String },
    SRV { content: String },
}

/// Create DNS Record
/// <https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record>
#[derive(Debug)]
pub struct CreateDnsRecord<'a> {
    pub zone_identifier: &'a str,
    pub params: CreateDnsRecordParams<'a>,
}

impl Endpoint for CreateDnsRecord<'_> {
    type Result = DnsRecord;

    fn method(&self) -> Method {
        Method::POST
    }

    fn path(&self) -> String {
        format!("zones/{}/dns_records", self.zone_identifier)
    }

    fn body(&self) -> Option<String> {
        serde_json::to_string(&self.params)
            .map_err(|err| warn!("Failed to serialize {}: {}", type_name::<Self>(), err))
            .ok()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde_with::skip_serializing_none]
pub struct CreateDnsRecordParams<'a> {
    /// Time to live for DNS record. Value of 1 is 'automatic'
    pub ttl: Option<u32>,
    /// Used with some records like MX and SRV to determine priority.
    /// If you do not supply a priority for an MX record, a default value of 0 will be set
    pub priority: Option<u16>,
    /// Whether the record is receiving the performance and security benefits of Cloudflare
    pub proxied: Option<bool>,
    /// DNS record name
    pub name: &'a str,
    /// Type of the DNS record that also holds the record value
    #[serde(flatten)]
    pub content: DnsContent,
}

/// List DNS Records
/// <https://api.cloudflare.com/#dns-records-for-a-zone-list-dns-records>
#[derive(Debug)]
pub struct ListDnsRecords<'a> {
    pub zone_identifier: &'a str,
    pub params: ListDnsRecordsParams,
}

impl Endpoint for ListDnsRecords<'_> {
    type Result = Vec<DnsRecord>;

    fn method(&self) -> Method {
        Method::GET
    }

    fn path(&self) -> String {
        format!("zones/{}/dns_records", self.zone_identifier)
    }

    fn query(&self) -> Option<String> {
        serde_urlencoded::to_string(&self.params)
            .map_err(|err| warn!("Failed to serialize {}: {}", type_name::<Self>(), err))
            .ok()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde_with::skip_serializing_none]
pub struct ListDnsRecordsParams {
    #[serde(flatten)]
    pub record_type: Option<DnsContent>,
    pub name: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub order: Option<ListDnsRecordsOrder>,
    pub direction: Option<OrderDirection>,
    #[serde(rename = "match")]
    pub search_match: Option<SearchMatch>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListDnsRecordsOrder {
    Type,
    Name,
    Content,
    Ttl,
    Proxied,
}

/// Update DNS Record
/// <https://api.cloudflare.com/#dns-records-for-a-zone-update-dns-record>
#[derive(Debug)]
pub struct UpdateDnsRecord<'a> {
    pub zone_identifier: &'a str,
    pub identifier: &'a str,
    pub params: UpdateDnsRecordParams<'a>,
}

impl Endpoint for UpdateDnsRecord<'_> {
    type Result = DnsRecord;

    fn method(&self) -> Method {
        Method::PUT
    }

    fn path(&self) -> String {
        format!(
            "zones/{}/dns_records/{}",
            self.zone_identifier, self.identifier
        )
    }

    fn body(&self) -> Option<String> {
        serde_json::to_string(&self.params)
            .map_err(|err| warn!("Failed to serialize {}: {}", type_name::<Self>(), err))
            .ok()
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Clone, Debug)]
pub struct UpdateDnsRecordParams<'a> {
    /// Time to live for DNS record. Value of 1 is 'automatic'
    pub ttl: Option<u32>,
    /// Whether the record is receiving the performance and security benefits of Cloudflare
    pub proxied: Option<bool>,
    /// DNS record name
    pub name: &'a str,
    /// Type of the DNS record that also holds the record value
    #[serde(flatten)]
    pub content: DnsContent,
}

/// Delete DNS Record
/// <https://api.cloudflare.com/#dns-records-for-a-zone-delete-dns-record>
#[derive(Debug)]
pub struct DeleteDnsRecord<'a> {
    pub zone_identifier: &'a str,
    pub identifier: &'a str,
}

impl Endpoint for DeleteDnsRecord<'_> {
    type Result = DeleteDnsRecordResponse;

    fn method(&self) -> Method {
        Method::DELETE
    }

    fn path(&self) -> String {
        format!(
            "zones/{}/dns_records/{}",
            self.zone_identifier, self.identifier
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteDnsRecordResponse {
    /// DNS record identifier tag
    pub id: String,
}
