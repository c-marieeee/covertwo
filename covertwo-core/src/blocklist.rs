use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Ip,
    Cidr,
    Domain, // stored but enforcement not yet wired; groundwork for future
}

impl std::fmt::Display for EntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryType::Ip => write!(f, "ip"),
            EntryType::Cidr => write!(f, "cidr"),
            EntryType::Domain => write!(f, "domain"),
        }
    }
}

impl FromStr for EntryType {
    type Err = BlocklistError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ip" => Ok(EntryType::Ip),
            "cidr" => Ok(EntryType::Cidr),
            "domain" => Ok(EntryType::Domain),
            other => Err(BlocklistError::InvalidEntryType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Malicious,
    Spam,
    Suspicious,
    Other,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Malicious => write!(f, "malicious"),
            Category::Spam => write!(f, "spam"),
            Category::Suspicious => write!(f, "suspicious"),
            Category::Other => write!(f, "other"),
        }
    }
}

impl FromStr for Category {
    type Err = BlocklistError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "malicious" => Ok(Category::Malicious),
            "spam" => Ok(Category::Spam),
            "suspicious" => Ok(Category::Suspicious),
            "other" => Ok(Category::Other),
            other => Err(BlocklistError::InvalidCategory(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    pub id: String,
    pub value: String,
    pub entry_type: EntryType,
    pub category: Category,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
    pub machine_id: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocklist {
    pub version: u32,
    pub updated_at: DateTime<Utc>,
    pub entries: Vec<BlocklistEntry>,
}

#[derive(Debug, Error)]
pub enum BlocklistError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    #[error("Invalid entry type: {0}")]
    InvalidEntryType(String),
    #[error("Invalid category: {0}")]
    InvalidCategory(String),
    #[error("Duplicate entry: {0}")]
    Duplicate(String),
    #[error("Entry not found: {0}")]
    NotFound(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            version: 1,
            updated_at: Utc::now(),
            entries: Vec::new(),
        }
    }

    pub fn from_json(data: &[u8]) -> Result<Self, BlocklistError> {
        Ok(serde_json::from_slice(data)?)
    }

    pub fn to_json_pretty(&self) -> Result<Vec<u8>, BlocklistError> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn add_entry(&mut self, entry: BlocklistEntry) -> Result<(), BlocklistError> {
        if self.entries.iter().any(|e| e.value == entry.value) {
            return Err(BlocklistError::Duplicate(entry.value));
        }
        validate_entry(&entry)?;
        self.entries.push(entry);
        self.updated_at = Utc::now();
        Ok(())
    }

    pub fn remove_entry(&mut self, value: &str) -> Result<BlocklistEntry, BlocklistError> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.value == value)
            .ok_or_else(|| BlocklistError::NotFound(value.to_string()))?;
        self.updated_at = Utc::now();
        Ok(self.entries.remove(pos))
    }

    pub fn find(&self, value: &str) -> Option<&BlocklistEntry> {
        self.entries.iter().find(|e| e.value == value)
    }

    /// Returns entries that pfctl can enforce (IP and CIDR only — not domains).
    pub fn enforceable_entries(&self) -> impl Iterator<Item = &BlocklistEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.entry_type, EntryType::Ip | EntryType::Cidr))
    }

    /// Format for pfctl: one value per line, no comments.
    pub fn to_pfctl_table(&self) -> String {
        self.enforceable_entries()
            .map(|e| e.value.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_entry(entry: &BlocklistEntry) -> Result<(), BlocklistError> {
    match entry.entry_type {
        EntryType::Ip => {
            IpAddr::from_str(&entry.value)
                .map_err(|_| BlocklistError::InvalidIp(entry.value.clone()))?;
        }
        EntryType::Cidr => {
            // Use ipnet for CIDR validation
            entry
                .value
                .parse::<ipnet::IpNet>()
                .map_err(|_| BlocklistError::InvalidCidr(entry.value.clone()))?;
        }
        EntryType::Domain => {
            let v = &entry.value;
            if v.is_empty() || v.len() > 253 || v.starts_with('.') || v.ends_with('.') {
                return Err(BlocklistError::InvalidDomain(v.clone()));
            }
            for label in v.split('.') {
                if label.is_empty() || label.len() > 63 {
                    return Err(BlocklistError::InvalidDomain(v.clone()));
                }
            }
        }
    }
    Ok(())
}
