use ipnet::{IpNet, Ipv4Net, Ipv6Net};
// IpRTrieMap is still needed for the in-memory structure
use iptrie::IpRTrieMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

// --- Error Handling (remains the same) ---
#[derive(Error, Debug)]
pub enum IpToolError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV Parsing Error: {0}")]
    Csv(#[from] csv::Error),
    #[error("IP Address Parsing Error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("IP Network Parsing Error: {0}")]
    NetParse(#[from] ipnet::AddrParseError),
    #[error("Serialization/Deserialization Error: {0}")]
    Serde(#[from] Box<bincode::ErrorKind>),
    #[error("Invalid IP Address: {0}")]
    InvalidIp(String),
    #[error("Geoname ID not found for network: {0}")]
    GeonameNotFound(String),
    #[error("Missing geoname ID for network entry: {0}")]
    MissingGeonameId(String),
    #[error("Database file format error: {0}")]
    DbFormat(String),
    #[error("Missing Required CSV Field: {0}")]
    MissingField(String),
}
type Result<T, E = IpToolError> = std::result::Result<T, E>;

// --- IP Version Enum (remains the same) ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpVersion {
    Unknown,
    V4,
    V6,
}

// --- IP Address Utilities (remain the same) ---
pub fn is_valid_ip(address: &str) -> bool {
    IpAddr::from_str(address).is_ok()
}
pub fn get_ip_version(address: &str) -> IpVersion {
    match IpAddr::from_str(address) {
        Ok(ip) => match ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        },
        Err(_) => IpVersion::Unknown,
    }
}

// --- Data Structure for Serialization ---
// This struct holds the raw data vectors that CAN be serialized.
// Requires `ipnet/serde` feature in Cargo.toml
#[derive(Serialize, Deserialize, Debug, Default)]
struct IpCountryDataRaw {
    ipv4_data: Vec<(String, String)>,
    ipv6_data: Vec<(String, String)>,
}

// --- In-Memory Database Structure (for lookups) ---
// This struct holds the built trie, NOT serialized directly.

pub struct IpCountryDatabase {
    trie: IpRTrieMap<String>,
}

impl IpCountryDatabase {
    // Helper to create an empty database (used by load_db)
    fn new() -> Self {
        IpCountryDatabase {
            trie: IpRTrieMap::new(),
        }
    }
}

// --- CSV Loading Helpers (remain the same) ---

/// Extracts geoname_id and country_iso_code from the CSV file
/// and returns a map mapping geoname_id (u32) to country_iso_code (String).
fn load_geoname_country_map<P: AsRef<Path>>(csv_path: P) -> Result<HashMap<u32, String>> {
    let file = File::open(csv_path)?;
    let mut reader = csv::Reader::from_reader(BufReader::new(file));
    let mut mapping = HashMap::new();

    #[derive(Deserialize)]
    struct GeoRecord {
        geoname_id: String,
        country_iso_code: String,
        #[serde(default)]
        _other: String,
    }

    for result in reader.deserialize::<GeoRecord>() {
        let record = match result {
            Ok(rec) => rec,
            Err(e) => {
                eprintln!("Warning: Skipping row due to CSV deserialize error: {}", e);
                continue;
            }
        };

        let geoname_id_str = record.geoname_id.trim();
        let country_iso_code = record.country_iso_code.trim();

        if !geoname_id_str.is_empty() && !country_iso_code.is_empty() {
            match geoname_id_str.parse::<u32>() {
                Ok(gid) => {
                    mapping.insert(gid, country_iso_code.to_string());
                }
                Err(e) => eprintln!(
                    "Warning: Could not parse geoname_id '{}': {}",
                    geoname_id_str, e
                ),
            }
        }
    }
    Ok(mapping)
}

/// Extracts the network and registered_country_geoname_id columns from the CSV
/// and returns a map mapping network (IpNet) to Optional<geoname_id> (Option<u32>).
fn load_network_to_registered_country<P: AsRef<Path>>(
    csv_path: P,
) -> Result<HashMap<String, Option<u32>>> {
    let file = File::open(csv_path)?;
    let mut reader = csv::Reader::from_reader(BufReader::new(file));
    let mut mapping = HashMap::new();

    #[derive(Deserialize)]
    struct NetworkRecord {
        network: String,
        registered_country_geoname_id: String,
        #[serde(default)]
        _other: String,
    }

    for result in reader.deserialize::<NetworkRecord>() {
        let record = match result {
            Ok(rec) => rec,
            Err(e) => {
                eprintln!("Warning: Skipping row due to CSV deserialize error: {}", e);
                continue;
            }
        };

        let network_str = record.network.trim();
        let reg_id_str = record.registered_country_geoname_id.trim();

        if network_str.is_empty() {
            continue;
        }

        let network = match IpNet::from_str(network_str) {
            Ok(net) => net,
            Err(e) => {
                eprintln!(
                    "Warning: Could not parse network CIDR '{}': {}",
                    network_str, e
                );
                continue;
            }
        };

        let reg_id = if reg_id_str.is_empty() {
            None
        } else {
            match reg_id_str.parse::<u32>() {
                Ok(id) => Some(id),
                Err(e) => {
                    eprintln!(
                        "Warning: Could not parse registered_country_geoname_id '{}' for network {}: {}",
                        reg_id_str, network_str, e
                    );
                    None
                }
            }
        };
        mapping.insert(network_str.to_string(), reg_id);
    }
    Ok(mapping)
}

// --- Database Generation and Loading ---

/// Generates raw data vectors of IP networks to country ISO codes using MaxMind CSV datasets
/// and saves the raw data to a binary file.
pub fn gen_db_from_maxmind_csv<P: AsRef<Path>>(
    db_path: P,
    geo_csv: P,
    ipv4_csv: P,
    ipv6_csv: P,
) -> Result<()> {
    println!("Loading geoname map from: {:?}", geo_csv.as_ref());
    let geo_map = load_geoname_country_map(geo_csv)?;
    println!("Loaded {} geoname entries.", geo_map.len());

    println!("Loading IPv4 network map from: {:?}", ipv4_csv.as_ref());
    let ipv4_map = load_network_to_registered_country(ipv4_csv)?;
    println!("Loaded {} IPv4 network entries.", ipv4_map.len());

    println!("Loading IPv6 network map from: {:?}", ipv6_csv.as_ref());
    let ipv6_map = load_network_to_registered_country(ipv6_csv)?;
    println!("Loaded {} IPv6 network entries.", ipv6_map.len());

    // Create the structure to hold raw data for serialization
    let mut raw_data = IpCountryDataRaw::default();
    let mut v4_processed = 0;
    let mut v6_processed = 0;
    let mut skipped_no_geo = 0;

    // Process IPv4 into raw_data.ipv4_data
    for (network, reg_id_opt) in ipv4_map {
        if let Some(reg_id) = reg_id_opt {
            if let Some(country) = geo_map.get(&reg_id) {
                // Add to the vector instead of inserting into a trie
                raw_data.ipv4_data.push((network, country.clone()));
                v4_processed += 1;
            } else {
                eprintln!(
                    "Warning: Geoname ID {} found for IPv4 network {} but not in geoname map. Skipping entry.",
                    reg_id, network
                );
                skipped_no_geo += 1;
            }
        }
    }
    println!("Collected {} IPv4 networks for database.", v4_processed);

    // Process IPv6 into raw_data.ipv6_data
    for (network, reg_id_opt) in ipv6_map {
        if let Some(reg_id) = reg_id_opt {
            if let Some(country) = geo_map.get(&reg_id) {
                // Add to the vector instead of inserting into a trie
                raw_data.ipv6_data.push((network, country.clone()));
                v6_processed += 1;
            } else {
                eprintln!(
                    "Warning: Geoname ID {} found for IPv6 network {} but not in geoname map. Skipping entry.",
                    reg_id, network
                );
                skipped_no_geo += 1;
            }
        }
    }
    println!("Collected {} IPv6 networks for database.", v6_processed);

    if skipped_no_geo > 0 {
        println!(
            "Skipped {} total entries due to missing geoname ID in map.",
            skipped_no_geo
        );
    }

    println!("Serializing raw database data to: {:?}", db_path.as_ref());
    let file = File::create(db_path)?;
    let writer = BufWriter::new(file);
    // Serialize the IpCountryDataRaw struct
    bincode::serialize_into(writer, &raw_data)?;
    println!("Raw database data generation complete.");

    Ok(())
}

fn nat_from_str(s: &str) -> Result<IpNet> {
    IpNet::from_str(s).map_err(|e| IpToolError::NetParse(e))
}

/// Load the serialized raw IP-to-country data and build the in-memory IpRTrieMap database.
pub fn load_db<P: AsRef<Path>>(db_path: P) -> Result<IpCountryDatabase> {
    println!("Loading raw database data from: {:?}", db_path.as_ref());
    let file = File::open(db_path)?;
    let reader = BufReader::new(file);
    // Deserialize the raw data vectors
    let raw_data: IpCountryDataRaw = bincode::deserialize_from(reader)?;
    println!("Raw data loaded. Building in-memory trie...");

    // Create the actual in-memory database structure (with the trie)
    let mut db = IpCountryDatabase::new();

    // Build the trie from the loaded raw data
    let mut v4_inserted = 0;
    for (network, country) in raw_data.ipv4_data {
        let nat = nat_from_str(&network)?;
        db.trie.insert(nat, country); // Insert into the IpRTrieMap
        v4_inserted += 1;
    }
    println!("Inserted {} IPv4 entries into trie.", v4_inserted);

    let mut v6_inserted = 0;
    for (network, country) in raw_data.ipv6_data {
        let nat = nat_from_str(&network)?;
        db.trie.insert(nat, country); // Insert into the IpRTrieMap
        v6_inserted += 1;
    }
    println!("Inserted {} IPv6 entries into trie.", v6_inserted);

    println!("In-memory trie database built successfully.");
    Ok(db) // Return the database with the populated trie
}

// --- Database Lookup (remains the same) ---

/// Check if an IPv6 address is in known private/special ranges.
fn is_ipv6_private_or_special(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if ip.segments()[0] & 0xffc0 == 0xfe80 {
        return true;
    } // Link-local
    if ip.segments()[0] & 0xfe00 == 0xfc00 {
        return true;
    } // ULA
    if ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8 {
        return true;
    } // Documentation
    if ip.is_unspecified() {
        return true;
    }
    false
}

/// Lookup the country ISO code for a given IP address using the loaded in-memory database.
/// Returns the country code, "Private" for private/special ranges, or None if
/// the address is invalid or not found.
pub fn lookup_db(db: &IpCountryDatabase, ip_str: &str) -> Option<String> {
    let ip = match IpAddr::from_str(ip_str) {
        Ok(ip) => ip,
        Err(_) => return None,
    };

    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
            {
                return Some("Private".to_string());
            }
        }
        IpAddr::V6(ipv6) => {
            if is_ipv6_private_or_special(&ipv6) {
                return Some("Private".to_string());
            }
        }
    }

    let lookup_net = IpNet::from(ip);

    let (_matched_net, country_code) = db.trie.lookup(&lookup_net);

    Some(country_code.clone())

    //.map(|(_matched_net, country_code)| country_code.clone())
}

// --- Unit Tests (Optional but Recommended) ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_validation_and_version() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("not an ip"));
        assert!(!is_valid_ip("192.168.1.256"));

        assert_eq!(get_ip_version("192.168.1.1"), IpVersion::V4);
        assert_eq!(get_ip_version("2001:db8::1"), IpVersion::V6);
        assert_eq!(get_ip_version("invalid"), IpVersion::Unknown);

        std::env::set_current_dir(r"E:\tmp\GeoIP2-Country-CSV_20240308")
            .expect("Failed to change directory to E:\\test");

        gen_db_from_maxmind_csv(
            "test_db.bin",
            "GeoIP2-Country-Locations-en.csv",
            "GeoIP2-Country-Blocks-IPv4.csv",
            "GeoIP2-Country-Blocks-IPv6.csv",
        );

        let db = load_db("test_db.bin").expect("Failed to load test DB");

        let country = lookup_db(&db, "1.2.3.4").unwrap();
        println!("{:?}", country);

        let country = lookup_db(&db, "2a01:cb06:c200:3e51:103d:6143:42e0:3d48").unwrap();
        println!("{:?}", country);
    }

    // Add more tests for database generation, loading, and lookup
    // These might require creating dummy CSV files or mocking file access.
    // Example (needs setup with dummy files/data):
    /*
    #[test]
    fn test_lookup() {
        // 1. Create dummy CSV files
        // 2. Generate a test DB file using gen_db_from_maxmind_csv
        // 3. Load the test DB using load_db
        let db = load_db("test_db.bin").expect("Failed to load test DB");

        // 4. Perform lookups
        assert_eq!(lookup_db(&db, "8.8.8.8").unwrap(), Some("US".to_string())); // Example, depends on dummy data
        assert_eq!(lookup_db(&db, "192.168.1.1").unwrap(), Some("Private".to_string()));
        assert_eq!(lookup_db(&db, "10.0.0.1").unwrap(), Some("Private".to_string()));
        assert_eq!(lookup_db(&db, "::1").unwrap(), Some("Private".to_string())); // Loopback v6
        assert_eq!(lookup_db(&db, "fe80::1").unwrap(), Some("Private".to_string())); // Link-local v6
        assert_eq!(lookup_db(&db, "invalid-ip").is_err(), true); // Check for invalid input error
        assert_eq!(lookup_db(&db, "1.1.1.1").unwrap(), None); // Example IP not in dummy data
    }
    */
}
