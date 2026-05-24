use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use maxminddb::{geoip2, Reader};
use pxxl_common::GeoLocation;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct GeoIpResolver {
    records: Arc<Vec<GeoIpRecord>>,
    mmdb: Option<Arc<MmdbDatabases>>,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct GeoIpRecord {
    network: IpNet,
    location: GeoLocation,
}

#[derive(Debug)]
struct MmdbDatabases {
    city: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl Default for GeoIpResolver {
    fn default() -> Self {
        Self {
            records: Arc::new(builtin_records()),
            mmdb: None,
            enabled: true,
        }
    }
}

impl GeoIpResolver {
    pub fn disabled() -> Self {
        Self {
            records: Arc::new(Vec::new()),
            mmdb: None,
            enabled: false,
        }
    }

    pub fn load_from_path(enabled: bool, path: impl AsRef<Path>) -> Result<Self> {
        if !enabled {
            return Ok(Self::disabled());
        }

        let path = path.as_ref();
        let mut records = builtin_records();

        let mmdb = if path
            .extension()
            .is_some_and(|extension| extension == "mmdb")
        {
            Some(Arc::new(load_mmdb_databases(path)?))
        } else {
            None
        };

        if path.exists() && mmdb.is_none() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("reading GeoIP database {}", path.display()))?;
            records.extend(parse_database(&content)?);
            info!(
                path = %path.display(),
                records = records.len(),
                "loaded offline GeoIP database"
            );
        } else if !path.exists() {
            warn!(
                path = %path.display(),
                "GeoIP database not found; using built-in private/local ranges only"
            );
        }

        Ok(Self {
            records: Arc::new(records),
            mmdb,
            enabled: true,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoLocation {
        if !self.enabled {
            return GeoLocation::unknown();
        }

        if let Some(location) = self.lookup_mmdb(ip) {
            return location;
        }

        self.records
            .iter()
            .filter(|record| record.network.contains(&ip))
            .max_by_key(|record| record.network.prefix_len())
            .map(|record| record.location.clone())
            .unwrap_or_else(GeoLocation::unknown)
    }

    fn lookup_mmdb(&self, ip: IpAddr) -> Option<GeoLocation> {
        let mmdb = self.mmdb.as_ref()?;

        if let Some(reader) = &mmdb.city {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip) {
                let location = location_from_city(city, mmdb.asn.as_ref(), ip);
                if location.country_code.is_some()
                    || location.continent_code.is_some()
                    || location.city.is_some()
                {
                    return Some(location);
                }
            }
        }

        if let Some(reader) = &mmdb.country {
            if let Ok(country) = reader.lookup::<geoip2::Country>(ip) {
                let location = location_from_country(country, mmdb.asn.as_ref(), ip);
                if location.country_code.is_some() || location.continent_code.is_some() {
                    return Some(location);
                }
            }
        }

        None
    }
}

fn load_mmdb_databases(path: &Path) -> Result<MmdbDatabases> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let city_path = pick_existing(path, dir, &["GeoLite2-City.mmdb", "GeoIP2-City.mmdb"]);
    let country_path = pick_existing(path, dir, &["GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb"]);
    let asn_path = pick_existing(
        path,
        dir,
        &["GeoLite2-ASN.mmdb", "GeoIP2-ISP.mmdb", "GeoIP2-ASN.mmdb"],
    );

    let city = load_mmdb_reader(city_path.as_ref(), "city")?;
    let country = load_mmdb_reader(country_path.as_ref(), "country")?;
    let asn = load_mmdb_reader(asn_path.as_ref(), "asn")?;

    info!(
        path = %path.display(),
        city = city.is_some(),
        country = country.is_some(),
        asn = asn.is_some(),
        "loaded MaxMind GeoIP MMDB databases"
    );

    Ok(MmdbDatabases { city, country, asn })
}

fn pick_existing(path: &Path, dir: &Path, candidates: &[&str]) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }

    candidates
        .iter()
        .map(|candidate| dir.join(candidate))
        .find(|candidate| candidate.exists())
}

fn load_mmdb_reader(path: Option<&PathBuf>, label: &str) -> Result<Option<Reader<Vec<u8>>>> {
    let Some(path) = path else {
        return Ok(None);
    };

    Reader::open_readfile(path)
        .map(Some)
        .with_context(|| format!("opening {label} MMDB {}", path.display()))
}

fn location_from_city(
    city: geoip2::City<'_>,
    asn: Option<&Reader<Vec<u8>>>,
    ip: IpAddr,
) -> GeoLocation {
    let mut location = GeoLocation {
        country_code: city
            .country
            .as_ref()
            .and_then(|country| country.iso_code)
            .map(str::to_ascii_uppercase),
        country_name: city
            .country
            .as_ref()
            .and_then(|country| localized_name(country.names.as_ref())),
        continent_code: city
            .continent
            .as_ref()
            .and_then(|continent| continent.code)
            .map(str::to_ascii_uppercase),
        continent_name: city
            .continent
            .as_ref()
            .and_then(|continent| localized_name(continent.names.as_ref())),
        region: city.subdivisions.as_ref().and_then(|subdivisions| {
            subdivisions
                .first()
                .and_then(|subdivision| localized_name(subdivision.names.as_ref()))
        }),
        city: city
            .city
            .as_ref()
            .and_then(|city| localized_name(city.names.as_ref())),
        source: "mmdb_city".to_string(),
    };

    if let Some(asn_summary) = lookup_asn_summary(asn, ip) {
        location.source = format!("{}:{asn_summary}", location.source);
    }

    location
}

fn location_from_country(
    country: geoip2::Country<'_>,
    asn: Option<&Reader<Vec<u8>>>,
    ip: IpAddr,
) -> GeoLocation {
    let mut location = GeoLocation {
        country_code: country
            .country
            .as_ref()
            .and_then(|country| country.iso_code)
            .map(str::to_ascii_uppercase),
        country_name: country
            .country
            .as_ref()
            .and_then(|country| localized_name(country.names.as_ref())),
        continent_code: country
            .continent
            .as_ref()
            .and_then(|continent| continent.code)
            .map(str::to_ascii_uppercase),
        continent_name: country
            .continent
            .as_ref()
            .and_then(|continent| localized_name(continent.names.as_ref())),
        region: None,
        city: None,
        source: "mmdb_country".to_string(),
    };

    if let Some(asn_summary) = lookup_asn_summary(asn, ip) {
        location.source = format!("{}:{asn_summary}", location.source);
    }

    location
}

fn localized_name(names: Option<&BTreeMap<&str, &str>>) -> Option<String> {
    names.and_then(|names| {
        names
            .get("en")
            .or_else(|| names.values().next())
            .map(|name| (*name).to_string())
    })
}

fn lookup_asn_summary(reader: Option<&Reader<Vec<u8>>>, ip: IpAddr) -> Option<String> {
    let asn = reader?.lookup::<geoip2::Asn>(ip).ok()?;
    let number = asn.autonomous_system_number?;
    let organization = asn.autonomous_system_organization.unwrap_or("unknown");
    Some(format!("asn{number}:{organization}"))
}

fn parse_database(content: &str) -> Result<Vec<GeoIpRecord>> {
    let mut records = Vec::new();

    for (line_index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if line_index == 0
            && fields
                .first()
                .is_some_and(|field| field.eq_ignore_ascii_case("cidr"))
        {
            continue;
        }

        if fields.len() < 4 {
            anyhow::bail!(
                "GeoIP row {} needs at least cidr,country_code,country_name,continent_code",
                line_index + 1
            );
        }

        records.push(GeoIpRecord {
            network: fields[0]
                .parse::<IpNet>()
                .with_context(|| format!("invalid GeoIP CIDR on row {}", line_index + 1))?,
            location: GeoLocation {
                country_code: empty_to_none(fields.get(1).copied()).map(str::to_ascii_uppercase),
                country_name: empty_to_none(fields.get(2).copied()).map(str::to_string),
                continent_code: empty_to_none(fields.get(3).copied()).map(str::to_ascii_uppercase),
                continent_name: empty_to_none(fields.get(4).copied()).map(str::to_string),
                region: empty_to_none(fields.get(5).copied()).map(str::to_string),
                city: empty_to_none(fields.get(6).copied()).map(str::to_string),
                source: "offline".to_string(),
            },
        });
    }

    Ok(records)
}

fn empty_to_none(value: Option<&str>) -> Option<&str> {
    value.and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn builtin_records() -> Vec<GeoIpRecord> {
    vec![
        builtin_v4(Ipv4Addr::LOCALHOST, 8, "LO", "Local", "LOCAL", "Local"),
        builtin_v6(Ipv6Addr::LOCALHOST, 128, "LO", "Local", "LOCAL", "Local"),
        builtin_v4(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            "PR",
            "Private",
            "PRIVATE",
            "Private",
        ),
        builtin_v4(
            Ipv4Addr::new(172, 16, 0, 0),
            12,
            "PR",
            "Private",
            "PRIVATE",
            "Private",
        ),
        builtin_v4(
            Ipv4Addr::new(192, 168, 0, 0),
            16,
            "PR",
            "Private",
            "PRIVATE",
            "Private",
        ),
        builtin_v4(
            Ipv4Addr::new(100, 64, 0, 0),
            10,
            "PR",
            "Private",
            "PRIVATE",
            "Private",
        ),
        builtin_v6(
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
            7,
            "PR",
            "Private",
            "PRIVATE",
            "Private",
        ),
        builtin_v6(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            10,
            "PR",
            "Private",
            "PRIVATE",
            "Private",
        ),
    ]
}

fn builtin_v4(
    network: Ipv4Addr,
    prefix_len: u8,
    country_code: &str,
    country_name: &str,
    continent_code: &str,
    continent_name: &str,
) -> GeoIpRecord {
    GeoIpRecord {
        network: IpNet::V4(Ipv4Net::new(network, prefix_len).expect("valid built-in IPv4 CIDR")),
        location: builtin_location(country_code, country_name, continent_code, continent_name),
    }
}

fn builtin_v6(
    network: Ipv6Addr,
    prefix_len: u8,
    country_code: &str,
    country_name: &str,
    continent_code: &str,
    continent_name: &str,
) -> GeoIpRecord {
    GeoIpRecord {
        network: IpNet::V6(Ipv6Net::new(network, prefix_len).expect("valid built-in IPv6 CIDR")),
        location: builtin_location(country_code, country_name, continent_code, continent_name),
    }
}

fn builtin_location(
    country_code: &str,
    country_name: &str,
    continent_code: &str,
    continent_name: &str,
) -> GeoLocation {
    GeoLocation {
        country_code: Some(country_code.to_string()),
        country_name: Some(country_name.to_string()),
        continent_code: Some(continent_code.to_string()),
        continent_name: Some(continent_name.to_string()),
        region: None,
        city: None,
        source: "builtin".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_longest_matching_offline_record() {
        let records = parse_database(
            r#"cidr,country_code,country_name,continent_code,continent_name
203.0.113.0/24,US,United States,NA,North America
203.0.113.8/29,CA,Canada,NA,North America
"#,
        )
        .unwrap();
        let resolver = GeoIpResolver {
            records: Arc::new(records),
            mmdb: None,
            enabled: true,
        };

        let location = resolver.lookup("203.0.113.10".parse().unwrap());

        assert_eq!(location.country_code.as_deref(), Some("CA"));
    }

    #[test]
    fn uses_builtin_localhost_record() {
        let resolver = GeoIpResolver::default();

        let location = resolver.lookup("127.0.0.1".parse().unwrap());

        assert_eq!(location.country_code.as_deref(), Some("LO"));
        assert_eq!(location.source, "builtin");
    }
}
