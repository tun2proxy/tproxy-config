use regex::Regex;

pub fn is_private_ip(ip: std::net::IpAddr) -> bool {
    if let std::net::IpAddr::V4(addr) = ip {
        if ip_v4_is_private(&addr) {
            return true;
        }
    }

    let patterns = [
        r"^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
        r"^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$",
        r"^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$",
        r"^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
        r"^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$",
        r"^f[cd][0-9a-f]{2}:",
        r"^fe80:",
        r"^::1$",
        r"^::$",
    ];

    let ip = ip.to_string();

    for pattern in &patterns {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(&ip) {
            return true;
        }
    }

    false
}

fn is_benchmarking(addr: &std::net::Ipv4Addr) -> bool {
    addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
}

fn ip_v4_is_private(addr: &std::net::Ipv4Addr) -> bool {
    is_benchmarking(addr) || addr.is_private() || addr.is_loopback() || addr.is_link_local()
}

/*
// FIXME: use IpAddr::is_global() instead when it's stable
pub fn is_private_ip(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(addr) => ip_v4_is_private(&addr),
        std::net::IpAddr::V6(_) => false,
    }
}
// */
