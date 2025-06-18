#![cfg(target_os = "linux")]

use futures::stream::TryStreamExt;
use std::fs;
use std::fs::Permissions;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;

use rtnetlink::packet_route::route::RouteMessage;
use rtnetlink::{Handle, IpVersion, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder, new_connection};

use cidr::IpCidr;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

use crate::{ETC_RESOLV_CONF_FILE, TproxyArgs, TproxyStateInner, run_command};

static IPV6_DEFAULT_ROUTE: std::sync::LazyLock<IpCidr> = std::sync::LazyLock::new(|| IpCidr::from_str("::/0").unwrap());
static IPV6_SPACE_LOWER: std::sync::LazyLock<IpCidr> = std::sync::LazyLock::new(|| IpCidr::from_str("::/1").unwrap());
static IPV6_SPACE_UPPER: std::sync::LazyLock<IpCidr> = std::sync::LazyLock::new(|| IpCidr::from_str("8000::/1").unwrap());

static IPV4_DEFAULT_ROUTE: std::sync::LazyLock<IpCidr> = std::sync::LazyLock::new(|| IpCidr::from_str("0.0.0.0/0").unwrap());
static IPV4_SPACE_LOWER: std::sync::LazyLock<IpCidr> = std::sync::LazyLock::new(|| IpCidr::from_str("0.0.0.0/1").unwrap());
static IPV4_SPACE_UPPER: std::sync::LazyLock<IpCidr> = std::sync::LazyLock::new(|| IpCidr::from_str("128.0.0.0/1").unwrap());

static ROUTING_TABLE_MAIN: u32 = 254;

fn bytes_to_string(bytes: Vec<u8>) -> Result<String> {
    match String::from_utf8(bytes) {
        Ok(content) => Ok(content),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("error converting bytes to string: {e}")).into()),
    }
}

async fn netlink_do<F, T, R>(f: F) -> Result<R>
where
    F: Fn(Handle) -> T,
    T: Future<Output = Result<R>>,
{
    let f = async || {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        f(handle).await
    };
    f().await
}

async fn ip_route_add_msg(msg: &RouteMessage) -> Result<()> {
    netlink_do(async |handle| Ok(handle.route().add(msg.clone()).execute().await?)).await
}

async fn ip_route_add(dest: &IpCidr, dev: &str, table: u32) -> Result<RouteMessage> {
    netlink_do(async |handle| {
        let mut interfaces = handle.link().get().match_name(String::from(dev)).execute();
        let index = match interfaces.try_next().await? {
            Some(link) => link.header.index,
            None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Interface not found").into()),
        };

        let route = RouteMessageBuilder::<std::net::IpAddr>::new()
            .destination_prefix(dest.first_address(), dest.network_length())
            .unwrap()
            .table_id(table)
            .output_interface(index)
            .build();
        handle.route().add(route.clone()).execute().await?;
        Ok(route)
    })
    .await
}

async fn ip_route_flush(table: u32, ip_version: IpVersion) -> Result<()> {
    netlink_do(async |handle| {
        let route = match ip_version {
            IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new().table_id(table).build(),
            IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new().table_id(table).build(),
        };
        let mut routes = handle.route().get(route).execute();

        while let Some(route) = routes.try_next().await? {
            let msg = route.clone();
            handle.route().del(msg).execute().await?
        }

        Ok(())
    })
    .await
}

async fn ip_route_del_msg(msg: &RouteMessage) -> Result<()> {
    netlink_do(async |handle| Ok(handle.route().del(msg.clone()).execute().await?)).await
}

async fn ip_link_set_up(dev: &str) -> Result<()> {
    netlink_do(async |handle| {
        let msg = LinkMessageBuilder::<LinkUnspec>::default().name(String::from(dev)).up().build();
        Ok(handle.link().set(msg).execute().await?)
    })
    .await
}

async fn ip_link_del(dev: &str) -> Result<()> {
    netlink_do(async |handle| {
        let mut interfaces = handle.link().get().match_name(String::from(dev)).execute();
        let index = match interfaces.try_next().await? {
            Some(link) => link.header.index,
            None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Interface not found").into()),
        };
        Ok(handle.link().del(index).execute().await?)
    })
    .await
}

async fn ip_route_show(ip_version: IpVersion, table: u32) -> Result<Vec<RouteMessage>> {
    netlink_do(async |handle| {
        let route = match ip_version {
            IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new().table_id(table).build(),
            IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new().table_id(table).build(),
        };
        let mut routes = handle.route().get(route).execute();
        let mut route_messages = Vec::new();
        while let Some(route) = routes.try_next().await? {
            route_messages.push(route);
        }

        // Sort routes by prefix length, the most specific route comes first.
        route_messages.sort_by(|entry1: &RouteMessage, entry2: &RouteMessage| {
            // If the prefix lengths are equal, we compare the priority of the routes.

            let mut prio1 = 0;
            let mut prio2 = 0;

            for nla in &entry1.attributes {
                if let rtnetlink::packet_route::route::RouteAttribute::Priority(prio) = nla {
                    prio1 = *prio
                }
            }

            for nla in &entry1.attributes {
                if let rtnetlink::packet_route::route::RouteAttribute::Priority(prio) = nla {
                    prio2 = *prio
                }
            }

            let prio_cmp = prio1.cmp(&prio2);
            if prio_cmp != std::cmp::Ordering::Equal {
                return prio_cmp;
            }

            entry2
                .header
                .destination_prefix_length
                .cmp(&entry1.header.destination_prefix_length)
        });

        Ok(route_messages)
    })
    .await
}

async fn ip_rule_add(ip_version: IpVersion, fwmark: u32, table: u32) -> Result<()> {
    netlink_do(async |handle| {
        if ip_version == IpVersion::V6 {
            Ok(handle.rule().add().v6().fw_mark(fwmark).table_id(table).execute().await?)
        } else {
            Ok(handle.rule().add().v4().fw_mark(fwmark).table_id(table).execute().await?)
        }
    })
    .await
}

async fn ip_rule_del(ip_version: IpVersion, fwmark: u32) -> Result<()> {
    netlink_do(async |handle| {
        let mut rules = handle.rule().get(ip_version.clone()).execute();
        while let Some(rule) = rules.try_next().await? {
            if rule.attributes.iter().any(|nla| {
                if let rtnetlink::packet_route::rule::RuleAttribute::FwMark(mark) = nla {
                    *mark == fwmark
                } else {
                    false
                }
            }) {
                return Ok(handle.rule().del(rule).execute().await?);
            }
        }
        Ok(())
    })
    .await
}

fn route_msg_to_cidr(msg: &rtnetlink::packet_route::route::RouteMessage) -> Result<IpCidr> {
    let mut net_addr: Option<IpAddr> = match msg.header.address_family {
        rtnetlink::packet_route::AddressFamily::Inet => Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        rtnetlink::packet_route::AddressFamily::Inet6 => Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        _ => None,
    };
    let prefix_len = msg.header.destination_prefix_length;
    let attrs = &msg.attributes;
    for nla in attrs.iter() {
        if let rtnetlink::packet_route::route::RouteAttribute::Destination(addr) = nla {
            if let rtnetlink::packet_route::route::RouteAddress::Inet(ip) = addr {
                net_addr = Some(IpAddr::V4(*ip));
            } else if let rtnetlink::packet_route::route::RouteAddress::Inet6(ip) = addr {
                net_addr = Some(IpAddr::V6(*ip));
            }
        }
    }

    if let Some(addr) = net_addr {
        return create_cidr(addr, prefix_len);
    }

    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "failed to find destination in message attributes").into())
}

fn bool_to_ip_version(is_ipv6: bool) -> IpVersion {
    if is_ipv6 { IpVersion::V6 } else { IpVersion::V4 }
}

fn get_table_id(table_name: String) -> Result<u32> {
    if let Ok(table_id) = u32::from_str(table_name.as_str()) {
        return Ok(table_id);
    }

    for path in ["/etc/iproute2/rt_tables", "/usr/share/iproute2/rt_tables"] {
        let rt_tables = parse_rt_tables(String::from(path))?;
        if let Some(&id) = rt_tables.get(&table_name) {
            return Ok(id);
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("Routing table '{table_name}' not found")).into())
}

/// Parses the /etc/iproute2/rt_tables file and returns a map of table ID to name.
fn parse_rt_tables<P: AsRef<Path>>(path: P) -> Result<HashMap<String, u32>> {
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let mut table_map = HashMap::new();
    // Defaults cf. https://github.com/iproute2/iproute2/blob/d30f38d5d752abe12174b1ea05707bcf86f3d305/lib/rt_names.c#L508
    table_map.insert("default".to_string(), 253);
    table_map.insert("main".to_string(), 254);
    table_map.insert("local".to_string(), 255);

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            log::debug!("Warning: skipping malformed line: {line}");
            continue;
        }

        match parts[0].parse::<u32>() {
            Ok(id) => {
                table_map.insert(parts[1].to_string(), id);
            }
            Err(_) => {
                log::debug!("Warning: invalid table ID in line: {line}");
            }
        }
    }

    Ok(table_map)
}

async fn ip_route_get(route: &IpCidr, table: u32) -> Result<Option<RouteMessage>> {
    let ip_version = bool_to_ip_version(route.is_ipv6());
    let route_messages = ip_route_show(ip_version, table).await?;
    for msg in route_messages {
        let cidr = route_msg_to_cidr(&msg)?;
        if cidr == *route {
            return Ok(Some(msg));
        }
    }
    Ok(None)
}

async fn route_exists(route: &IpCidr, table: u32) -> Result<bool> {
    Ok(ip_route_get(route, table).await?.is_some())
}

fn create_cidr(addr: IpAddr, len: u8) -> Result<IpCidr> {
    match IpCidr::new(addr, len) {
        Ok(cidr) => Ok(cidr),
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("failed to convert {addr}/{len} to CIDR")).into()),
    }
}

fn write_buffer_to_fd(fd: std::os::fd::BorrowedFd<'_>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    loop {
        if written >= data.len() {
            break;
        }
        written += nix::unistd::write(fd, &data[written..])?;
    }
    Ok(())
}

fn write_nameserver(fd: std::os::fd::BorrowedFd<'_>, tun_gateway: Option<IpAddr>) -> Result<()> {
    let tun_gateway = tun_gateway.unwrap_or_else(|| "198.18.0.1".parse().unwrap());
    let data = format!("nameserver {}\n", tun_gateway);
    nix::sys::stat::fchmod(fd.as_fd(), nix::sys::stat::Mode::from_bits(0o444).unwrap())?;
    write_buffer_to_fd(fd, data.as_bytes())?;
    Ok(())
}

fn ip_forwarding_file_path(ipv6: bool) -> &'static str {
    if ipv6 {
        "/proc/sys/net/ipv6/conf/all/forwarding"
    } else {
        "/proc/sys/net/ipv4/ip_forward"
    }
}

fn ip_fowarding_enabled(ipv6: bool) -> Result<bool> {
    let path = ip_forwarding_file_path(ipv6);
    Ok(bytes_to_string(fs::read(path)?)?.trim() == "1")
}

fn configure_ip_forwarding(ipv6: bool, enable: bool) -> Result<()> {
    let path = ip_forwarding_file_path(ipv6);
    fs::write(path, if enable { "1\n" } else { "0\n" })?;
    Ok(())
}

fn setup_resolv_conf(restore: &mut TproxyStateInner) -> Result<()> {
    let tun_gateway = restore.tproxy_args.as_ref().map(|args| args.tun_gateway);
    // We use a mount here because software like NetworkManager is known to fiddle with the
    // resolv.conf file and restore it to its original state.
    // Example: https://stackoverflow.com/q/51784208
    // Using a readonly bind mount, we can pin our configuration without having the user update
    // the NetworkManager configuration.
    let file = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o644))
        .rand_bytes(32)
        .tempfile()?;
    write_nameserver(file.as_fd(), tun_gateway)?;
    let source = format!("/proc/self/fd/{}", file.as_raw_fd());
    let flags = nix::mount::MsFlags::MS_BIND;
    let mount1 = nix::mount::mount(source.as_str().into(), ETC_RESOLV_CONF_FILE, "".into(), flags, "".into());
    if mount1.is_ok() {
        restore.umount_resolvconf = true;
        let flags = nix::mount::MsFlags::MS_REMOUNT | nix::mount::MsFlags::MS_RDONLY | nix::mount::MsFlags::MS_BIND;
        if nix::mount::mount("".into(), ETC_RESOLV_CONF_FILE, "".into(), flags, "".into()).is_err() {
            log::warn!("failed to remount /etc/resolv.conf as readonly");
        }
    }
    drop(file);
    if mount1.is_err() {
        log::warn!("failed to bind mount custom resolv.conf onto /etc/resolv.conf, resorting to direct write");

        restore.restore_resolvconf_content = Some(fs::read(ETC_RESOLV_CONF_FILE)?);

        let flags = nix::fcntl::OFlag::O_WRONLY | nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_TRUNC;
        let fd = nix::fcntl::open(ETC_RESOLV_CONF_FILE, flags, nix::sys::stat::Mode::from_bits(0o644).unwrap())?;
        write_nameserver(fd.as_fd(), tun_gateway)?;
    }
    Ok(())
}

async fn do_bypass_ip(state: &mut TproxyStateInner, ip: &IpCidr) -> Result<bool> {
    let route_info = ip_route_show(bool_to_ip_version(ip.is_ipv6()), ROUTING_TABLE_MAIN).await?;

    let cidr = *ip;

    for route_message in route_info {
        let route_cidr = match route_msg_to_cidr(&route_message) {
            Ok(cidr) => cidr,
            Err(_) => {
                log::debug!("failed to convert route message to CIDR: {route_message:?}");
                continue;
            }
        };

        // If the route does not contain the target CIDR, it is not interesting for us.
        if !route_cidr.contains(&cidr.first_address()) || !route_cidr.contains(&cidr.last_address()) {
            continue;
        }

        // The IP address is routed through a more specific route than the default route.
        // In this case, there is nothing to do.
        if route_cidr.network_length() != 0 {
            break;
        }

        let mut new_route_message = route_message.clone();
        let dst_attr = rtnetlink::packet_route::route::RouteAttribute::Destination(match cidr.first_address() {
            IpAddr::V4(ip) => rtnetlink::packet_route::route::RouteAddress::Inet(ip),
            IpAddr::V6(ip) => rtnetlink::packet_route::route::RouteAddress::Inet6(ip),
        });
        new_route_message.header.destination_prefix_length = cidr.network_length();

        let mut dst_index = None;
        new_route_message.attributes.iter().enumerate().for_each(|(i, nla)| {
            if let rtnetlink::packet_route::route::RouteAttribute::Destination(_) = nla {
                dst_index = Some(i);
            }
        });

        if dst_index.is_none() {
            new_route_message.attributes.push(dst_attr);
        } else {
            new_route_message.attributes[dst_index.unwrap()] = dst_attr;
        }

        ip_route_add_msg(&new_route_message).await?;

        state.remove_routes.push(new_route_message);

        return Ok(true);
    }
    Ok(false)
}

fn setup_gateway_mode(state: &mut TproxyStateInner, tun_name: &String) -> Result<()> {
    // sudo iptables -t nat -A POSTROUTING -o "tun_name" -j MASQUERADE
    let args = &["-t", "nat", "-A", "POSTROUTING", "-o", tun_name.as_str(), "-j", "MASQUERADE"];
    run_command("iptables", args)?;

    // sudo iptables -A FORWARD -o "tun_name" -j ACCEPT
    let args = &["-A", "FORWARD", "-o", tun_name.as_str(), "-j", "ACCEPT"];
    run_command("iptables", args)?;

    // sudo iptables -A FORWARD -i "tun_name" -o "default_interface" -m state --state RELATED,ESTABLISHED -j ACCEPT
    let args = &[
        "-A",
        "FORWARD",
        "-i",
        tun_name.as_str(),
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ];
    run_command("iptables", args)?;

    if !ip_fowarding_enabled(false)? {
        log::debug!("IP forwarding not enabled");
        configure_ip_forwarding(false, true)?;

        state.restore_ip_forwarding = true;
    }

    let mut restore_gateway_mode = Vec::new();

    // sudo iptables -t nat -D POSTROUTING -o "tun_name" -j MASQUERADE
    restore_gateway_mode.push(format!("-t nat -D POSTROUTING -o {tun_name} -j MASQUERADE"));

    // sudo iptables -D FORWARD -o "tun_name" -j ACCEPT
    restore_gateway_mode.push(format!("-D FORWARD -o {tun_name} -j ACCEPT"));

    // sudo iptables -D FORWARD -i "tun_name" -m state --state RELATED,ESTABLISHED -j ACCEPT
    restore_gateway_mode.push(format!("-D FORWARD -i {tun_name} -m state --state RELATED,ESTABLISHED -j ACCEPT"));

    state.restore_gateway_mode = Some(restore_gateway_mode);
    log::debug!("restore gateway mode: {:?}", state.restore_gateway_mode);

    Ok(())
}

async fn setup_fwmark_table(state: &mut TproxyStateInner, tproxy_args: &TproxyArgs) -> Result<()> {
    let fwmark = tproxy_args.socket_fwmark.unwrap();

    let table = get_table_id(tproxy_args.socket_fwmark_table.clone())?;

    // sudo ip rule add fwmark "mark" table "table"
    ip_rule_add(IpVersion::V4, fwmark, table).await?;
    ip_rule_add(IpVersion::V6, fwmark, table).await?;

    // Flush the fwmark table. We just claim that table.
    ip_route_flush(table, IpVersion::V4).await?;
    ip_route_flush(table, IpVersion::V6).await?;

    let ipv4_routes = ip_route_show(IpVersion::V4, table).await?;
    let ipv6_routes = ip_route_show(IpVersion::V6, table).await?;

    for route in ipv4_routes.iter().chain(ipv6_routes.iter()) {
        let mut cloned_route = route.clone();

        cloned_route.header.table = 0;

        let mut tbl_index = None;
        cloned_route.attributes.iter().enumerate().for_each(|(i, nla)| {
            if let rtnetlink::packet_route::route::RouteAttribute::Table(_) = nla {
                tbl_index = Some(i);
            }
        });

        if let Some(tbl_index) = tbl_index {
            cloned_route.attributes[tbl_index] = rtnetlink::packet_route::route::RouteAttribute::Table(table);
        } else {
            cloned_route
                .attributes
                .push(rtnetlink::packet_route::route::RouteAttribute::Table(table));
        }

        ip_route_add_msg(route).await?;
    }

    state.restore_socket_fwmark = Vec::from([
        crate::FwmarkRestore {
            ip_version: IpVersion::V4,
            fwmark,
            table,
        },
        crate::FwmarkRestore {
            ip_version: IpVersion::V6,
            fwmark,
            table,
        },
    ]);
    log::debug!("restore socket fwmark: {:?}", state.restore_socket_fwmark);

    Ok(())
}

pub(crate) async fn _tproxy_setup(tproxy_args: &TproxyArgs) -> Result<TproxyStateInner> {
    let tun_name = &tproxy_args.tun_name;

    let mut state: TproxyStateInner = TproxyStateInner {
        tproxy_args: Some(tproxy_args.clone()),
        ..Default::default()
    };

    flush_dns_cache()?;

    // check for gateway mode
    if tproxy_args.gateway_mode {
        setup_gateway_mode(&mut state, tun_name)?;
    }

    // check for socket fwmark
    if tproxy_args.socket_fwmark.is_some() {
        setup_fwmark_table(&mut state, tproxy_args).await?;
    }

    // sudo ip link set tun0 up
    ip_link_set_up(tun_name).await?;

    for ip in tproxy_args.bypass_ips.iter() {
        do_bypass_ip(&mut state, ip).await?;
    }

    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let cidr = IpCidr::new_host(tproxy_args.proxy_addr.ip());
        do_bypass_ip(&mut state, &cidr).await?;
    }

    if tproxy_args.ipv4_default_route {
        if !route_exists(&IPV4_DEFAULT_ROUTE, ROUTING_TABLE_MAIN).await? {
            state
                .remove_routes
                .push(ip_route_add(&IPV4_DEFAULT_ROUTE, tun_name, ROUTING_TABLE_MAIN).await?);
        } else {
            state
                .remove_routes
                .push(ip_route_add(&IPV4_SPACE_LOWER, tun_name, ROUTING_TABLE_MAIN).await?);
            state
                .remove_routes
                .push(ip_route_add(&IPV4_SPACE_UPPER, tun_name, ROUTING_TABLE_MAIN).await?);
        }
    } else {
        // If IPv4 is not enabled, we do not want IPv4 traffic to bypass the proxy if a route
        // already exists.
        let default_route = ip_route_get(&IPV4_DEFAULT_ROUTE, ROUTING_TABLE_MAIN).await?;

        if let Some(msg) = default_route {
            ip_route_del_msg(&msg).await?;
            state.restore_routes.push(msg.clone());
        } else {
            log::debug!("no IPv4 default route found");
        }
    }

    if tproxy_args.ipv6_default_route {
        if !route_exists(&IPV6_DEFAULT_ROUTE, ROUTING_TABLE_MAIN).await? {
            state
                .remove_routes
                .push(ip_route_add(&IPV6_DEFAULT_ROUTE, tun_name, ROUTING_TABLE_MAIN).await?);
        } else {
            state
                .remove_routes
                .push(ip_route_add(&IPV6_SPACE_LOWER, tun_name, ROUTING_TABLE_MAIN).await?);
            state
                .remove_routes
                .push(ip_route_add(&IPV6_SPACE_UPPER, tun_name, ROUTING_TABLE_MAIN).await?);
        }
    } else {
        // If IPv6 is not enabled, we do not want IPv6 traffic to bypass the proxy if a route
        // already exists.
        let default_route = ip_route_get(&IPV6_DEFAULT_ROUTE, ROUTING_TABLE_MAIN).await?;

        if let Some(msg) = default_route {
            ip_route_del_msg(&msg).await?;
            state.restore_routes.push(msg.clone());
        } else {
            log::debug!("no IPv6 default route found");
        }
    }

    setup_resolv_conf(&mut state)?;

    Ok(state)
}

pub(crate) async fn _tproxy_remove(state: &mut TproxyStateInner) -> Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }

    state.tproxy_removed_done = true;
    let tproxy_args = state
        .tproxy_args
        .as_ref()
        .ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "tproxy_args is None"))?;

    for route in &state.restore_routes {
        log::debug!("restoring route: {:?}", route);
        if let Err(err) = ip_route_add_msg(route).await {
            log::debug!("ip route add {route:?} error: {err}");
        }
    }

    for route in &state.remove_routes {
        log::debug!("removing route: {:?}", route);
        if let Err(err) = ip_route_del_msg(route).await {
            log::debug!("ip route del {route:?} error: {err}");
        }
    }

    if let Some(gateway_restore) = &state.restore_gateway_mode {
        for restore in gateway_restore {
            log::debug!("restore gateway mode: iptables {restore}");

            if let Err(_err) = run_command("iptables", &restore.split(' ').collect::<Vec<&str>>()) {
                log::debug!("command \"iptables {restore}\" error: {_err}");
            }
        }
    }

    for entry in &state.restore_socket_fwmark {
        log::debug!(
            "restore socket fwmark: ip rule del {} table {} (v: {:?})",
            entry.fwmark,
            entry.table,
            entry.ip_version
        );

        if let Err(_err) = ip_rule_del(entry.ip_version.clone(), entry.fwmark).await {
            log::debug!("ip_rule_del error: {_err}");
        }

        if let Err(err) = ip_rule_del(entry.ip_version.clone(), entry.fwmark).await {
            log::debug!("ip rule del fwmark {} (v: {:?}) error: {err}", entry.fwmark, entry.ip_version);
        }
        if let Err(err) = ip_route_flush(entry.table, entry.ip_version.clone()).await {
            log::debug!("ip route flush table {} (v: {:?}) error: {err}", entry.table, entry.ip_version);
        }
    }

    if state.restore_ip_forwarding {
        log::debug!("restore ip forwarding");

        if let Err(_err) = configure_ip_forwarding(false, false) {
            log::debug!("error restoring IP forwarding: {_err}");
        }
    }

    log::debug!("deleting link: {}", tproxy_args.tun_name);
    // sudo ip link del tun0
    if let Err(err) = ip_link_del(&tproxy_args.tun_name).await {
        log::debug!("ip link del {} error: {err}", tproxy_args.tun_name);
    }

    if state.umount_resolvconf {
        log::debug!("unmounting {}", ETC_RESOLV_CONF_FILE);
        nix::mount::umount(ETC_RESOLV_CONF_FILE)?;
    }

    if let Some(data) = &state.restore_resolvconf_content {
        fs::write(ETC_RESOLV_CONF_FILE, data)?;
    }

    flush_dns_cache()?;

    Ok(())
}

pub(crate) fn flush_dns_cache() -> Result<()> {
    // do nothing in linux
    Ok(())
}
