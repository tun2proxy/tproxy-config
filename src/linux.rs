#![cfg(target_os = "linux")]

use std::fs;
use std::fs::Permissions;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;

use cidr::IpCidr;

use crate::{ETC_RESOLV_CONF_FILE, TproxyArgs, TproxyState, run_command};

fn bytes_to_string(bytes: Vec<u8>) -> std::io::Result<String> {
    match String::from_utf8(bytes) {
        Ok(content) => Ok(content),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("error converting bytes to string: {}", e),
        )),
    }
}

fn bytes_to_lines(bytes: Vec<u8>) -> std::io::Result<Vec<String>> {
    // Convert bytes to string
    let content = bytes_to_string(bytes)?;

    // Split string into lines
    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    Ok(lines)
}

fn route_exists(route: &str, ipv6: bool, table: &str) -> std::io::Result<bool> {
    let args = if ipv6 {
        ["-6", "route", "show", route, "table", table]
    } else {
        ["-4", "route", "show", route, "table", table]
    };
    Ok(!bytes_to_string(run_command("ip", &args)?)?.trim().is_empty())
}

fn create_cidr(addr: IpAddr, len: u8) -> std::io::Result<IpCidr> {
    match IpCidr::new(addr, len) {
        Ok(cidr) => Ok(cidr),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to convert {}/{} to CIDR", addr, len),
        )),
    }
}

fn write_buffer_to_fd(fd: std::os::fd::BorrowedFd<'_>, data: &[u8]) -> std::io::Result<()> {
    let mut written = 0;
    loop {
        if written >= data.len() {
            break;
        }
        written += nix::unistd::write(fd, &data[written..])?;
    }
    Ok(())
}

fn write_nameserver(fd: std::os::fd::BorrowedFd<'_>, tun_gateway: Option<IpAddr>) -> std::io::Result<()> {
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

fn ip_fowarding_enabled(ipv6: bool) -> std::io::Result<bool> {
    let path = ip_forwarding_file_path(ipv6);
    Ok(bytes_to_string(fs::read(path)?)?.trim() == "1")
}

fn configure_ip_forwarding(ipv6: bool, enable: bool) -> std::io::Result<()> {
    let path = ip_forwarding_file_path(ipv6);
    fs::write(path, if enable { "1\n" } else { "0\n" })?;
    Ok(())
}

fn setup_resolv_conf(restore: &mut TproxyState) -> std::io::Result<()> {
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

fn route_show(is_ipv6: bool) -> std::io::Result<Vec<(IpCidr, Vec<String>)>> {
    use std::io::{Error, ErrorKind::InvalidData};
    let route_show_args = if is_ipv6 {
        ["-6", "route", "show"]
    } else {
        ["-4", "route", "show"]
    };

    /*
    The resulting vector, route_info, contains tuples where each tuple consists of two elements:
    1. An IpCidr object representing the destination CIDR of the route.
    2. A vector of strings containing components of the route obtained from the output of the ip
       route show command (such as the gateway, interface, and other attributes associated with the
       route).
    */

    let routes = bytes_to_lines(run_command("ip", &route_show_args)?)?;

    let mut route_info = Vec::<(IpCidr, Vec<String>)>::new();
    for line in routes {
        if line.starts_with([' ', '\t']) {
            continue;
        }

        let mut split = line.split_whitespace();
        let mut dst_str = split
            .next()
            .ok_or(Error::new(InvalidData, format!("failed to parse route {}", line)))?;

        // NOTE: ignore routes like "multicast ff00::/8 dev eth1 metric 256"
        if dst_str == "multicast" {
            // dst_str = split.next()..ok_or(Error::new(InvalidData, format!("failed to parse route {}", line)))?;
            continue;
        }

        // if the first part of the route is "unreachable", we ignore it
        if dst_str == "unreachable" {
            continue;
        }

        if dst_str == "default" {
            dst_str = if is_ipv6 { "::/0" } else { "0.0.0.0/0" }
        }

        let (addr_str, prefix_len_str) = match dst_str.split_once(['/']) {
            None => (dst_str, if is_ipv6 { "128" } else { "32" }),
            Some((addr_str, prefix_len_str)) => (addr_str, prefix_len_str),
        };

        let addr = IpAddr::from_str(addr_str)
            .map_err(|err| Error::new(InvalidData, format!("failed to parse IP address \"{}\": {}", addr_str, err)))?;
        let len = u8::from_str(prefix_len_str)
            .map_err(|err| Error::new(InvalidData, format!("failed to parse prefix len \"{}\": {}", prefix_len_str, err)))?;
        let cidr: IpCidr = create_cidr(addr, len)?;
        let route_components: Vec<String> = split.map(String::from).collect();
        route_info.push((cidr, route_components));
    }
    Ok(route_info)
}

fn do_bypass_ip(ip: &IpCidr) -> std::io::Result<bool> {
    let mut route_info = route_show(ip.is_ipv6())?;

    let cidr = *ip;

    // Sort routes by prefix length, the most specific route comes first.
    route_info.sort_by(|entry1, entry2| entry2.0.network_length().cmp(&entry1.0.network_length()));

    for (route_cidr, route_components) in route_info {
        // If the route does not contain the target CIDR, it is not interesting for us.
        if !route_cidr.contains(&cidr.first_address()) || !route_cidr.contains(&cidr.last_address()) {
            continue;
        }

        // The IP address is routed through a more specific route than the default route.
        // In this case, there is nothing to do.
        if route_cidr.network_length() != 0 {
            break;
        }

        // There is a default route which the target CIDR is routed through.
        // Duplicate it for the CIDR as we will hijack the default route by two /1 routes later.
        let mut proxy_route = vec!["route".into(), "add".into()];
        proxy_route.push(cidr.to_string());
        proxy_route.extend(route_components.into_iter());
        run_command("ip", &proxy_route.iter().map(|s| s.as_str()).collect::<Vec<&str>>())?;
        return Ok(true);
    }
    Ok(false)
}

pub fn get_route_components(cidr: &IpCidr) -> std::io::Result<Option<Vec<String>>> {
    let routes = route_show(cidr.is_ipv6())?;
    let matching_route = routes.iter().find(|(search_cidr, _)| search_cidr == cidr);
    match matching_route {
        None => Ok(None),
        Some((_, components)) => {
            let mut vec = Vec::new();
            vec.push(cidr.to_string());
            vec.extend(components.clone());
            Ok(Some(vec))
        }
    }
}

pub fn restore_route(route_components: &[String]) -> std::io::Result<()> {
    let mut args = Vec::new();
    args.push("route");
    args.push("add");
    args.extend(route_components.iter().map(|x| x.as_str()));
    run_command("ip", args.as_slice())?;
    Ok(())
}

pub fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<TproxyState> {
    let tun_name = &tproxy_args.tun_name;

    let targs = Some(tproxy_args.clone());
    let mut state = TproxyState {
        tproxy_args: targs,
        original_dns_servers: None,
        gateway: None,
        gw_scope: None,
        umount_resolvconf: false,
        restore_resolvconf_content: None,
        tproxy_removed_done: false,
        restore_ipv4_route: None,
        restore_ipv6_route: None,
        restore_gateway_mode: None,
        restore_ip_forwarding: false,
        restore_socket_fwmark: None,
    };

    flush_dns_cache()?;

    // check for gateway mode
    if tproxy_args.gateway_mode {
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
        restore_gateway_mode.push(format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", tun_name));

        // sudo iptables -D FORWARD -o "tun_name" -j ACCEPT
        restore_gateway_mode.push(format!("-D FORWARD -o {} -j ACCEPT", tun_name));

        // sudo iptables -D FORWARD -i "tun_name" -m state --state RELATED,ESTABLISHED -j ACCEPT
        restore_gateway_mode.push(format!("-D FORWARD -i {} -m state --state RELATED,ESTABLISHED -j ACCEPT", tun_name));

        state.restore_gateway_mode = Some(restore_gateway_mode);
        log::debug!("restore gateway mode: {:?}", state.restore_gateway_mode);
    }

    // check for socket fwmark
    if let Some(fwmark) = tproxy_args.socket_fwmark {
        let mark = format!("{}", fwmark);
        let table = tproxy_args.socket_fwmark_table.as_str();

        // sudo ip rule add fwmark "mark" table "table"
        let args = &["rule", "add", "fwmark", mark.as_str(), "table", table];
        run_command("ip", args)?;

        // Flush the fwmark table. We just claim that table.
        let args = &["route", "flush", "table", table];
        let _ = run_command("ip", args);

        let default_route_components = get_route_components(&IpCidr::from_str("0.0.0.0/0").unwrap())?
            .ok_or_else(|| std::io::Error::other("failed to get default route components"))?;
        let mut args = vec!["route", "add", "table", table];
        args.extend(default_route_components.iter().map(|s| s.as_str()));
        run_command("ip", &args)?;
        log::debug!("fwmark default route: ip {}", args.join(" "));

        let mut restore_socket_fwmark = Vec::new();

        // sudo ip rule del fwmark "mark"
        restore_socket_fwmark.push(format!("rule del fwmark {}", mark));

        // sudo ip route flush table "table"
        restore_socket_fwmark.push(format!("route flush table {}", table));
        state.restore_socket_fwmark = Some(restore_socket_fwmark);

        log::debug!("restore socket fwmark: {:?}", state.restore_socket_fwmark);
    }

    // sudo ip link set tun0 up
    let args = &["link", "set", tun_name, "up"];
    run_command("ip", args)?;

    for ip in tproxy_args.bypass_ips.iter() {
        do_bypass_ip(ip)?;
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let cidr = IpCidr::new_host(tproxy_args.proxy_addr.ip());
        do_bypass_ip(&cidr)?;
    }

    if tproxy_args.ipv4_default_route {
        if !route_exists("0.0.0.0/0", false, "main")? {
            // sudo ip route add 0.0.0.0/0 dev tun0
            let args = &["route", "add", "0.0.0.0/0", "dev", tun_name];
            run_command("ip", args)?;
        } else {
            // sudo ip route add 128.0.0.0/1 dev tun0
            let args = &["route", "add", "128.0.0.0/1", "dev", tun_name];
            run_command("ip", args)?;

            // sudo ip route add 0.0.0.0/1 dev tun0
            let args = &["route", "add", "0.0.0.0/1", "dev", tun_name];
            run_command("ip", args)?;
        }
    } else {
        // If IPv4 is not enabled, we do not want IPv4 traffic to bypass the proxy if a route
        // already exists.
        state.restore_ipv4_route = get_route_components(&IpCidr::from_str("0.0.0.0/0").unwrap())?;

        log::debug!("restore ipv4 route: {:?}", state.restore_ipv4_route);

        if let Err(_err) = run_command("ip", &["route", "del", "0.0.0.0/0"]) {
            log::debug!("command \"ip route del 0.0.0.0/0\" error: {}", _err);
        }
    }

    if tproxy_args.ipv6_default_route {
        if !route_exists("::/0", true, "main")? {
            // sudo ip route add ::/0 dev tun0
            let args = &["route", "add", "::/0", "dev", tun_name];
            run_command("ip", args)?;
        } else {
            // sudo ip route add ::/1 dev tun0
            let args = &["route", "add", "::/1", "dev", tun_name];
            run_command("ip", args)?;

            // sudo ip route add 8000::/1 dev tun0
            let args = &["route", "add", "8000::/1", "dev", tun_name];
            run_command("ip", args)?;
        }
    } else {
        // If IPv6 is not enabled, we do not want IPv6 traffic to bypass the proxy if a route
        // already exists.
        state.restore_ipv6_route = get_route_components(&IpCidr::from_str("::/0").unwrap())?;

        log::debug!("restore ipv6 route: {:?}", state.restore_ipv6_route);

        if let Err(_err) = run_command("ip", &["route", "del", "::/0"]) {
            log::debug!("command \"ip route del ::/0\" error: {}", _err);
        }
    }

    setup_resolv_conf(&mut state)?;

    #[cfg(feature = "unsafe-state-file")]
    crate::store_intermediate_state(&state)?;
    Ok(state)
}

impl Drop for TproxyState {
    fn drop(&mut self) {
        log::debug!("restoring network settings");

        if let Err(_e) = _tproxy_remove(self) {
            let _pid = std::process::id();
            log::error!("Current process \"{}\" failed to restore network settings: {}", _pid, _e);
        }
    }
}

pub fn tproxy_remove(state: Option<TproxyState>) -> std::io::Result<()> {
    match state {
        Some(mut state) => _tproxy_remove(&mut state),
        None => {
            #[cfg(feature = "unsafe-state-file")]
            if let Ok(mut state) = crate::retrieve_intermediate_state() {
                _tproxy_remove(&mut state)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn _tproxy_remove(state: &mut TproxyState) -> std::io::Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }
    state.tproxy_removed_done = true;
    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "tproxy_args is None");
    let tproxy_args = state.tproxy_args.as_ref().ok_or(err)?;
    // sudo ip route del bypass_ip/24
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["route", "del", &bypass_ip.to_string()];
        if let Err(_err) = run_command("ip", args) {
            log::debug!("command \"ip route del {}\" error: {}", bypass_ip, _err);
        }
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let bypass_ip = IpCidr::new_host(tproxy_args.proxy_addr.ip());
        let args = &["route", "del", &bypass_ip.to_string()];
        if let Err(_err) = run_command("ip", args) {
            log::debug!("command \"ip route del {}\" error: {}", bypass_ip, _err);
        }
    }

    if let Some(components) = &state.restore_ipv4_route {
        log::debug!("restore route: {:?}", components);
        if let Err(_err) = restore_route(components.as_slice()) {
            log::debug!("restore_route error: {}", _err);
        }
    }

    if let Some(components) = &state.restore_ipv6_route {
        log::debug!("restore route: {:?}", components);
        if let Err(_err) = restore_route(components.as_slice()) {
            log::debug!("restore_route error: {}", _err);
        }
    }

    if let Some(gateway_restore) = &state.restore_gateway_mode {
        for restore in gateway_restore {
            log::debug!("restore gateway mode: iptables {}", restore);

            if let Err(_err) = run_command("iptables", &restore.split(' ').collect::<Vec<&str>>()) {
                log::debug!("command \"iptables {}\" error: {}", restore, _err);
            }
        }
    }

    if let Some(fwmark_restore) = &state.restore_socket_fwmark {
        for restore in fwmark_restore {
            log::debug!("restore fwmark: ip {}", restore);

            if let Err(_err) = run_command("ip", &restore.split(' ').collect::<Vec<&str>>()) {
                log::debug!("command \"ip {}\" error: {}", restore, _err);
            }
        }
    }

    if state.restore_ip_forwarding {
        log::debug!("restore ip forwarding");

        if let Err(_err) = configure_ip_forwarding(false, false) {
            log::debug!("error restoring IP forwarding: {}", _err);
        }
    }

    // sudo ip link del tun0
    let args = &["link", "del", &tproxy_args.tun_name];
    if let Err(_err) = run_command("ip", args) {
        log::debug!("command \"ip {:?}\" error: {}", args, _err);
    }

    if state.umount_resolvconf {
        nix::mount::umount(ETC_RESOLV_CONF_FILE)?;
    }

    if let Some(data) = &state.restore_resolvconf_content {
        fs::write(ETC_RESOLV_CONF_FILE, data)?;
    }

    flush_dns_cache()?;

    #[cfg(feature = "unsafe-state-file")]
    let _ = std::fs::remove_file(crate::get_state_file_path());

    Ok(())
}

pub(crate) fn flush_dns_cache() -> std::io::Result<()> {
    // do nothing in linux
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn get_default_gateway() -> std::io::Result<(IpAddr, String)> {
    // Command: sh -c "ip route | grep default | awk '{print $3}'"
    let cmd = "ip route | grep default | awk '{print $3}'";
    let out = run_command("sh", &["-c", cmd])?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let addr = IpAddr::from_str(stdout.trim()).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    let cmd = "ip route | grep default | awk '{print $5}'";
    let out = run_command("sh", &["-c", cmd])?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let iface = stdout.trim().to_string();

    Ok((addr, iface))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_gateway() {
        let (addr, iface) = get_default_gateway().unwrap();
        println!("addr: {:?}, iface: {}", addr, iface);
    }

    #[test]
    fn test_bypass_ip() {
        let ip = "123.45.67.89".parse().unwrap();
        let res = do_bypass_ip(&ip);
        println!("do_bypass_ip: {:?}", res);
    }

    #[test]
    fn test_route_components() {
        let components = get_route_components(&IpCidr::from_str("0.0.0.0/0").unwrap()).unwrap();
        println!("route_components: {:?}", components);
    }
}
