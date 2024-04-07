#![cfg(target_os = "linux")]

use std::fs;
use std::fs::Permissions;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;

use cidr::IpCidr;

use crate::{run_command, TproxyArgs, TproxyState, ETC_RESOLV_CONF_FILE};

fn bytes_to_lines(bytes: Vec<u8>) -> std::io::Result<Vec<String>> {
    // Convert bytes to string
    let content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error converting bytes to string: {}", e),
            ));
        }
    };

    // Split string into lines
    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    Ok(lines)
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
    let tun_gateway = match tun_gateway {
        Some(gw) => gw,
        None => "198.18.0.1".parse().unwrap(),
    };
    let data = format!("nameserver {}\n", tun_gateway);
    nix::sys::stat::fchmod(fd.as_raw_fd(), nix::sys::stat::Mode::from_bits(0o444).unwrap())?;
    write_buffer_to_fd(fd, data.as_bytes())?;
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
            #[cfg(feature = "log")]
            log::warn!("failed to remount /etc/resolv.conf as readonly");
        }
    }
    drop(file);
    if mount1.is_err() {
        #[cfg(feature = "log")]
        log::warn!("failed to bind mount custom resolv.conf onto /etc/resolv.conf, resorting to direct write");

        restore.restore_resolvconf_content = Some(fs::read(ETC_RESOLV_CONF_FILE)?);

        let flags = nix::fcntl::OFlag::O_WRONLY | nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_TRUNC;
        let fd = nix::fcntl::open(ETC_RESOLV_CONF_FILE, flags, nix::sys::stat::Mode::from_bits(0o644).unwrap())?;
        let fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) };
        write_nameserver(fd.as_fd(), tun_gateway)?;
    }
    Ok(())
}

fn bypass_ip(ip: &IpAddr) -> std::io::Result<bool> {
    let is_ipv6 = ip.is_ipv6();
    let route_show_args = if is_ipv6 {
        ["-6", "route", "show"]
    } else {
        ["-4", "route", "show"]
    };

    let cidr = create_cidr(*ip, if is_ipv6 { 128 } else { 32 })?;

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
        let mut dst_str = split.next().unwrap();
        if dst_str == "default" {
            dst_str = if is_ipv6 { "::/0" } else { "0.0.0.0/0" }
        }

        let (addr_str, prefix_len_str) = match dst_str.split_once(['/']) {
            None => (dst_str, if is_ipv6 { "128" } else { "32" }),
            Some((addr_str, prefix_len_str)) => (addr_str, prefix_len_str),
        };

        let cidr: IpCidr = create_cidr(IpAddr::from_str(addr_str).unwrap(), u8::from_str(prefix_len_str).unwrap())?;
        let route_components: Vec<String> = split.map(String::from).collect();
        route_info.push((cidr, route_components))
    }

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
    };

    // sudo ip link set tun0 up
    let args = &["link", "set", tun_name, "up"];
    run_command("ip", args)?;

    for ip in tproxy_args.bypass_ips.iter() {
        bypass_ip(ip)?;
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        bypass_ip(&tproxy_args.proxy_addr.ip())?;
    }

    // sudo ip route add 128.0.0.0/1 dev tun0
    let args = &["route", "add", "128.0.0.0/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add 0.0.0.0/1 dev tun0
    let args = &["route", "add", "0.0.0.0/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add ::/1 dev tun0
    let args = &["route", "add", "::/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add 8000::/1 dev tun0
    let args = &["route", "add", "8000::/1", "dev", tun_name];
    run_command("ip", args)?;

    setup_resolv_conf(&mut state)?;

    crate::store_intermediate_state(&state)?;
    Ok(state)
}

impl Drop for TproxyState {
    fn drop(&mut self) {
        #[cfg(feature = "log")]
        log::debug!("restoring network settings");

        if let Err(_e) = _tproxy_remove(self) {
            #[cfg(feature = "log")]
            log::error!("failed to restore network settings: {}", _e);
        }
    }
}

pub fn tproxy_remove(state: Option<TproxyState>) -> std::io::Result<()> {
    let mut state = match state {
        Some(state) => state,
        None => crate::retrieve_intermediate_state()?,
    };
    _tproxy_remove(&mut state)
}

pub(crate) fn _tproxy_remove(state: &mut TproxyState) -> std::io::Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }
    state.tproxy_removed_done = true;
    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "tproxy_args is None");
    let tproxy_args = state.tproxy_args.as_ref().ok_or(err)?;
    // sudo ip route del bypass_ip
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["route", "del", &bypass_ip.to_string()];
        if let Err(_err) = run_command("ip", args) {
            #[cfg(feature = "log")]
            log::debug!("command \"ip route del {}\" error: {}", bypass_ip, _err);
        }
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let bypass_ip = tproxy_args.proxy_addr.ip();
        let args = &["route", "del", &bypass_ip.to_string()];
        if let Err(_err) = run_command("ip", args) {
            #[cfg(feature = "log")]
            log::debug!("command \"ip route del {}\" error: {}", bypass_ip, _err);
        }
    }

    // sudo ip link del tun0
    let args = &["link", "del", &tproxy_args.tun_name];
    if let Err(_err) = run_command("ip", args) {
        #[cfg(feature = "log")]
        log::debug!("command \"ip {:?}\" error: {}", args, _err);
    }

    if state.umount_resolvconf {
        nix::mount::umount(ETC_RESOLV_CONF_FILE)?;
    }

    if let Some(data) = &state.restore_resolvconf_content {
        fs::write(ETC_RESOLV_CONF_FILE, data)?;
    }

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
        let res = bypass_ip(&ip);
        println!("bypass_ip: {:?}", res);
    }
}
