#![cfg(target_os = "linux")]

use crate::{run_command, TproxyArgs, ETC_RESOLV_CONF_FILE};
use cidr::IpCidr;
use std::net::IpAddr;
use std::str::FromStr;

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

pub fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    let tun_name = &tproxy_args.tun_name;

    // sudo ip link set tun0 up
    let args = &["link", "set", tun_name, "up"];
    run_command("ip", args)?;

    for ip in tproxy_args.bypass_ips.iter() {
        bypass_ip(ip)?;
    }
    bypass_ip(&tproxy_args.proxy_addr.ip())?;

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

    // sudo sh -c "echo nameserver 10.0.0.1 > /etc/resolv.conf"
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open(ETC_RESOLV_CONF_FILE)?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver {}", tproxy_args.tun_gateway)?;

    Ok(())
}

pub fn tproxy_remove(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    // sudo ip route del bypass_ip
    for bypass_ip in tproxy_args.bypass_ips.iter() {
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

    // sudo systemctl restart systemd-resolved.service
    let args = &["restart", "systemd-resolved.service"];
    if let Err(_err) = run_command("systemctl", args) {
        #[cfg(feature = "log")]
        log::debug!("command \"systemctl {:?}\" error: {}", args, _err);
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
