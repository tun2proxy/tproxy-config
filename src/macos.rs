#![cfg(target_os = "macos")]

use crate::{is_private_ip, run_command, IntermediateState, TproxyArgs, ETC_RESOLV_CONF_FILE};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

pub fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    // 0. Save the original gateway and scope
    let (original_gateway_0, orig_gw_iface) = get_default_gateway()?;
    let original_gateway = original_gateway_0.to_string();
    let dns_servers = extract_system_dns_servers()?;

    let tun_ip = tproxy_args.tun_ip.to_string();
    let tun_netmask = tproxy_args.tun_netmask.to_string();
    let tun_gateway = tproxy_args.tun_gateway.to_string();
    let tun_dns = tproxy_args.tun_dns;

    // sudo sysctl -w net.inet.ip.forwarding=1
    run_command("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;

    // Set up the address and netmask and gateway of the interface
    // Command: `sudo ifconfig tun_name 10.0.0.33 10.0.0.1 netmask 255.255.255.0`
    let args = &[&tproxy_args.tun_name, &tun_ip, &tun_gateway, "netmask", &tun_netmask];
    run_command("ifconfig", args)?;

    configure_system_proxy(true, None, Some(tproxy_args.proxy_addr))?;
    if dns_servers.is_empty() || is_private_ip(dns_servers[0]) {
        configure_dns_servers(&[tun_dns])?;
    }

    // route delete default
    // route delete default -ifscope original_gw_scope
    // route add default tun_gateway
    // route add default original_gateway -ifscope original_gw_scope
    run_command("route", &["delete", "default"])?;
    run_command("route", &["delete", "default", "-ifscope", &orig_gw_iface])?;
    run_command("route", &["add", "default", &tun_gateway])?;
    run_command("route", &["add", "default", &original_gateway, "-ifscope", &orig_gw_iface])?;

    // Route the bypass ip to the original gateway
    // Command: `sudo route add bypass_ip/32 original_gateway`
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["add", &bypass_ip.to_string(), &original_gateway];
        run_command("route", args)?;
    }

    /*
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 2. Remove the default route
    // Command: `sudo route delete 0.0.0.0`
    let args = &["delete", &unspecified];
    run_command("route", args)?;

    // 3. Set the gateway `10.0.0.1` as the default route
    // Command: `sudo route add -net 0.0.0.0 10.0.0.1`
    let args = &["add", "-net", &unspecified, &tun_gateway];
    run_command("route", args)?;
    // */

    // 5. Set the DNS server to a reserved IP address
    // Command: `sudo sh -c "echo nameserver 10.0.0.1 > /etc/resolv.conf"`
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open(ETC_RESOLV_CONF_FILE)?;
    let mut writer = std::io::BufWriter::new(file);

    use std::io::Write;
    writeln!(writer, "nameserver {}\n", tun_gateway)?;

    let disk_record = IntermediateState {
        dns_servers: Some(dns_servers),
        gateway: Some(original_gateway_0),
        gw_scope: Some(orig_gw_iface),
    };
    crate::store_intermediate_state(&disk_record)?;

    Ok(())
}

pub fn tproxy_remove(_tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    let mut state = crate::retrieve_intermediate_state()?;

    let original_dns_servers = state.dns_servers.take().unwrap_or_default();

    let err = std::io::Error::new(std::io::ErrorKind::Other, "No original gateway found");
    let original_gateway = state.gateway.take().ok_or(err)?.to_string();
    let err = std::io::Error::new(std::io::ErrorKind::Other, "No original gateway scope found");
    let original_gw_scope = state.gw_scope.take().ok_or(err)?;

    if let Err(_err) = configure_system_proxy(false, None, None) {
        #[cfg(feature = "log")]
        log::debug!("configure_system_proxy error: {}", _err);
    }
    if !original_dns_servers.is_empty() {
        if let Err(_err) = configure_dns_servers(&original_dns_servers) {
            #[cfg(feature = "log")]
            log::debug!("configure_dns_servers error: {}", _err);
        }
    }

    // route delete default
    // route delete default -ifscope original_gw_scope
    // route add default original_gateway
    if let Err(_err) = run_command("route", &["delete", "default"]) {
        #[cfg(feature = "log")]
        log::debug!("command \"route delete default\" error: {}", _err);
    }
    if let Err(_err) = run_command("route", &["delete", "default", "-ifscope", &original_gw_scope]) {
        #[cfg(feature = "log")]
        log::debug!("command \"route delete default -ifscope {}\" error: {}", original_gw_scope, _err);
    }
    if let Err(_err) = run_command("route", &["add", "default", &original_gateway]) {
        #[cfg(feature = "log")]
        log::debug!("command \"route add default {}\" error: {}", original_gateway, _err);
    }

    /*
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 1. Remove current adapter's route
    // command: `sudo route delete 0.0.0.0`
    let args = &["delete", &unspecified];
    run_command("route", args)?;

    // 2. Add back the original gateway route
    // command: `sudo route add -net 0.0.0.0 original_gateway`
    let args = &["add", "-net", &unspecified, &original_gateway];
    run_command("route", args)?;
    // */

    // 3. Restore DNS server to the original gateway
    // command: `sudo sh -c "echo nameserver original_gateway > /etc/resolv.conf"`
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open(ETC_RESOLV_CONF_FILE)?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver {}\n", original_gateway)?;

    // remove the record file anyway
    let _ = std::fs::remove_file(crate::get_state_file_path());

    Ok(())
}

pub(crate) fn get_default_gateway() -> std::io::Result<(IpAddr, String)> {
    let script = r#"
    gateway=$(route -n get default | awk '/gateway:/{print $2}')
    interface=$(route -n get default | awk '/interface:/{print $2}')
    if [ -z "$gateway" ] || [ -z "$interface" ]; then
        exit 1
    fi
    echo "$gateway $interface"
    "#;
    let out = run_command("sh", &["-c", script])?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let v = stdout.split_whitespace().collect::<Vec<_>>();
    if v.len() != 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found"));
    }

    let addr = IpAddr::from_str(v[0]).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok((addr, v[1].to_string()))
}

pub(crate) fn configure_dns_servers(dns_servers: &[IpAddr]) -> std::io::Result<()> {
    if dns_servers.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "dns_servers is empty"));
    }
    let dns_servers = dns_servers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(" ");
    let script = format!(
        r#"
    dns_servers={}
    services=$(networksetup -listnetworkserviceorder | grep 'Hardware Port')
    while read line; do
        sname=$(echo $line | awk -F  "(, )|(: )|[)]" '{{print $2}}')
        sdev=$(echo $line | awk -F  "(, )|(: )|[)]" '{{print $4}}')
        if [ -n "$sdev" ]; then
            ifout="$(ifconfig $sdev 2>/dev/null)"
            echo "$ifout" | grep 'status: active' > /dev/null 2>&1
            rc="$?"
            if [ "$rc" -eq 0 ]; then
                currentservice="$sname"
                networksetup -setdnsservers "$currentservice" $dns_servers
            fi
        fi
    done <<< "$(echo "$services")"
    if [ -z "$currentservice" ]; then
        >&2 echo "Could not find current service"
        exit 1
    fi
    "#,
        dns_servers
    );

    let _r = run_command("sh", &["-c", &script])?;
    Ok(())
}

fn extract_system_dns_servers() -> std::io::Result<Vec<IpAddr>> {
    let mut buf = Vec::with_capacity(4096);
    let mut f = std::fs::File::open(ETC_RESOLV_CONF_FILE)?;
    use std::io::Read;
    f.read_to_end(&mut buf)?;
    let cfg = resolv_conf::Config::parse(&buf).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let mut dns_servers = Vec::new();
    for name_server in cfg.nameservers {
        dns_servers.push(name_server.into());
    }
    Ok(dns_servers)
}

fn configure_system_proxy(state: bool, http_proxy: Option<SocketAddr>, socks_proxy: Option<SocketAddr>) -> std::io::Result<()> {
    let state = if state { "on" } else { "off" };

    fn port_and_status(proxy_addr: Option<SocketAddr>) -> (String, String, &'static str) {
        match proxy_addr {
            Some(addr) => (addr.ip().to_string(), addr.port().to_string(), "on"),
            None => ("".to_string(), "".to_string(), "off"),
        }
    }
    let (http_addr, http_port, http_port_enabled) = port_and_status(http_proxy);
    let (socks_addr, socks_port, socks_port_enabled) = port_and_status(socks_proxy);

    let script = format!(
        r#"
    state={}
    http_addr={}
    http_port={}
    http_port_enabled={}
    socks_addr={}
    socks_port={}
    socks_port_enabled={}

    services=$(networksetup -listnetworkserviceorder | grep 'Hardware Port')

    while read line; do
        sname=$(echo $line | awk -F  "(, )|(: )|[)]" '{{print $2}}')
        sdev=$(echo $line | awk -F  "(, )|(: )|[)]" '{{print $4}}')
        if [ -n "$sdev" ]; then
            ifout="$(ifconfig $sdev 2>/dev/null)"
            echo "$ifout" | grep 'status: active' > /dev/null 2>&1
            rc="$?"
            if [ "$rc" -eq 0 ]; then
                currentservice="$sname"
                currentdevice="$sdev"
                currentmac=$(echo "$ifout" | awk '/ether/{{print $2}}')

                if [ "$state" = "on" ]; then
                    if [ "$http_port_enabled" = "on" ]; then
                        networksetup -setwebproxy "$currentservice" "$http_addr" $http_port
                        networksetup -setsecurewebproxy "$currentservice" "$http_addr" $http_port
                    fi
                    if [ "$socks_port_enabled" = "on" ]; then
                        networksetup -setsocksfirewallproxy "$currentservice" "$socks_addr" $socks_port
                    fi
                elif [ "$state" = "off" ]; then
                    networksetup -setwebproxystate "$currentservice" off
                    networksetup -setsecurewebproxystate "$currentservice" off
                    networksetup -setsocksfirewallproxystate "$currentservice" off
                else
                    echo "invalid argument"
                fi
            fi
        fi
    done <<< "$(echo "$services")"

    if [ -z "$currentservice" ]; then
        >&2 echo "Could not find current service"
        exit 1
    fi
    "#,
        state, http_addr, http_port, http_port_enabled, socks_addr, socks_port, socks_port_enabled
    );

    let _r = run_command("sh", &["-c", &script])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configure_dns_servers() {
        let v = extract_system_dns_servers().unwrap();
        println!("{:?}", v);

        // let servers = ["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        // configure_dns_servers(&servers).unwrap();

        let http_proxy = "127.0.0.1:1081".parse().unwrap();
        let socks_proxy = "127.0.0.1:1080".parse().unwrap();
        configure_system_proxy(true, Some(http_proxy), Some(socks_proxy)).unwrap();
        configure_system_proxy(false, None, None).unwrap();
    }
}
