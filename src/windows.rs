#![cfg(target_os = "windows")]

use windows_sys::{
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, NO_ERROR, WIN32_ERROR},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
                DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IF_TYPE_ETHERNET_CSMACD,
                IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::{IfOperStatusUp, NET_LUID_LH},
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
    },
    core::GUID,
};

use crate::{TproxyArgs, TproxyState, run_command};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<TproxyState> {
    log::trace!("Setting up transparent proxy...");

    flush_dns_cache()?;

    log::trace!("Route all traffic to the gateway of adapter \"{}\"...", tproxy_args.tun_name);
    // Route all traffic to the adapter, here the destination is adapter's gateway
    // command: `route add 0.0.0.0 mask 0.0.0.0 10.1.0.1 metric 6`
    let unspecified = if tproxy_args.tun_gateway.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.to_string()
    } else {
        std::net::Ipv6Addr::UNSPECIFIED.to_string()
    };
    let gateway = tproxy_args.tun_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &gateway, "metric", "6"];
    run_command("route", args)?;

    log::trace!("Get default gateway...");
    let original_gateway = get_default_gateway_ip()?;

    log::trace!("Setting bypass IPs...");
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        do_bypass_ip(*bypass_ip, original_gateway)?;
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let cidr = cidr::IpCidr::new_host(tproxy_args.proxy_addr.ip());
        do_bypass_ip(cidr, original_gateway)?;
    }

    log::trace!("Setting \"{}\"'s DNS to {}...", tproxy_args.tun_name, tproxy_args.tun_gateway);
    set_dns_server(&tproxy_args.tun_name, tproxy_args.tun_gateway)?;

    log::trace!("Transparent proxy setup done");

    let state = TproxyState {
        tproxy_args: Some(tproxy_args.clone()),
        original_dns_servers: None,
        gateway: Some(original_gateway),
        gw_scope: None,
        umount_resolvconf: false,
        restore_resolvconf_content: None,
        tproxy_removed_done: false,
    };
    #[cfg(feature = "unsafe-state-file")]
    crate::store_intermediate_state(&state)?;

    Ok(state)
}

fn do_bypass_ip(bypass_ip: cidr::IpCidr, original_gateway: IpAddr) -> std::io::Result<()> {
    // route the bypass ip to the original gateway
    // command: `route add bypass_ip/24 original_gateway metric 1`
    let args = &["add", &bypass_ip.to_string(), &original_gateway.to_string(), "metric", "1"];
    run_command("route", args)?;
    Ok(())
}

impl Drop for TproxyState {
    fn drop(&mut self) {
        log::debug!("restoring network settings");
        if let Err(_e) = _tproxy_remove(self) {
            log::error!("failed to restore network settings: {}", _e);
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

fn _tproxy_remove(state: &mut TproxyState) -> std::io::Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }
    state.tproxy_removed_done = true;
    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "tproxy_args is None");
    let tproxy_args = state.tproxy_args.as_ref().ok_or(err)?;

    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    let original_gateway = state.gateway.take().ok_or(err)?;
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 0. delete persistent route
    // command: `route -p delete 0.0.0.0 mask 0.0.0.0 10.0.0.1`
    let gateway = tproxy_args.tun_gateway.to_string();
    let args = &["-p", "delete", &unspecified, "mask", &unspecified, &gateway];
    if let Err(_err) = run_command("route", args) {
        log::debug!("command \"route {:?}\" error: {}", args, _err);
    }

    // Remove bypass ips
    // command: `route delete bypass_ip`
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["delete", &bypass_ip.to_string()];
        if let Err(_err) = run_command("route", args) {
            log::debug!("command \"route {:?}\" error: {}", args, _err);
        }
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let bypass_ip = cidr::IpCidr::new_host(tproxy_args.proxy_addr.ip());
        let args = &["delete", &bypass_ip.to_string()];
        if let Err(_err) = run_command("route", args) {
            log::debug!("command \"route {:?}\" error: {}", args, _err);
        }
    }

    // 1. Remove current adapter's route
    // command: `route delete 0.0.0.0 mask 0.0.0.0`
    let args = &["delete", &unspecified, "mask", &unspecified];
    if let Err(_err) = run_command("route", args) {
        log::debug!("command \"route {:?}\" error: {}", args, _err);
    }

    // 2. Add back the original gateway route
    // command: `route add 0.0.0.0 mask 0.0.0.0 original_gateway metric 200`
    let original_gateway = original_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &original_gateway, "metric", "200"];
    if let Err(_err) = run_command("route", args) {
        log::debug!("command \"route {:?}\" error: {}", args, _err);
    }

    // remove the record file anyway
    #[cfg(feature = "unsafe-state-file")]
    let _ = std::fs::remove_file(crate::get_state_file_path());

    flush_dns_cache()?;

    Ok(())
}

// NETIOAPI_API SetInterfaceDnsSettings(GUID Interface, const DNS_INTERFACE_SETTINGS *Settings);
crate::define_fn_dynamic_load!(
    SetInterfaceDnsSettingsDeclare,
    unsafe extern "system" fn(interface: GUID, settings: *const DNS_INTERFACE_SETTINGS) -> WIN32_ERROR,
    SET_INTERFACE_DNS_SETTINGS,
    SetInterfaceDnsSettings,
    "iphlpapi.dll",
    "SetInterfaceDnsSettings"
);

pub(crate) fn set_dns_server(iface: &str, dns_server: IpAddr) -> std::io::Result<()> {
    let Some(set_dns_fn) = SetInterfaceDnsSettings() else {
        // command: `netsh interface ip set dns "utun3" static 10.0.0.1`
        // or command: `powershell Set-DnsClientServerAddress -InterfaceAlias "utun3" -ServerAddresses ("10.0.0.1")`
        let tun_name = format!("\"{}\"", iface);
        let args = &["interface", "ip", "set", "dns", &tun_name, "static", &dns_server.to_string()];
        run_command("netsh", args)?;
        return Ok(());
    };
    let svr: Vec<u16> = dns_server.to_string().encode_utf16().chain(std::iter::once(0)).collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as _,
        NameServer: svr.as_ptr() as _,
        Domain: std::ptr::null_mut(),
        SearchList: std::ptr::null_mut(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: std::ptr::null_mut(),
    };

    let luid = alias_to_luid(iface)?;
    let guid = luid_to_guid(&luid)?;
    let ret = unsafe { set_dns_fn(guid, &settings) };
    if ret != NO_ERROR {
        let err = std::io::Error::from_raw_os_error(ret as _);
        return Err(err);
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn get_default_gateway() -> std::io::Result<(IpAddr, String)> {
    let addr = get_default_gateway_ip()?;
    let iface = get_default_gateway_interface()?;
    Ok((addr, iface))
}

pub(crate) fn get_default_gateway_ip() -> std::io::Result<IpAddr> {
    match get_active_network_interface_gateways().map(|gateways| gateways[0]) {
        Ok(gateway) => Ok(gateway),
        Err(e) => {
            log::debug!("Failed to get default gateway by GetAdaptersAddresses: {}", e);
            get_default_gateway_ip_by_cmd()
        }
    }
}

pub(crate) fn get_default_gateway_ip_by_cmd() -> std::io::Result<IpAddr> {
    let cmd = "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | ForEach-Object { $_.DefaultIPGateway }";
    let gateways = match run_command("powershell", &["-Command", cmd]) {
        Ok(gateways) => gateways,
        Err(e) => {
            let str = format!("Command \"powershell -Command {}\" error: {}", cmd, e);
            let err = std::io::Error::new(std::io::ErrorKind::Other, str);
            return Err(err);
        }
    };

    let stdout = String::from_utf8_lossy(&gateways).into_owned();
    let lines: Vec<&str> = stdout.lines().collect();

    let mut ipv4_gateway = None;
    let mut ipv6_gateway = None;

    for line in lines {
        if let Ok(ip) = <IpAddr as std::str::FromStr>::from_str(line) {
            match ip {
                IpAddr::V4(_) => {
                    ipv4_gateway = Some(ip);
                    break;
                }
                IpAddr::V6(_) => {
                    ipv6_gateway = Some(ip);
                }
            }
        }
    }

    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    ipv4_gateway.or(ipv6_gateway).ok_or(err)
}

#[allow(dead_code)]
pub(crate) fn get_default_gateway_interface() -> std::io::Result<String> {
    let cmd = "Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1 -ExpandProperty NetConnectionID";
    let iface = match run_command("powershell", &["-Command", cmd]) {
        Ok(iface) => iface,
        Err(e) => {
            let str = format!("Command \"powershell -Command {}\" error: {}", cmd, e);
            let err = std::io::Error::new(std::io::ErrorKind::Other, str);
            return Err(err);
        }
    };

    let stdout = String::from_utf8_lossy(&iface).into_owned();
    let iface = stdout.trim().to_string();

    Ok(iface)
}

pub(crate) fn flush_dns_cache() -> std::io::Result<()> {
    // command: `ipconfig /flushdns`
    run_command("ipconfig", &["/flushdns"])?;
    Ok(())
}

pub fn alias_to_luid(alias: &str) -> std::io::Result<NET_LUID_LH> {
    let alias = alias.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
    let mut luid = unsafe { std::mem::zeroed() };

    match unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } {
        0 => Ok(luid),
        err => Err(std::io::Error::from_raw_os_error(err as _)),
    }
}

pub fn luid_to_guid(luid: &NET_LUID_LH) -> std::io::Result<GUID> {
    let mut guid = unsafe { std::mem::zeroed() };
    match unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) } {
        0 => Ok(guid),
        err => Err(std::io::Error::from_raw_os_error(err as _)),
    }
}

pub fn get_active_network_interface_gateways() -> std::io::Result<Vec<IpAddr>> {
    let mut addrs = vec![];
    get_adapters_addresses(|adapter| {
        if adapter.OperStatus == IfOperStatusUp && [IF_TYPE_IEEE80211, IF_TYPE_ETHERNET_CSMACD].contains(&adapter.IfType) {
            let mut current_gateway = adapter.FirstGatewayAddress;
            while !current_gateway.is_null() {
                let gateway = unsafe { &*current_gateway };
                {
                    let sockaddr_ptr = gateway.Address.lpSockaddr;
                    let sockaddr = unsafe { &*(sockaddr_ptr as *const SOCKADDR) };
                    let a = unsafe { sockaddr_to_socket_addr(sockaddr) }?;
                    addrs.insert(0, a.ip());
                }
                current_gateway = gateway.Next;
            }
        }
        Ok(())
    })?;
    if addrs.is_empty() {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "No gateway found"))
    } else {
        Ok(addrs)
    }
}

pub(crate) fn get_adapters_addresses<F>(mut callback: F) -> std::io::Result<()>
where
    F: FnMut(IP_ADAPTER_ADDRESSES_LH) -> std::io::Result<()>,
{
    let mut size = 0;
    let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    let family = AF_UNSPEC as u32;

    // Make an initial call to GetAdaptersAddresses to get the
    // size needed into the size variable
    let result = unsafe { GetAdaptersAddresses(family, flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut size) };

    if result != ERROR_BUFFER_OVERFLOW {
        return Err(std::io::Error::from_raw_os_error(result as _));
    }
    // Allocate memory for the buffer
    let mut addresses: Vec<u8> = vec![0; (size + 4) as usize];

    // Make a second call to GetAdaptersAddresses to get the actual data we want
    let addrs = addresses.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let result = unsafe { GetAdaptersAddresses(family, flags, std::ptr::null_mut(), addrs, &mut size) };

    if ERROR_SUCCESS != result {
        return Err(std::io::Error::from_raw_os_error(result as _));
    }

    // If successful, output some information from the data we received
    let mut current_addresses = addresses.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current_addresses.is_null() {
        unsafe {
            callback(*current_addresses)?;
            current_addresses = (*current_addresses).Next;
        }
    }
    Ok(())
}

pub(crate) unsafe fn sockaddr_to_socket_addr(sock_addr: *const SOCKADDR) -> std::io::Result<SocketAddr> {
    use std::io::{Error, ErrorKind};
    let address = match (unsafe { *sock_addr }).sa_family {
        AF_INET => unsafe { sockaddr_in_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN)) },
        AF_INET6 => unsafe { sockaddr_in6_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN6)) },
        _ => return Err(Error::new(ErrorKind::Other, "Unsupported address type")),
    };
    Ok(address)
}

pub(crate) unsafe fn sockaddr_in_to_socket_addr(sockaddr_in: &SOCKADDR_IN) -> SocketAddr {
    let ip_bytes = unsafe { sockaddr_in.sin_addr.S_un.S_addr.to_ne_bytes() };
    let ip = std::net::IpAddr::from(ip_bytes);
    let port = u16::from_be(sockaddr_in.sin_port);
    SocketAddr::new(ip, port)
}

pub(crate) unsafe fn sockaddr_in6_to_socket_addr(sockaddr_in6: &SOCKADDR_IN6) -> SocketAddr {
    let ip = std::net::IpAddr::from(unsafe { sockaddr_in6.sin6_addr.u.Byte });
    let port = u16::from_be(sockaddr_in6.sin6_port);
    SocketAddr::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_gateway() {
        let (addr, iface) = get_default_gateway().unwrap();
        println!("addr: {:?}, iface: {}", addr, iface);

        let gw = get_active_network_interface_gateways().unwrap();
        println!("gateways: {:?}", gw);
    }
}
