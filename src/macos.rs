#![cfg(target_os = "macos")]

use cidr::IpCidr;
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::TCFType,
        dictionary::{CFDictionary, CFDictionaryGetValue},
        propertylist::{CFPropertyList, CFPropertyListSubClass},
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
    sys::dynamic_store::SCDynamicStoreCopyValue,
};

use crate::{ETC_RESOLV_CONF_FILE, TproxyArgs, TproxyStateInner, run_command};
use std::{net::IpAddr, str::FromStr};

pub(crate) async fn _tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<TproxyStateInner> {
    flush_dns_cache()?;

    // 0. Save the original gateway and scope
    let (original_gateway_0, orig_gw_iface, service_id, orig_iface_name) = get_default_iface_params()?;
    let original_gateway = original_gateway_0.to_string();

    let tun_ip = tproxy_args.tun_ip.to_string();
    let tun_netmask = tproxy_args.tun_netmask.to_string();
    let tun_gateway = tproxy_args.tun_gateway.to_string();

    // sudo sysctl -w net.inet.ip.forwarding=1
    run_command("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;

    // Set up the address and netmask and gateway of the interface
    // Command: `sudo ifconfig tun_name 10.0.0.33 10.0.0.1 netmask 255.255.255.0`
    let args = &[&tproxy_args.tun_name, &tun_ip, &tun_gateway, "netmask", &tun_netmask];
    run_command("ifconfig", args)?;

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
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let bypass_ip = IpCidr::new_host(tproxy_args.proxy_addr.ip());
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

    let default_service_dns = match get_dns_servers(&service_id) {
        Ok(servers) => servers,
        Err(msg) => {
            log::error!("failed to get DNS servers of default interface: {msg}");
            None
        }
    };

    let restore_resolvconf_content = Some(std::fs::read(ETC_RESOLV_CONF_FILE)?);

    // 5. Set the DNS server to the gateway of the interface
    {
        // Command: `sudo sh -c "echo nameserver 10.0.0.1 > /etc/resolv.conf"`
        let file = std::fs::OpenOptions::new().write(true).truncate(true).open(ETC_RESOLV_CONF_FILE)?;
        let mut writer = std::io::BufWriter::new(file);
        use std::io::Write;
        writeln!(writer, "nameserver {tun_gateway}\n")?;

        let orig_iface_name = orig_iface_name.as_deref().unwrap_or("");
        configure_dns_servers(orig_iface_name, &service_id, &[tproxy_args.tun_gateway])?;
    }

    let state = TproxyStateInner {
        tproxy_args: Some(tproxy_args.clone()),
        original_dns_servers: None,
        gateway: Some(original_gateway_0),
        gw_scope: Some(orig_gw_iface),
        umount_resolvconf: false,
        restore_resolvconf_content,
        tproxy_removed_done: false,
        default_service_id: Some(service_id),
        default_service_dns,
        orig_iface_name,
    };

    #[cfg(all(feature = "unsafe-state-file", any(target_os = "macos", target_os = "windows")))]
    crate::store_intermediate_state(&state)?;

    Ok(state)
}

pub(crate) async fn _tproxy_remove(state: &mut TproxyStateInner) -> std::io::Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }
    state.tproxy_removed_done = true;

    let err = std::io::Error::other("No original gateway found");
    let original_gateway = state.gateway.take().ok_or(err)?.to_string();
    let err = std::io::Error::other("No original gateway scope found");
    let original_gw_scope = state.gw_scope.take().ok_or(err)?;

    if let Some(service_id) = &state.default_service_id {
        let iface_friendly_name = state.orig_iface_name.as_deref().unwrap_or("");
        if let Some(default_service_dns) = &state.default_service_dns {
            if let Err(_err) = configure_dns_servers(iface_friendly_name, service_id, default_service_dns.as_slice()) {
                log::debug!("restore original dns servers error: {_err}");
            }
        } else if let Err(e) = remove_dns_servers(service_id, iface_friendly_name) {
            log::debug!("failed to remove DNS servers: {e}");
        }
    }

    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "tproxy_args is None");
    let tproxy_args = state.tproxy_args.as_ref().ok_or(err)?;

    // Command: `sudo route delete bypass_ip/24`
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["delete", &bypass_ip.to_string()];
        run_command("route", args)?;
    }
    if tproxy_args.bypass_ips.is_empty() && !crate::is_private_ip(tproxy_args.proxy_addr.ip()) {
        let bypass_ip = IpCidr::new_host(tproxy_args.proxy_addr.ip());
        let args = &["delete", &bypass_ip.to_string()];
        run_command("route", args)?;
    }

    // route delete default
    // route delete default -ifscope original_gw_scope
    // route add default original_gateway
    if let Err(_err) = run_command("route", &["delete", "default"]) {
        log::debug!("command \"route delete default\" error: {_err}");
    }
    if let Err(_err) = run_command("route", &["delete", "default", "-ifscope", &original_gw_scope]) {
        log::debug!("command \"route delete default -ifscope {original_gw_scope}\" error: {_err}");
    }
    if let Err(_err) = run_command("route", &["add", "default", &original_gateway]) {
        log::debug!("command \"route add default {original_gateway}\" error: {_err}");
    }

    if let Some(data) = &state.restore_resolvconf_content {
        std::fs::write(ETC_RESOLV_CONF_FILE, data)?;
    }

    // remove the record file anyway
    #[cfg(all(feature = "unsafe-state-file", any(target_os = "macos", target_os = "windows")))]
    let _ = std::fs::remove_file(crate::get_state_file_path());

    flush_dns_cache()?;

    Ok(())
}

fn get_cf_dict_entry<T>(dict: &CFDictionary, key: CFString) -> Option<T>
where
    T: CFPropertyListSubClass,
{
    let result = dict.find(key.as_CFTypeRef())?;
    if result.is_null() {
        return None;
    }
    let property_list = unsafe { CFPropertyList::wrap_under_get_rule(*result) };
    property_list.downcast::<T>()
}

/// The path strings can be found in command `scutil` with subcommand `list`.
///
/// Get the gatway IP, name, service ID, friendly name of the default interface.
pub(crate) fn get_default_iface_params() -> std::io::Result<(IpAddr, String, String, Option<String>)> {
    let store = SCDynamicStoreBuilder::new("tproxy-config get iface params").build();
    let Some(property_list) = store.get("State:/Network/Global/IPv4") else {
        return Err(std::io::Error::other("Failed to get network state"));
    };
    let Some(dict) = property_list.downcast::<CFDictionary>() else {
        return Err(std::io::Error::other("Dictionary conversion failed"));
    };
    let Some(gateway) = get_cf_dict_entry::<CFString>(&dict, "Router".into()) else {
        return Err(std::io::Error::other("Failed to get default gateway"));
    };
    let Some(interface) = get_cf_dict_entry::<CFString>(&dict, "PrimaryInterface".into()) else {
        return Err(std::io::Error::other("Failed to get default interface"));
    };
    let Some(service_id) = get_cf_dict_entry::<CFString>(&dict, "PrimaryService".into()) else {
        return Err(std::io::Error::other("Failed to get default service"));
    };

    use std::io::{Error, ErrorKind::InvalidData};
    let gateway_ip = IpAddr::from_str(gateway.to_string().as_str()).map_err(|err| Error::new(InvalidData, err))?;

    let mut iface_name = None;
    let svc_path: CFString = format!("Setup:/Network/Service/{service_id}").as_str().into();
    if let Some(service_dict) = unsafe { SCDynamicStoreCopyValue(store.as_concrete_TypeRef(), svc_path.as_concrete_TypeRef()).as_ref() }
        .and_then(|plist| unsafe { CFPropertyList::wrap_under_create_rule(plist) }.downcast::<CFDictionary>())
    {
        let key: CFString = "UserDefinedName".into();
        if let Some(name) = unsafe { CFDictionaryGetValue(service_dict.as_concrete_TypeRef(), key.as_CFTypeRef()).as_ref() }
            .map(|cfstr| unsafe { CFString::wrap_under_get_rule(cfstr as *const _ as _) })
        {
            iface_name = Some(name.to_string());
        }
    }

    Ok((gateway_ip, interface.to_string(), service_id.to_string(), iface_name))
}

fn configure_dns_servers(iface_friendly_name: &str, service_id: &str, dns_servers: &[IpAddr]) -> std::io::Result<()> {
    if dns_servers.is_empty() {
        return Ok(());
    }
    let store = SCDynamicStoreBuilder::new("tproxy-config configure dns").build();
    let mut dns_server_vec = Vec::<CFString>::new();
    dns_servers.iter().for_each(|x| dns_server_vec.push(x.to_string().as_str().into()));
    let dns_server_array = CFArray::from_CFTypes(dns_server_vec.as_slice());
    let dns_dict = CFDictionary::from_CFType_pairs(&[(CFString::from("ServerAddresses"), dns_server_array)]);
    let key = format!("State:/Network/Service/{service_id}/DNS").as_str().into();
    if !store.set::<CFString, CFDictionary>(key, dns_dict.to_untyped()) {
        log::error!("Failed to set DNS servers");
    }

    // The above statements actually changes the DNS settings, but the network preferences dialog still
    // shows the old settings. Therefore, we execute the following command additionally.
    // Maybe one day the above settings will fully take effect, and this command can be removed.
    if !iface_friendly_name.is_empty() {
        // networksetup -setdnsservers "$iface_name" dns1 dns2 ...
        let addrs = dns_servers.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        let mut args = vec!["-setdnsservers", iface_friendly_name];
        args.extend(addrs.iter().map(|s| s.as_str()));
        run_command("networksetup", &args)?;
    }
    Ok(())
}

/// Get the DNS servers from the specified service.
/// If the DNS servers are obtained through DHCP, this function will return None.
/// Overridden DNS servers are returned as a vector.
fn get_dns_servers(service_id: &String) -> std::io::Result<Option<Vec<IpAddr>>> {
    let store = SCDynamicStoreBuilder::new("tproxy-config get dns").build();
    let key: CFString = format!("State:/Network/Service/{service_id}/DNS").as_str().into();

    let Some(result) = store.get(key) else {
        return Ok(None);
    };

    let Some(cf_dict) = result.downcast::<CFDictionary>() else {
        return Err(std::io::Error::other("Network service DNS server conversion failed"));
    };

    let Some(server_addresses) = cf_dict.find(CFString::from("ServerAddresses").as_CFTypeRef()) else {
        return Ok(None);
    };

    if server_addresses.is_null() {
        return Err(std::io::Error::other("Server addresses are null"));
    }

    let server_addr_prop = unsafe { CFPropertyList::wrap_under_get_rule(*server_addresses) };
    let Some(cf_array) = server_addr_prop.downcast::<CFArray>() else {
        return Err(std::io::Error::other("Server address conversion failed"));
    };

    let mut vec: Vec<IpAddr> = Vec::new();
    for item in cf_array.iter() {
        if item.is_null() {
            continue;
        }

        let property_list = unsafe { CFPropertyList::wrap_under_get_rule(*item) };
        let Some(addr_str) = property_list.downcast::<CFString>() else {
            continue;
        };
        use std::io::{Error, ErrorKind::InvalidData};
        let ip = IpAddr::from_str(addr_str.to_string().as_str()).map_err(|err| Error::new(InvalidData, err))?;

        vec.push(ip);
    }
    Ok(Some(vec))
}

fn remove_dns_servers(_service_id: &str, _friendly_name: &str) -> std::io::Result<()> {
    /*
    let store = SCDynamicStoreBuilder::new("tproxy-config remove dns").build();
    let key: CFString = format!("State:/Network/Service/{}/DNS", _service_id).as_str().into();
    if !store.remove(key) {
        return Err(std::io::Error::other("Failed to remove DNS servers"));
    }
    // */
    if !_friendly_name.is_empty() {
        // command: `networksetup -setdnsservers Wi-Fi Empty`
        run_command("networksetup", &["-setdnsservers", _friendly_name, "Empty"])?;
    }
    Ok(())
}

pub(crate) fn flush_dns_cache() -> std::io::Result<()> {
    // retrieve current macos version `sw_vers -productVersion`
    let ver = run_command("sw_vers", &["-productVersion"])?;
    let ver = String::from_utf8_lossy(&ver).into_owned();

    if crate::compare_version(&ver, "10.12") >= 0 {
        // MacOS version 10.12 and later
        // Command: `sudo killall -HUP mDNSResponder`
        if let Err(e) = run_command("killall", &["-HUP", "mDNSResponder"]) {
            log::debug!("Failed to flush DNS cache: {e}");
        }
    } else {
        // to make the code simpler, we do nothing for MacOS version 10.11 and earlier
    }

    Ok(())
}
