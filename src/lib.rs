mod linux;
mod macos;
mod private_ip;
mod tproxy_args;
mod windows;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
pub use {private_ip::is_private_ip, tproxy_args::TproxyArgs};

pub use cidr::IpCidr;

#[cfg(target_os = "linux")]
pub use linux::{tproxy_remove, tproxy_setup};

#[cfg(target_os = "windows")]
pub use windows::{tproxy_remove, tproxy_setup};

#[cfg(target_os = "macos")]
pub use macos::{tproxy_remove, tproxy_setup};

pub const TUN_NAME: &str = if cfg!(target_os = "linux") {
    "tun0"
} else if cfg!(target_os = "windows") {
    "wintun"
} else if cfg!(target_os = "macos") {
    "utun5"
} else {
    // panic!("Unsupported OS")
    "unknown-tun"
};
pub const TUN_MTU: u16 = 1500;
pub const PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const TUN_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
pub const SOCKET_FWMARK_TABLE: &str = "100";

#[allow(dead_code)]
#[cfg(unix)]
pub(crate) const ETC_RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

#[allow(dead_code)]
pub(crate) fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let full_cmd = format!("{} {}", command, args.join(" "));
    log::trace!("Running command: \"{full_cmd}\"...");
    let out = match std::process::Command::new(command).args(args).output() {
        Ok(out) => out,
        Err(e) => {
            log::trace!("Run command: \"{full_cmd}\" failed with: {e}");
            return Err(e);
        }
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("Run command: \"{full_cmd}\" failed with {err}");
        log::trace!("{}", info);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

#[allow(dead_code)]
#[cfg(feature = "unsafe-state-file")]
pub(crate) fn get_state_file_path() -> std::path::PathBuf {
    let temp_dir = std::env::temp_dir();
    temp_dir.join("tproxy_config_restore_state.json")
}

#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct TproxyState {
    pub(crate) tproxy_args: Option<TproxyArgs>,
    pub(crate) original_dns_servers: Option<Vec<IpAddr>>,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) gw_scope: Option<String>,
    pub(crate) umount_resolvconf: bool,
    pub(crate) restore_resolvconf_content: Option<Vec<u8>>,
    pub(crate) tproxy_removed_done: bool,
    #[cfg(target_os = "linux")]
    pub(crate) restore_ipv4_route: Option<Vec<String>>,
    #[cfg(target_os = "linux")]
    pub(crate) restore_ipv6_route: Option<Vec<String>>,
    #[cfg(target_os = "linux")]
    pub(crate) restore_gateway_mode: Option<Vec<String>>,
    #[cfg(target_os = "linux")]
    pub(crate) restore_ip_forwarding: bool,
    #[cfg(target_os = "linux")]
    pub(crate) restore_socket_fwmark: Option<Vec<String>>,
    #[cfg(target_os = "macos")]
    pub(crate) default_service_id: Option<String>,
    #[cfg(target_os = "macos")]
    pub(crate) default_service_dns: Option<Vec<IpAddr>>,
    #[cfg(target_os = "macos")]
    pub(crate) orig_iface_name: Option<String>,
}

#[allow(dead_code)]
#[cfg(feature = "unsafe-state-file")]
pub(crate) fn store_intermediate_state(state: &TproxyState) -> std::io::Result<()> {
    let contents = serde_json::to_string(&state)?;
    std::fs::write(crate::get_state_file_path(), contents)?;
    Ok(())
}

#[allow(dead_code)]
#[cfg(feature = "unsafe-state-file")]
pub(crate) fn retrieve_intermediate_state() -> std::io::Result<TproxyState> {
    let path = crate::get_state_file_path();
    if !path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No state file found"));
    }
    let s = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<TproxyState>(&s)?)
}

/// Compare two version strings
/// Returns 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2
#[allow(dead_code)]
pub(crate) fn compare_version(v1: &str, v2: &str) -> i32 {
    let n = v1.len().abs_diff(v2.len());
    let split_parse = |ver: &str| -> Vec<i32> {
        ver.split('.')
            .filter_map(|s| s.parse::<i32>().ok())
            .chain(std::iter::repeat(0).take(n))
            .collect()
    };

    std::iter::zip(split_parse(v1), split_parse(v2))
        .skip_while(|(a, b)| a == b)
        .map(|(a, b)| if a > b { 1 } else { -1 })
        .next()
        .unwrap_or(0)
}
