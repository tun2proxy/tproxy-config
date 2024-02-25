mod linux;
mod macos;
mod private_ip;
mod tproxy_args;
mod windows;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
pub use {private_ip::is_private_ip, tproxy_args::TproxyArgs};

#[cfg(target_os = "linux")]
pub use {linux::tproxy_remove, linux::tproxy_setup};

#[cfg(target_os = "windows")]
pub use {windows::tproxy_remove, windows::tproxy_setup};

#[cfg(target_os = "macos")]
pub use {macos::tproxy_remove, macos::tproxy_setup};

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

#[allow(dead_code)]
#[cfg(unix)]
pub(crate) const ETC_RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

#[allow(dead_code)]
pub(crate) fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

#[allow(dead_code)]
pub(crate) fn get_state_file_path() -> PathBuf {
    let temp_dir = std::env::temp_dir();
    temp_dir.join("tproxy_config_restore_state.json")
}

#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct TproxyRestore {
    tproxy_args: TproxyArgs,
    #[cfg(not(target_os = "linux"))]
    pub(crate) dns_servers: Option<Vec<IpAddr>>,
    #[cfg(not(target_os = "linux"))]
    pub(crate) gateway: Option<IpAddr>,
    #[cfg(not(target_os = "linux"))]
    pub(crate) gw_scope: Option<String>,
    #[cfg(target_os = "linux")]
    pub(crate) umount_resolvconf: bool,
    #[cfg(target_os = "linux")]
    pub(crate) restore_resolvconf_content: Option<Vec<u8>>,
}

#[allow(dead_code)]
pub(crate) fn store_restore_state(state: &TproxyRestore) -> std::io::Result<()> {
    let contents = serde_json::to_string(&state)?;
    std::fs::write(crate::get_state_file_path(), contents)?;
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn retrieve_restore_state() -> std::io::Result<TproxyRestore> {
    let path = crate::get_state_file_path();
    if !path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No state file found"));
    }
    let s = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<TproxyRestore>(&s)?)
}
