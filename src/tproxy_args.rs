use std::net::{IpAddr, SocketAddr};

use crate::{PROXY_ADDR, TUN_DNS, TUN_GATEWAY, TUN_IPV4, TUN_MTU, TUN_NAME, TUN_NETMASK};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TproxyArgs {
    pub tun_ip: IpAddr,
    pub tun_netmask: IpAddr,
    pub tun_gateway: IpAddr,
    pub tun_dns: IpAddr,
    pub tun_mtu: u16,
    pub tun_name: String,
    pub proxy_addr: SocketAddr,
    pub bypass_ips: Vec<IpAddr>,
}

impl Default for TproxyArgs {
    fn default() -> Self {
        Self {
            tun_ip: TUN_IPV4,
            tun_netmask: TUN_NETMASK,
            tun_gateway: TUN_GATEWAY,
            tun_dns: TUN_DNS,
            tun_mtu: TUN_MTU,
            tun_name: TUN_NAME.to_string(),
            proxy_addr: PROXY_ADDR,
            bypass_ips: vec![],
        }
    }
}

impl TproxyArgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tun_ip(mut self, tun_ip: IpAddr) -> Self {
        self.tun_ip = tun_ip;
        self
    }

    pub fn tun_netmask(mut self, tun_netmask: IpAddr) -> Self {
        self.tun_netmask = tun_netmask;
        self
    }

    pub fn tun_gateway(mut self, tun_gateway: IpAddr) -> Self {
        self.tun_gateway = tun_gateway;
        self
    }

    pub fn tun_dns(mut self, tun_dns: IpAddr) -> Self {
        self.tun_dns = tun_dns;
        self
    }

    pub fn tun_mtu(mut self, tun_mtu: u16) -> Self {
        self.tun_mtu = tun_mtu;
        self
    }

    pub fn tun_name(mut self, tun_name: &str) -> Self {
        self.tun_name = tun_name.to_owned();
        self
    }

    pub fn proxy_addr(mut self, proxy_addr: SocketAddr) -> Self {
        self.proxy_addr = proxy_addr;
        self
    }

    pub fn bypass_ips(mut self, bypass_ips: &[IpAddr]) -> Self {
        self.bypass_ips = bypass_ips.to_vec();
        self
    }
}
