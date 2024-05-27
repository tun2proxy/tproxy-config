use std::net::{IpAddr, SocketAddr};

use crate::{IpCidr, PROXY_ADDR, SOCKET_FWMARK_TABLE, TUN_DNS, TUN_GATEWAY, TUN_IPV4, TUN_MTU, TUN_NAME, TUN_NETMASK};

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Deserialize, serde::Serialize)]
pub struct TproxyArgs {
    pub tun_ip: IpAddr,
    pub tun_netmask: IpAddr,
    pub tun_gateway: IpAddr,
    pub tun_dns: IpAddr,
    pub tun_mtu: u16,
    pub tun_name: String,
    pub proxy_addr: SocketAddr,
    pub bypass_ips: Vec<IpCidr>,
    pub ipv4_default_route: bool,
    pub ipv6_default_route: bool,
    pub gateway_mode: bool,
    pub socket_fwmark: Option<u32>,
    pub socket_fwmark_table: String,
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
            ipv4_default_route: true,
            ipv6_default_route: false,
            gateway_mode: false,
            socket_fwmark: None,
            socket_fwmark_table: SOCKET_FWMARK_TABLE.to_string(),
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
        tun_name.clone_into(&mut self.tun_name);
        self
    }

    pub fn proxy_addr(mut self, proxy_addr: SocketAddr) -> Self {
        self.proxy_addr = proxy_addr;
        self
    }

    pub fn bypass_ips(mut self, bypass_ips: &[IpCidr]) -> Self {
        self.bypass_ips = bypass_ips.to_vec();
        self
    }

    pub fn ipv6_default_route(mut self, enabled: bool) -> Self {
        self.ipv6_default_route = enabled;
        self
    }

    pub fn ipv4_default_route(mut self, enabled: bool) -> Self {
        self.ipv6_default_route = enabled;
        self
    }

    pub fn gateway_mode(mut self, gateway_mode: bool) -> Self {
        self.gateway_mode = gateway_mode;
        self
    }

    pub fn socket_fwmark(mut self, socket_fwmark: u32) -> Self {
        self.socket_fwmark = Some(socket_fwmark);
        self
    }

    pub fn socket_fwmark_table(mut self, socket_fwmark_table: &str) -> Self {
        self.socket_fwmark_table = socket_fwmark_table.to_string();
        self
    }
}
