#![cfg(target_os = "linux")]

use crate::{run_command, TproxyArgs, ETC_RESOLV_CONF_FILE};
use std::net::IpAddr;

pub fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    let tun_name = &tproxy_args.tun_name;
    // sudo ip tuntap add name tun0 mode tun
    let args = &["tuntap", "add", "name", tun_name, "mode", "tun"];
    run_command("ip", args)?;

    // sudo ip link set tun0 up
    let args = &["link", "set", tun_name, "up"];
    run_command("ip", args)?;

    // sudo ip route add "${bypass_ip}" $(ip route | grep '^default' | cut -d ' ' -f 2-)
    let args = &["-c", "ip route | grep '^default' | cut -d ' ' -f 2-"];
    let out = run_command("sh", args)?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let cmd = format!("ip route add {} {}", bypass_ip, stdout.trim());
        let args = &["-c", &cmd];
        if let Err(_err) = run_command("sh", args) {
            #[cfg(feature = "log")]
            log::trace!("run_command {}", _err);
        }
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

    // sudo sh -c "echo nameserver 10.0.0.1 > /etc/resolv.conf"
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open(ETC_RESOLV_CONF_FILE)?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver {}", tproxy_args.tun_gateway)?;

    Ok(())
}

pub fn tproxy_remove(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    // sudo route del bypass_ip
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["del", &bypass_ip.to_string()];
        if let Err(_err) = run_command("route", args) {
            #[cfg(feature = "log")]
            log::debug!("command \"route del {}\" error: {}", bypass_ip, _err);
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
    use std::str::FromStr;
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
}
