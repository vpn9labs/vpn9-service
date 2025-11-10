use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;

use ipnetwork::{IpNetwork, IpNetworkError};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("WireGuard interface not configured for routing")]
    InterfaceMissing,

    #[error("Invalid CIDR '{cidr}': {source}")]
    InvalidCidr {
        cidr: String,
        source: IpNetworkError,
    },

    #[error("Failed to execute '{command}': {stderr}")]
    CommandFailure { command: String, stderr: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Default)]
pub struct RouteManager {
    interface: Option<String>,
    assigned_networks: Vec<IpNetwork>,
    routes: HashMap<IpNetwork, u32>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn replace_interface(&mut self, iface: String, assigned: Vec<IpNetwork>) {
        if self.interface.is_some() {
            self.reset();
        } else {
            self.routes.clear();
        }
        self.interface = Some(iface);
        self.assigned_networks = assigned;
    }

    pub fn add_routes(&mut self, cidrs: &[String]) -> Result<(), RouteError> {
        let iface = self.interface.clone().ok_or(RouteError::InterfaceMissing)?;

        for cidr in cidrs {
            let network = Self::parse_network(cidr)?;
            if self.should_skip(&network) {
                continue;
            }

            let counter = self.routes.entry(network).or_insert(0);
            if *counter == 0 {
                Self::install_route(&iface, &network)?;
                debug!(interface = %iface, route = %network, "Installed route for WireGuard peer");
            }
            *counter += 1;
        }

        Ok(())
    }

    pub fn remove_routes(&mut self, cidrs: &[String]) -> Result<(), RouteError> {
        let iface = match self.interface.clone() {
            Some(iface) => iface,
            None => return Ok(()),
        };

        for cidr in cidrs {
            let network = match Self::parse_network(cidr) {
                Ok(net) => net,
                Err(_) => continue,
            };

            if self.should_skip(&network) {
                continue;
            }

            if let Some(counter) = self.routes.get_mut(&network) {
                if *counter <= 1 {
                    Self::remove_route(&iface, &network)?;
                    debug!(interface = %iface, route = %network, "Removed route for WireGuard peer");
                    self.routes.remove(&network);
                } else {
                    *counter -= 1;
                }
            }
        }

        Ok(())
    }

    pub fn clear_all_routes(&mut self) {
        if let Some(iface) = self.interface.clone() {
            let existing: Vec<IpNetwork> = self.routes.keys().cloned().collect();
            for network in existing {
                if let Err(err) = Self::remove_route(&iface, &network) {
                    warn!(?err, interface = %iface, route = %network, "Failed to remove route during cleanup");
                }
            }
        }
        self.routes.clear();
    }

    pub fn update_assigned_networks(&mut self, assigned: Vec<IpNetwork>) {
        self.assigned_networks = assigned;
    }

    pub fn reset(&mut self) {
        self.clear_all_routes();
        self.interface = None;
        self.assigned_networks.clear();
    }

    fn parse_network(cidr: &str) -> Result<IpNetwork, RouteError> {
        IpNetwork::from_str(cidr).map_err(|source| RouteError::InvalidCidr {
            cidr: cidr.to_string(),
            source,
        })
    }

    fn should_skip(&self, network: &IpNetwork) -> bool {
        if Self::is_default_route(network) {
            return true;
        }

        self.assigned_networks
            .iter()
            .any(|assigned| Self::covers(assigned, network))
    }

    fn is_default_route(network: &IpNetwork) -> bool {
        match network {
            IpNetwork::V4(v4) => v4.prefix() == 0,
            IpNetwork::V6(v6) => v6.prefix() == 0,
        }
    }

    fn covers(super_net: &IpNetwork, sub_net: &IpNetwork) -> bool {
        match (super_net, sub_net) {
            (IpNetwork::V4(super_v4), IpNetwork::V4(sub_v4)) => {
                super_v4.prefix() <= sub_v4.prefix() && super_v4.contains(sub_v4.network())
            }
            (IpNetwork::V6(super_v6), IpNetwork::V6(sub_v6)) => {
                super_v6.prefix() <= sub_v6.prefix() && super_v6.contains(sub_v6.network())
            }
            _ => false,
        }
    }

    fn install_route(iface: &str, network: &IpNetwork) -> Result<(), RouteError> {
        match network {
            IpNetwork::V4(_) => {
                Self::run_ip_command(&["route", "replace", &network.to_string(), "dev", iface])
            }
            IpNetwork::V6(_) => Self::run_ip_command(&[
                "-6",
                "route",
                "replace",
                &network.to_string(),
                "dev",
                iface,
            ]),
        }
    }

    fn remove_route(iface: &str, network: &IpNetwork) -> Result<(), RouteError> {
        match network {
            IpNetwork::V4(_) => {
                Self::run_ip_command(&["route", "del", &network.to_string(), "dev", iface])
            }
            IpNetwork::V6(_) => {
                Self::run_ip_command(&["-6", "route", "del", &network.to_string(), "dev", iface])
            }
        }
    }

    fn run_ip_command(args: &[&str]) -> Result<(), RouteError> {
        let output = Command::new("ip").args(args).output()?;
        if output.status.success() {
            return Ok(());
        }

        Err(RouteError::CommandFailure {
            command: format!("ip {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}
