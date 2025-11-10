use std::fmt;
use std::fs;

use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(Uuid);

impl AgentId {
    pub fn derive() -> Self {
        let agent_id_override = std::env::var("VPN9_AGENT_ID").ok();
        let machine_id = std::env::var("VPN9_MACHINE_ID_PATH")
            .ok()
            .and_then(|path| fs::read_to_string(path).ok())
            .or_else(|| fs::read_to_string("/etc/machine-id").ok());
        let hostname = std::env::var("HOSTNAME").ok();

        Self::derive_from_sources(agent_id_override, machine_id, hostname)
    }

    pub(crate) fn derive_from_sources(
        agent_id_override: Option<String>,
        machine_id: Option<String>,
        hostname: Option<String>,
    ) -> Self {
        if let Some(candidate) = agent_id_override
            && let Ok(id) = Uuid::parse_str(candidate.trim()) {
                return Self(id);
            }

        if let Some(machine_id) = machine_id {
            let name = format!("vpn9-agent:{}", machine_id.trim());
            return Self(Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes()));
        }

        if let Some(hostname) = hostname {
            let name = format!("vpn9-agent:{}", hostname.trim());
            return Self(Uuid::new_v5(&Uuid::NAMESPACE_DNS, name.as_bytes()));
        }

        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for AgentId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<AgentId> for Uuid {
    fn from(value: AgentId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_prefers_env_override() {
        let derived = AgentId::derive_from_sources(
            Some("0fb8bdfd-4015-40c4-9d48-908496c372b1".into()),
            None,
            Some("ignored-host".into()),
        );

        assert_eq!(
            derived.as_uuid(),
            &Uuid::parse_str("0fb8bdfd-4015-40c4-9d48-908496c372b1").unwrap(),
        );
    }

    #[test]
    fn derive_uses_machine_id() {
        let derived = AgentId::derive_from_sources(
            None,
            Some("test-machine-id\n".into()),
            Some("ignored-host".into()),
        );

        let expected = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"vpn9-agent:test-machine-id");
        assert_eq!(derived.as_uuid(), &expected);
    }

    #[test]
    fn derive_falls_back_to_hostname() {
        let derived = AgentId::derive_from_sources(None, None, Some("vpn9-host".into()));

        let expected = Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"vpn9-agent:vpn9-host");
        assert_eq!(derived.as_uuid(), &expected);
    }
}
