use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub git_hash: String,
    pub git_branch: String,
    pub build_time: String,
}

impl VersionInfo {
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_hash: env!("GIT_HASH").to_string(),
            git_branch: env!("GIT_BRANCH").to_string(),
            build_time: env!("BUILD_TIME").to_string(),
        }
    }

    pub fn full_version(&self) -> String {
        if self.git_hash != "unknown" {
            format!("{}-{}", self.version, self.git_hash)
        } else {
            self.version.clone()
        }
    }

    pub fn short_version(&self) -> &str {
        &self.version
    }
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_version())
    }
}

// Convenience function to get version info
pub fn get_version_info() -> VersionInfo {
    VersionInfo::new()
}

// Convenience function to get just the version string
pub fn get_version() -> String {
    get_version_info().full_version()
}
