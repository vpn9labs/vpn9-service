use std::env;
use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::time::interval;
use tracing::{error, info};

use crate::version::get_version;
use vpn9_core::control_plane::control_plane_client::ControlPlaneClient;
use vpn9_core::control_plane::{DownloadUpdateRequest, UpdateCheckRequest};

pub struct UpdateManager {
    client: ControlPlaneClient<tonic::transport::Channel>,
    current_version: String,
    agent_id: String,
    update_check_interval: Duration,
}

impl UpdateManager {
    pub fn new(client: ControlPlaneClient<tonic::transport::Channel>) -> Self {
        Self {
            client,
            current_version: get_version(),
            agent_id: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            update_check_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_check_interval = interval;
        self
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.current_version = version;
        self
    }

    pub async fn check_for_updates(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let request = tonic::Request::new(UpdateCheckRequest {
            current_version: self.current_version.clone(),
            agent_id: self.agent_id.clone(),
        });

        match self.client.check_for_update(request).await {
            Ok(response) => {
                let update_info = response.into_inner();
                if update_info.update_available {
                    info!(
                        "Update available: {} -> {}",
                        self.current_version, update_info.latest_version
                    );
                    self.download_and_install_update(
                        &update_info.latest_version,
                        &update_info.checksum,
                    )
                    .await?;
                } else {
                    info!("No updates available");
                }
            }
            Err(e) => {
                error!("Failed to check for updates: {}", e);
            }
        }
        Ok(())
    }

    async fn download_and_install_update(
        &mut self,
        version: &str,
        expected_checksum: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Downloading update version {}", version);

        let request = tonic::Request::new(DownloadUpdateRequest {
            version: version.to_string(),
            agent_id: self.agent_id.clone(),
        });

        let mut stream = self.client.download_update(request).await?.into_inner();
        let temp_file_path = format!("/tmp/vpn9-agent-{}", version);
        let mut file_data = Vec::new();

        while let Some(chunk_result) = stream.message().await? {
            file_data.extend_from_slice(&chunk_result.data);
            if chunk_result.is_final {
                break;
            }
        }

        // Verify checksum
        if !self.verify_checksum(&file_data, expected_checksum)? {
            return Err("Checksum verification failed".into());
        }

        // Write to temp file
        fs::write(&temp_file_path, &file_data)?;

        // Make executable
        self.make_executable(&temp_file_path)?;

        info!("Update downloaded and verified. Installing...");
        self.install_update(&temp_file_path).await?;

        Ok(())
    }

    fn verify_checksum(
        &self,
        data: &[u8],
        expected_checksum: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let actual_checksum = format!("{:x}", hasher.finalize());

        if actual_checksum != expected_checksum {
            error!(
                "Checksum mismatch: expected {}, got {}",
                expected_checksum, actual_checksum
            );
            return Ok(false);
        }

        Ok(true)
    }

    #[cfg(unix)]
    fn make_executable(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(file_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(file_path, perms)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn make_executable(&self, _file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // On non-Unix systems, files are typically executable by default
        Ok(())
    }

    async fn install_update(
        &self,
        new_binary_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_exe = env::current_exe()?;
        let backup_path = format!("{}.backup", current_exe.display());

        // Create backup of current binary
        fs::copy(&current_exe, &backup_path)?;
        info!("Created backup at: {}", backup_path);

        // Replace current binary with new one
        fs::copy(new_binary_path, &current_exe)?;
        info!("Replaced binary with new version");

        info!("Update installed successfully. Restarting...");

        // Restart the agent
        let mut cmd = Command::new(&current_exe);
        cmd.args(env::args().skip(1))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = cmd.exec();
        }

        #[cfg(not(unix))]
        {
            cmd.spawn()?;
            std::process::exit(0);
        }

        // This line should never be reached on Unix systems
        unreachable!("exec() should not return on success");
    }

    pub async fn start_update_checker(&mut self) {
        let mut update_interval = interval(self.update_check_interval);

        loop {
            update_interval.tick().await;
            if let Err(e) = self.check_for_updates().await {
                error!("Update check failed: {}", e);
            }
        }
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}
