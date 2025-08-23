use std::env;
use std::process::{Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::time::interval;
use tracing::{error, info};

use crate::version::get_version;
use vpn9_core::control_plane::control_plane_client::ControlPlaneClient;
use vpn9_core::control_plane::{DownloadUpdateRequest, UpdateCheckRequest};

pub struct SecureUpdateManager {
    client: ControlPlaneClient<tonic::transport::Channel>,
    current_version: String,
    agent_id: String,
    update_check_interval: Duration,
}

impl SecureUpdateManager {
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
                    self.download_and_install_update_securely(
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

    /// Download and install update without touching disk
    async fn download_and_install_update_securely(
        &mut self,
        version: &str,
        expected_checksum: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Downloading update version {} (memory-only)", version);

        let request = tonic::Request::new(DownloadUpdateRequest {
            version: version.to_string(),
            agent_id: self.agent_id.clone(),
        });

        let mut stream = self.client.download_update(request).await?.into_inner();
        let mut file_data = Vec::new();

        // Download directly to memory
        while let Some(chunk_result) = stream.message().await? {
            file_data.extend_from_slice(&chunk_result.data);
            if chunk_result.is_final {
                break;
            }
        }

        // Verify checksum in memory
        if !self.verify_checksum(&file_data, expected_checksum)? {
            return Err("Checksum verification failed".into());
        }

        info!("Update downloaded and verified. Installing securely...");
        self.install_update_from_memory(&file_data).await?;

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

    /// Install update directly from memory using memfd (Linux-specific)
    #[cfg(target_os = "linux")]
    async fn install_update_from_memory(
        &self,
        binary_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        // Create anonymous memory file descriptor (memfd_create)
        let memfd = unsafe {
            let name = std::ffi::CString::new("vpn9-agent-update")?;
            let fd = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), libc::MFD_CLOEXEC);
            if fd == -1 {
                return Err("Failed to create memfd".into());
            }
            File::from_raw_fd(fd as i32)
        };

        // Write binary data to memory file descriptor
        {
            use std::io::Write;
            let mut memfd_file = &memfd;
            memfd_file.write_all(binary_data)?;
        }

        // Make the memfd executable
        unsafe {
            if libc::fchmod(memfd.as_raw_fd(), 0o755) != 0 {
                return Err("Failed to make memfd executable".into());
            }
        }

        // Execute the new binary from memory
        let memfd_path = format!("/proc/self/fd/{}", memfd.as_raw_fd());
        info!("Executing update from memory: {}", memfd_path);

        // Fork and exec the new binary
        let args: Vec<String> = env::args().collect();
        Command::new(&memfd_path)
            .args(&args[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Exit current process immediately
        std::process::exit(0);
    }

    /// Fallback for non-Linux systems (uses tmpfs if available)
    #[cfg(not(target_os = "linux"))]
    async fn install_update_from_memory(
        &self,
        binary_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Try to use /dev/shm (tmpfs) which is memory-backed
        let temp_paths = ["/dev/shm", "/tmp"];

        for temp_dir in temp_paths.iter() {
            if std::path::Path::new(temp_dir).exists() {
                let temp_file_path =
                    format!("{}/vpn9-agent-update-{}", temp_dir, uuid::Uuid::new_v4());

                // Write to memory-backed filesystem
                std::fs::write(&temp_file_path, binary_data)?;

                // Make executable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(&temp_file_path)?.permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(&temp_file_path, perms)?;
                }

                // Execute and cleanup
                let args: Vec<String> = env::args().collect();
                Command::new(&temp_file_path)
                    .args(&args[1..])
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()?;

                // Remove file immediately and exit
                let _ = std::fs::remove_file(&temp_file_path);
                std::process::exit(0);
            }
        }

        Err("No suitable memory-backed filesystem found for secure update".into())
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
