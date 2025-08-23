use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, trace, warn};

use vpn9_core::control_plane::{
    DownloadUpdateRequest, UpdateCheckRequest, UpdateCheckResponse, UpdateChunk,
};

use crate::config::Config;

/// Manages update checking and distribution for VPN9 agents
#[derive(Debug)]
pub struct UpdateManager {
    config: Config,
}

impl UpdateManager {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Check if an update is available for the requesting agent
    pub async fn check_for_update(
        &self,
        request: Request<UpdateCheckRequest>,
    ) -> Result<Response<UpdateCheckResponse>, Status> {
        let req = request.into_inner();
        debug!(
            agent_id = %req.agent_id,
            current_version = %req.current_version,
            "Received update check request"
        );

        let update_available =
            self.version_compare(&req.current_version, &self.config.current_version);

        trace!(
            agent_id = %req.agent_id,
            current_version = %req.current_version,
            latest_version = %self.config.current_version,
            update_available = update_available,
            "Update availability check completed"
        );

        let response = if update_available {
            let update_file_path = format!(
                "{}/vpn9-agent-{}",
                self.config.update_path, self.config.current_version
            );

            let (checksum, file_size) = if Path::new(&update_file_path).exists() {
                debug!(
                    update_file_path = %update_file_path,
                    "Update file found, calculating checksum"
                );
                let checksum = self.calculate_checksum(&update_file_path).map_err(|e| {
                    error!(
                        update_file_path = %update_file_path,
                        error = %e,
                        "Failed to calculate checksum"
                    );
                    Status::internal(format!("Failed to calculate checksum: {}", e))
                })?;
                let file_size = fs::metadata(&update_file_path)
                    .map_err(|e| {
                        error!(
                            update_file_path = %update_file_path,
                            error = %e,
                            "Failed to get file size"
                        );
                        Status::internal(format!("Failed to get file size: {}", e))
                    })?
                    .len() as i64;
                (checksum, file_size)
            } else {
                warn!(
                    update_file_path = %update_file_path,
                    "Update file not found"
                );
                return Err(Status::not_found("Update file not found"));
            };

            UpdateCheckResponse {
                update_available: true,
                latest_version: self.config.current_version.clone(),
                download_url: format!("/download/{}", self.config.current_version),
                checksum,
                file_size,
            }
        } else {
            UpdateCheckResponse {
                update_available: false,
                latest_version: req.current_version,
                download_url: String::new(),
                checksum: String::new(),
                file_size: 0,
            }
        };

        Ok(Response::new(response))
    }

    /// Download an update file for an agent
    pub async fn download_update(
        &self,
        request: Request<DownloadUpdateRequest>,
    ) -> Result<Response<ReceiverStream<Result<UpdateChunk, Status>>>, Status> {
        let req = request.into_inner();
        let update_file_path = format!("{}/vpn9-agent-{}", self.config.update_path, req.version);

        info!(
            version = %req.version,
            update_file_path = %update_file_path,
            "Update download request received"
        );

        if !Path::new(&update_file_path).exists() {
            warn!(
                update_file_path = %update_file_path,
                "Update file not found for download"
            );
            return Err(Status::not_found("Update file not found"));
        }

        let (tx, rx) = mpsc::channel(4);
        let file_path = update_file_path.clone();

        tokio::spawn(async move {
            const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

            match fs::read(&file_path) {
                Ok(file_data) => {
                    let total_size = file_data.len();
                    let mut offset = 0;

                    debug!(
                        file_path = %file_path,
                        total_size = total_size,
                        chunk_size = CHUNK_SIZE,
                        "Starting file streaming"
                    );

                    for chunk in file_data.chunks(CHUNK_SIZE) {
                        let is_final = offset + chunk.len() >= total_size;

                        let update_chunk = UpdateChunk {
                            data: chunk.to_vec(),
                            offset: offset as i64,
                            is_final,
                        };

                        trace!(
                            offset = offset,
                            chunk_size = chunk.len(),
                            is_final = is_final,
                            "Sending chunk"
                        );

                        if tx.send(Ok(update_chunk)).await.is_err() {
                            debug!("Stream receiver disconnected, stopping file transfer");
                            break;
                        }

                        offset += chunk.len();
                    }

                    debug!(
                        file_path = %file_path,
                        total_bytes_sent = offset,
                        "File streaming completed"
                    );
                }
                Err(e) => {
                    error!(
                        file_path = %file_path,
                        error = %e,
                        "Failed to read update file for streaming"
                    );
                    let _ = tx
                        .send(Err(Status::internal(format!(
                            "Failed to read update file: {}",
                            e
                        ))))
                        .await;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Calculate SHA256 checksum of a file
    fn calculate_checksum(&self, file_path: &str) -> Result<String, std::io::Error> {
        let contents = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&contents);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compare two version strings
    /// TODO: Replace with proper semver comparison in production
    fn version_compare(&self, current: &str, latest: &str) -> bool {
        current != latest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compare() {
        let config = Config::default();
        let update_manager = UpdateManager::new(config);

        assert!(update_manager.version_compare("1.0.0", "1.0.1"));
        assert!(!update_manager.version_compare("1.0.0", "1.0.0"));
        assert!(update_manager.version_compare("1.0.1", "1.0.0"));
    }

    #[test]
    fn test_calculate_checksum() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let config = Config::default();
        let update_manager = UpdateManager::new(config);

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();

        let checksum = update_manager
            .calculate_checksum(temp_file.path().to_str().unwrap())
            .unwrap();

        // SHA256 of "test content"
        assert_eq!(
            checksum,
            "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
        );
    }
}
