use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sysinfo::{Networks, System};
use tracing::error;

#[derive(Serialize, Deserialize, Debug)]
pub struct NetInterface {
    pub name: String,
    pub ip_addresses: Vec<IpAddr>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsInfo {
    pub hostname: String,
    pub os_version: String,
    pub kernel_version: String,
    pub network_interfaces: Vec<NetInterface>,
    pub public_ip: Option<IpAddr>,
    pub cpu_count: usize,
    pub total_memory_mb: u64,
}

/// Collect OS information without reading from disk files
pub async fn collect_os_info() -> OsInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());

    // Get OS version from system API instead of reading files
    let os_version = get_os_version_from_system();
    let kernel_version = get_kernel_version_from_system();

    let network_interfaces: Vec<NetInterface> = Networks::new_with_refreshed_list()
        .into_iter()
        .map(|(name, data)| NetInterface {
            name: name.to_string(),
            ip_addresses: data.ip_networks().iter().map(|addr| addr.addr).collect(),
        })
        .collect();

    // Get public IP without caching to disk
    let public_ip = get_public_ip().await;

    let cpu_count = sys.cpus().len();
    let total_memory_mb = sys.total_memory() / 1024; // KB to MB

    OsInfo {
        hostname,
        os_version,
        kernel_version,
        network_interfaces,
        public_ip,
        cpu_count,
        total_memory_mb,
    }
}

/// Get OS version using system calls instead of reading files
fn get_os_version_from_system() -> String {
    #[cfg(target_os = "linux")]
    {
        // Use uname system call instead of reading /etc files
        use std::ffi::CStr;
        unsafe {
            let mut utsname: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut utsname) == 0 {
                let release = CStr::from_ptr(utsname.release.as_ptr())
                    .to_string_lossy()
                    .to_string();

                // Try to detect distribution from environment or processes
                if let Ok(pretty_name) = std::env::var("PRETTY_NAME") {
                    return pretty_name;
                }

                // Fallback to generic Linux identification
                format!("Linux {release}")
            } else {
                "Linux Unknown".to_string()
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        System::name().unwrap_or_else(|| "Unknown".to_string())
    }
}

/// Get kernel version using system calls
fn get_kernel_version_from_system() -> String {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CStr;
        unsafe {
            let mut utsname: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut utsname) == 0 {
                CStr::from_ptr(utsname.release.as_ptr())
                    .to_string_lossy()
                    .to_string()
            } else {
                "unknown".to_string()
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        System::kernel_version().unwrap_or_else(|| "unknown".to_string())
    }
}

/// Get public IP without caching to filesystem
async fn get_public_ip() -> Option<IpAddr> {
    // Use multiple endpoints for redundancy
    let endpoints = [
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    ];

    for endpoint in endpoints {
        if let Ok(Ok(response)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), reqwest::get(endpoint)).await
        {
            if let Ok(ip_str) = response.text().await {
                let trimmed = ip_str.trim();
                if let Ok(ip) = IpAddr::from_str(trimmed) {
                    return Some(ip);
                }
            }
        }
    }

    error!("Failed to get public IP from all endpoints");
    None
}

/// Clear sensitive data from memory (best effort)
pub fn secure_zero_memory(data: &mut [u8]) {
    unsafe {
        std::ptr::write_volatile(data.as_mut_ptr(), 0);
        for byte in data.iter_mut() {
            std::ptr::write_volatile(byte, 0);
        }
    }
}
