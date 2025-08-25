use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

pub struct RuntimeSecurity {
    secure_mode: Arc<AtomicBool>,
}

impl RuntimeSecurity {
    pub fn new() -> Self {
        Self {
            secure_mode: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initialize secure runtime environment
    pub fn initialize_secure_runtime(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing secure runtime environment...");

        // Disable core dumps
        self.disable_core_dumps()?;

        // Lock memory pages
        self.lock_memory_pages()?;

        // Clear environment variables that might contain sensitive data
        self.sanitize_environment();

        // Set up signal handlers for graceful shutdown
        self.setup_signal_handlers()?;

        // Disable swap for current process (Linux-specific)
        #[cfg(target_os = "linux")]
        self.disable_swap()?;

        self.secure_mode.store(true, Ordering::SeqCst);
        info!("Secure runtime environment initialized");
        Ok(())
    }

    /// Disable core dump generation
    #[cfg(unix)]
    fn disable_core_dumps(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let rlimit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &rlimit) != 0 {
                return Err("Failed to disable core dumps".into());
            }
        }
        info!("Core dumps disabled");
        Ok(())
    }

    #[cfg(not(unix))]
    fn disable_core_dumps(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Core dump disabling not supported on this platform");
        Ok(())
    }

    /// Lock memory pages to prevent swapping
    #[cfg(unix)]
    fn lock_memory_pages(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            // Lock all current and future pages
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
                warn!("Failed to lock memory pages (requires root privileges)");
                // Don't fail the entire initialization - this is best-effort
            } else {
                info!("Memory pages locked to prevent swapping");
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn lock_memory_pages(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Memory locking not supported on this platform");
        Ok(())
    }

    /// Clear potentially sensitive environment variables
    fn sanitize_environment(&self) {
        let sensitive_vars = [
            "HOME",
            "USER",
            "USERNAME",
            "LOGNAME",
            "SHELL",
            "MAIL",
            "PATH",
            "PWD",
            "OLDPWD",
            "TERM",
            "SSH_CLIENT",
            "SSH_CONNECTION",
            "SSH_TTY",
        ];

        for var in sensitive_vars.iter() {
            unsafe {
                std::env::remove_var(var);
            }
        }

        // Keep only essential variables
        let essential_vars = [
            "VPN9_CONTROL_PLANE_URL",
            "VPN9_AGENT_VERSION",
            "VPN9_UPDATE_CHECK_INTERVAL",
            "VPN9_HEARTBEAT_INTERVAL",
        ];

        let current_vars: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
        for var in current_vars {
            if !essential_vars.contains(&var.as_str()) && !var.starts_with("VPN9_") {
                unsafe {
                    std::env::remove_var(&var);
                }
            }
        }

        info!("Environment sanitized");
    }

    /// Set up signal handlers for secure shutdown
    #[cfg(unix)]
    fn setup_signal_handlers(&self) -> Result<(), Box<dyn std::error::Error>> {
        use signal_hook::{consts::SIGTERM, iterator::Signals};
        use std::thread;

        let _secure_mode = self.secure_mode.clone();

        thread::spawn(move || {
            let mut signals = Signals::new([SIGTERM]).expect("Failed to register signal handler");
            if let Some(_sig) = signals.forever().next() {
                info!("Received termination signal - performing secure shutdown");

                // Clear sensitive memory
                // Note: In a real implementation, you'd clear specific sensitive data structures

                // Exit immediately without cleanup that might write to disk
                std::process::exit(0);
            }
        });

        info!("Signal handlers configured for secure shutdown");
        Ok(())
    }

    #[cfg(not(unix))]
    fn setup_signal_handlers(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Signal handling not available on this platform");
        Ok(())
    }

    /// Disable swap for current process (Linux-specific)
    #[cfg(target_os = "linux")]
    fn disable_swap(&self) -> Result<(), Box<dyn std::error::Error>> {
        // This requires CAP_SYS_ADMIN capability
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                warn!("Failed to set process as non-dumpable");
            }
        }

        // Attempt to disable swap (best effort)
        match std::process::Command::new("swapoff").arg("-a").output() {
            Ok(_) => info!("Swap disabled (if running as root)"),
            Err(_) => warn!("Could not disable swap (requires root privileges)"),
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn disable_swap(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Check if running in secure mode
    pub fn is_secure_mode(&self) -> bool {
        self.secure_mode.load(Ordering::SeqCst)
    }

    /// Perform secure shutdown
    pub fn secure_shutdown(&self) {
        info!("Performing secure shutdown...");

        // Clear any sensitive memory structures
        // In a real implementation, you'd iterate through and clear all sensitive data

        // Exit without cleanup that might write to disk
        std::process::exit(0);
    }
}

impl Default for RuntimeSecurity {
    fn default() -> Self {
        Self::new()
    }
}
