use std::process::Command;

fn main() {
    // Get the package version from Cargo.toml
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION={}",
        env!("CARGO_PKG_VERSION")
    );

    // Get git commit hash if available
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_HASH={git_hash}");
        } else {
            println!("cargo:rustc-env=GIT_HASH=unknown");
        }
    } else {
        println!("cargo:rustc-env=GIT_HASH=unknown");
    }

    // Get git branch if available
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_BRANCH={git_branch}");
        } else {
            println!("cargo:rustc-env=GIT_BRANCH=unknown");
        }
    } else {
        println!("cargo:rustc-env=GIT_BRANCH=unknown");
    }

    // Get build timestamp
    let build_time = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    println!("cargo:rustc-env=BUILD_TIME={build_time}");

    // Re-run if git state changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}
