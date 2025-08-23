pub mod control_plane {
    tonic::include_proto!("vpn9");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_proto_generation() {
        // Test that the proto module is generated correctly
        let _msg = super::control_plane::AgentSubscriptionRequest {
            agent_id: "test".to_string(),
            hostname: "test-host".to_string(),
            os_version: "test-os".to_string(),
            kernel_version: "test-kernel".to_string(),
            public_ip: "127.0.0.1".to_string(),
            cpu_count: 4,
            total_memory_mb: 8192,
            wg_public_key: "test-public-key".to_string(),
        };
    }
}
