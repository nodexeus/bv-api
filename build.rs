//! Build file generating gRPC stubs

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        // needed for integration tests
        .build_client(true)
        .compile(
            &[
                "proto/blockjoy/api/v1/command_flow.proto",
                "proto/blockjoy/api/v1/host_service.proto",
            ],
            &["proto/blockjoy/api/v1"],
        )?;

    Ok(())
}
