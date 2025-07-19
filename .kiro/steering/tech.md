# Technology Stack

## Core Technologies

- **Language**: Rust (Edition 2024)
- **Framework**: Tokio async runtime with Axum web framework
- **Database**: PostgreSQL with Diesel ORM and async support
- **Communication**: gRPC (Tonic) and MQTT (rumqttc)
- **Storage**: AWS S3-compatible object storage
- **Monitoring**: OpenTelemetry with Grafana, Prometheus, and Tempo

## Key Dependencies

- **Web/HTTP**: Axum, Tower, Hyper
- **Database**: Diesel (async), PostgreSQL driver
- **Authentication**: JWT tokens, Argon2 password hashing
- **Serialization**: Protobuf (Prost), Serde JSON
- **Cloud Services**: AWS SDK, Stripe API, Cloudflare API, SendGrid
- **Testing**: Integration tests with Docker Compose

## Build System

Uses Cargo workspace with Make for orchestration:

### Common Commands

```bash
# Initial setup
make setup              # Install prerequisites and initialize submodules

# Development
make up                 # Start Docker services (PostgreSQL, MQTT, etc.)
make down              # Stop all Docker services
make reset             # Reset Docker services and database

# Testing
make test              # Run all tests
make test <test_name>  # Run specific test
make test-out          # Run tests with stdout output

# Database
make diesel <command>  # Run Diesel CLI commands
```

### Prerequisites

- Rust toolchain (via rustup)
- Docker and Docker Compose
- PostgreSQL client tools
- Protobuf compiler
- Make

## Configuration

Supports both TOML config files and environment variables. See `configuration.md` for complete reference. Key config areas:

- Database connection pooling
- External service integrations (Cloudflare, Stripe, SendGrid)
- MQTT broker settings
- OpenTelemetry/observability
- JWT token management
- S3-compatible storage