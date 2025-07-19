# Project Structure

## Repository Layout

```
blockvisor-api/          # Main Rust workspace
├── src/                 # Core application source
│   ├── auth/           # Authentication & RBAC
│   ├── grpc/           # gRPC service implementations
│   ├── http/           # HTTP handlers
│   ├── model/          # Database models & schema
│   ├── config/         # Configuration management
│   ├── database/       # DB utilities & seeding
│   ├── email/          # Email templating
│   ├── mqtt/           # MQTT message handling
│   ├── store/          # S3 storage client
│   ├── stripe/         # Stripe API integration
│   ├── cloudflare/     # Cloudflare DNS management
│   └── util/           # Common utilities
├── tests/              # Integration tests
├── migrations/         # Diesel database migrations
└── emails/             # Email templates

proto/                   # Protobuf definitions (git submodule)
deploy/                  # Kubernetes & deployment configs
docker/                  # Docker Compose & configs
```

## Code Organization Patterns

### Service Layer Architecture
- **gRPC services**: Primary API interface in `src/grpc/`
- **HTTP handlers**: REST endpoints in `src/http/handler/`
- **Models**: Database entities in `src/model/` with Diesel schema
- **Authentication**: JWT-based auth with RBAC in `src/auth/`

### Database Patterns
- **Migrations**: Timestamped SQL migrations in `migrations/`
- **Schema**: Auto-generated Diesel schema in `src/model/schema.rs`
- **Models**: Separate files per domain (user, org, node, host, etc.)

### Configuration Management
- **Hierarchical config**: TOML files + environment variables
- **Service-specific**: Each integration has its own config module
- **Validation**: Built-in validation for all config parameters

### Testing Strategy
- **Integration tests**: Full stack tests with Docker services
- **Test helpers**: Shared setup utilities in `tests/setup/`
- **Service isolation**: Each gRPC service has dedicated test module

## Key Conventions

- **Error handling**: Use `anyhow` for application errors, `thiserror` for library errors
- **Async patterns**: Tokio throughout, async Diesel for database
- **Serialization**: Protobuf for gRPC, JSON for HTTP, TOML for config
- **Database**: Use Diesel migrations, never manual schema changes
- **Dependencies**: Pin major versions, use workspace inheritance where possible