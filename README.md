# StakeJoy Api Server

## Database

Copy `.env-example` to `.env` and properly configure the `DATABASE_URL`.

### Install Diesel CLI

```bash
cargo install diesel_cli --no-default-features --features postgres
```

Run Setup:
```bash
diesel setup
```

Run Migrations:
```bash
diesel migration run
```

Revert Migration:
```bash
diesel migration revert
```

## Testing

Currently the tests require live db and do not support multithreaded testing.

To run:
```bash
cargo test -- --test-threads=1
```