### Build container
FROM rust:alpine as build

RUN apk update && apk add \
    protobuf \
    protobuf-dev \
    protoc \
    libc-dev \
    libpq-dev

ENV RUSTFLAGS -Ctarget-feature=-crt-static

WORKDIR /src

RUN cargo init

COPY blockvisor-api/build.rs /src
COPY docker/builder.toml /src/Cargo.toml
COPY proto /src/proto
COPY rust-toolchain.toml /src

RUN cargo build --release
