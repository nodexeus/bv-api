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
RUN strip /src/target/release/blockvisor-api


### App container
FROM alpine:latest

RUN apk add --no-cache libgcc libpq

COPY --from=build /src/target/release/blockvisor-api /usr/bin/api
COPY --from=build /src/blockvisor-api/emails /emails

CMD ["api"]
