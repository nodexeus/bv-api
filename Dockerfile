# Build container
FROM rust:1.51-alpine as build

# We are indirectly depending on libbrotli.
RUN apk update && apk add libc-dev

WORKDIR /usr/src/api

COPY . .

ENV RUSTFLAGS -Ctarget-feature=-crt-static
ENV SQLX_OFFLINE true
RUN cargo build --release

# Slim output image not containing any build tools / artefacts
FROM alpine:latest

RUN apk add libgcc

COPY --from=build /usr/src/api/target/release/api /usr/bin/api

CMD ["api"]
