# Build container
FROM rust:alpine as build

RUN apk update && apk add libc-dev openssl-dev

RUN cargo install sqlx-cli --features postgres
RUN strip /usr/local/cargo/bin/sqlx

# Slim output image not containing any build tools / artefacts
FROM alpine:latest

RUN apk add libgcc

COPY --from=build /usr/local/cargo/bin/sqlx /usr/bin/sqlx

WORKDIR /usr/src/

COPY . ./migrations

CMD ["sqlx", "migrate", "run"]
