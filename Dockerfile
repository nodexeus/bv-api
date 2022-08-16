# Build container
FROM rust:alpine as build

# We are indirectly depending on libbrotli.
RUN apk update && apk add libc-dev
RUN curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.21.5/$PROTOC_ZIP \
    && unzip -o $PROTOC_ZIP -d /usr/local bin/protoc \
    && unzip -o $PROTOC_ZIP -d /usr/local 'include/*' \
    && rm -f $PROTOC_ZIP

WORKDIR /usr/src/api

COPY . .

ENV RUSTFLAGS -Ctarget-feature=-crt-static
RUN cargo build --release
RUN strip target/release/api

# Slim output image not containing any build tools / artefacts
FROM alpine:latest

RUN apk add libgcc

COPY --from=build /usr/src/api/target/release/api /usr/bin/api
COPY --from=build /usr/src/api/conf /etc/api/conf

CMD ["api"]
