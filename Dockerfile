# docker build --platform linux/arm64 -t koreadmin/kore-tools:arm64 --target arm64 -f ./Dockerfile .
# docker build --platform linux/amd64 -t koreadmin/kore-tools:amd64 --target amd64 -f ./Dockerfile .
# docker push koreadmin/kore-tools:arm64
# docker push koreadmin/kore-tools:amd64
# docker manifest rm  koreadmin/kore-tools:0.5
# docker manifest create koreadmin/kore-tools:0.5 koreadmin/kore-tools:arm64 koreadmin/kore-tools:amd64
# docker manifest push koreadmin/kore-tools:0.5

FROM alpine:3.16 AS pre-builder
RUN apk update && apk add openssl-dev pkgconfig

FROM messense/rust-musl-cross:aarch64-musl AS builder-arm64
ENV OPENSSL_LIB_DIR=/usr/local/musl/aarch64-unknown-linux-musl/lib
ENV OPENSSL_INCLUDE_DIR=/usr/local/musl/aarch64-unknown-linux-musl/include/openssl

COPY control control
COPY keygen keygen
COPY patch patch
COPY sign sign
COPY Cargo.toml Cargo.toml

RUN rustup target add aarch64-unknown-linux-musl

# pkgconfig
COPY --from=pre-builder usr/bin/pkg-config /usr/local/musl/aarch64-unknown-linux-musl/bin/pkg-config
COPY --from=pre-builder usr/bin/pkgconf /usr/local/musl/aarch64-unknown-linux-musl/bin/pkgconf
COPY --from=pre-builder usr/lib/libpkgconf.* /usr/local/musl/aarch64-unknown-linux-musl/lib
COPY --from=pre-builder usr/lib/pkgconfig /usr/local/musl/aarch64-unknown-linux-musl/lib/pkgconfig

# openssl
COPY --from=pre-builder usr/include/openssl /usr/local/musl/aarch64-unknown-linux-musl/include/openssl
COPY --from=pre-builder usr/lib/libcrypto.so /usr/local/musl/aarch64-unknown-linux-musl/lib/libcrypto.so
COPY --from=pre-builder usr/lib/libssl.* /usr/local/musl/aarch64-unknown-linux-musl/lib

RUN cp -r /usr/local/musl/aarch64-unknown-linux-musl/bin/* /usr/bin
RUN cp -r /usr/local/musl/aarch64-unknown-linux-musl/lib/* /usr/lib

RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-keygen
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-sign
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-patch
RUN cargo build --release --target aarch64-unknown-linux-musl --bin control

FROM alpine:3.16 AS arm64
COPY --from=builder-arm64 /home/rust/src/target/aarch64-unknown-linux-musl/release/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-patch /usr/local/bin/kore-patch
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/control /usr/local/bin/control
RUN apk add --no-cache --upgrade bash
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
CMD ["/script/run.sh"]


FROM messense/rust-musl-cross:x86_64-musl AS builder-amd64
ENV OPENSSL_LIB_DIR=/usr/local/musl/x86_64-unknown-linux-musl/lib
ENV OPENSSL_INCLUDE_DIR=/usr/local/musl/x86_64-unknown-linux-musl/include/openssl

COPY control control
COPY keygen keygen
COPY patch patch
COPY sign sign
COPY Cargo.toml Cargo.toml

RUN rustup target add x86_64-unknown-linux-musl

# pkgconfig
COPY --from=pre-builder usr/bin/pkg-config /usr/local/musl/x86_64-unknown-linux-musl/bin/pkg-config
COPY --from=pre-builder usr/bin/pkgconf /usr/local/musl/x86_64-unknown-linux-musl/bin/pkgconf
COPY --from=pre-builder usr/lib/libpkgconf.* /usr/local/musl/x86_64-unknown-linux-musl/lib
COPY --from=pre-builder usr/lib/pkgconfig /usr/local/musl/x86_64-unknown-linux-musl/lib/pkgconfig

# openssl
COPY --from=pre-builder usr/include/openssl /usr/local/musl/x86_64-unknown-linux-musl/include/openssl
COPY --from=pre-builder usr/lib/libcrypto.so /usr/local/musl/x86_64-unknown-linux-musl/lib/libcrypto.so
COPY --from=pre-builder usr/lib/libssl.* /usr/local/musl/x86_64-unknown-linux-musl/lib

RUN cp -r /usr/local/musl/x86_64-unknown-linux-musl/bin/* /usr/bin
RUN cp -r /usr/local/musl/x86_64-unknown-linux-musl/lib/* /usr/lib

RUN cargo build --release --target x86_64-unknown-linux-musl --bin kore-keygen
RUN cargo build --release --target x86_64-unknown-linux-musl --bin kore-sign
RUN cargo build --release --target x86_64-unknown-linux-musl --bin kore-patch
RUN cargo build --release --target x86_64-unknown-linux-musl --bin control

FROM alpine:3.16 AS amd64
COPY --from=builder-amd64 /home/rust/src/target/x86_64-unknown-linux-musl/release/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-amd64 /home/rust/src//target/x86_64-unknown-linux-musl/release/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-amd64 /home/rust/src//target/x86_64-unknown-linux-musl/release/kore-patch /usr/local/bin/kore-patch
COPY --from=builder-amd64 /home/rust/src//target/x86_64-unknown-linux-musl/release/control /usr/local/bin/control

RUN apk add --no-cache --upgrade bash
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
CMD ["/script/run.sh"]