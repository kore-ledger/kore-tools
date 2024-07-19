# docker build --platform linux/arm64 -t kore-tools:arm64 --target arm64 -f ./Dockerfile .
# docker build --platform linux/amd64 -t kore-tools:amd64 --target amd64 -f ./Dockerfile .
# docker tag kore-tools:arm64 koreadmin/kore-tools:arm64
# docker tag kore-tools:amd64 koreadmin/kore-tools:amd64
# docker manifest create koreadmin/kore-tools:latest koreadmin/kore-tools:arm64 koreadmin/kore-tools:amd64
# docker manifest push koreadmin/kore-tools:latest

FROM alpine:3.19 AS pre-builder
RUN apk update && apk add openssl-dev pkgconfig proj-dev libstdc++

FROM messense/rust-musl-cross:aarch64-musl as builder-arm64
ENV PKG_CONFIG_PATH=/usr/local/musl/aarch64-unknown-linux-musl/lib/pkgconfig
COPY . .
RUN rustup target add aarch64-unknown-linux-musl
COPY --from=pre-builder usr/bin/bomtool /usr/local/musl/aarch64-unknown-linux-musl/bin/bomtool
COPY --from=pre-builder usr/bin/pkg-config /usr/local/musl/aarch64-unknown-linux-musl/bin/pkg-config
COPY --from=pre-builder usr/bin/pkgconf /usr/local/musl/aarch64-unknown-linux-musl/bin/pkgconf
COPY --from=pre-builder usr/lib/libpkgconf.so.4.0.0 /usr/local/musl/aarch64-unknown-linux-musl/lib/libpkgconf.so.4.0.0
COPY --from=pre-builder usr/lib/libpkgconf.so.4 /usr/local/musl/aarch64-unknown-linux-musl/lib/libpkgconf.so.4
COPY --from=pre-builder usr/include/proj.h /usr/local/musl/aarch64-unknown-linux-musl/include/proj.h
COPY --from=pre-builder usr/include/openssl /usr/local/musl/aarch64-unknown-linux-musl/include/openssl
COPY --from=pre-builder usr/lib/libcrypto.so /usr/local/musl/aarch64-unknown-linux-musl/lib/libcrypto.so
COPY --from=pre-builder usr/lib/libssl.* /usr/local/musl/aarch64-unknown-linux-musl/lib
COPY --from=pre-builder usr/lib/pkgconfig /usr/local/musl/aarch64-unknown-linux-musl/lib/pkgconfig
RUN cp -r /usr/local/musl/aarch64-unknown-linux-musl/bin/* /usr/bin
RUN cp -r /usr/local/musl/aarch64-unknown-linux-musl/lib/* /usr/lib
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-keygen
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-sign
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-patch
RUN cargo build --release --target aarch64-unknown-linux-musl --bin control

FROM alpine:3.16 as arm64
COPY --from=builder-arm64 /home/rust/src/target/aarch64-unknown-linux-musl/release/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-patch /usr/local/bin/kore-patch
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/control /usr/local/bin/control
RUN apk add --no-cache --upgrade bash
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
ENTRYPOINT ["/script/run.sh"]


FROM messense/rust-musl-cross:x86_64-musl as builder-amd64
ENV PKG_CONFIG_PATH=/usr/local/musl/x86_64-unknown-linux-gnu/lib/pkgconfig
COPY . .
RUN rustup target add x86_64-unknown-linux-gnu
COPY --from=pre-builder usr/bin/bomtool /usr/local/musl/x86_64-unknown-linux-gnu/bin/bomtool
COPY --from=pre-builder usr/bin/pkg-config /usr/local/musl/x86_64-unknown-linux-gnu/bin/pkg-config
COPY --from=pre-builder usr/bin/pkgconf /usr/local/musl/x86_64-unknown-linux-gnu/bin/pkgconf
COPY --from=pre-builder usr/lib/libpkgconf.so.4.0.0 /usr/local/musl/x86_64-unknown-linux-gnu/lib/libpkgconf.so.4.0.0
COPY --from=pre-builder usr/lib/libpkgconf.so.4 /usr/local/musl/x86_64-unknown-linux-gnu/lib/libpkgconf.so.4
COPY --from=pre-builder usr/include/proj.h /usr/local/musl/x86_64-unknown-linux-gnu/include/proj.h
COPY --from=pre-builder usr/include/openssl /usr/local/musl/x86_64-unknown-linux-gnu/include/openssl
COPY --from=pre-builder usr/lib/libcrypto.so /usr/local/musl/x86_64-unknown-linux-gnu/lib/libcrypto.so
COPY --from=pre-builder usr/lib/libssl.* /usr/local/musl/x86_64-unknown-linux-gnu/lib
COPY --from=pre-builder usr/lib/pkgconfig /usr/local/musl/x86_64-unknown-linux-gnu/lib/pkgconfig
RUN cp -r /usr/local/musl/x86_64-unknown-linux-gnu/bin/* /usr/bin
RUN cp -r /usr/local/musl/x86_64-unknown-linux-gnu/lib/* /usr/lib
RUN cargo build --release --target x86_64-unknown-linux-gnu --bin control
RUN cargo build --release --target x86_64-unknown-linux-gnu --bin kore-keygen
RUN cargo build --release --target x86_64-unknown-linux-gnu --bin kore-sign
RUN cargo build --release --target x86_64-unknown-linux-gnu --bin kore-patch

FROM alpine:3.16 as amd64
COPY --from=builder-amd64 /home/rust/src/target/x86_64-unknown-linux-gnu/release/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-amd64 /home/rust/src/target/x86_64-unknown-linux-gnu/release/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-amd64 /home/rust/src/target/x86_64-unknown-linux-gnu/release/kore-patch /usr/local/bin/kore-patch
COPY --from=builder-amd64 /home/rust/src/target/x86_64-unknown-linux-gnu/release/control /usr/local/bin/control
RUN apk add --no-cache --upgrade bash
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
ENTRYPOINT ["/script/run.sh"]

