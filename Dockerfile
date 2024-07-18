# docker build --platform linux/arm64 -t kore-tools:arm64 --target arm64 -f ./Dockerfile .
# docker build --platform linux/amd64 -t kore-tools:amd64 --target amd64 -f ./Dockerfile .
# docker tag kore-tools:arm64 koreadmin/kore-tools:arm64
# docker tag kore-tools:amd64 koreadmin/kore-tools:amd64
# docker manifest create koreadmin/kore-tools:latest koreadmin/kore-tools:arm64 koreadmin/kore-tools:amd64
# docker manifest push koreadmin/kore-tools:latest
FROM messense/rust-musl-cross:aarch64-musl as builder-arm64
RUN apt-get update && apt-get install --no-install-recommends -y build-essential cmake \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN rustup target add aarch64-unknown-linux-musl
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-keygen
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-sign
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-patch

FROM alpine:3.16 as arm64
COPY --from=builder-arm64 /home/rust/src/target/aarch64-unknown-linux-musl/release/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-patch /usr/local/bin/kore-patch
RUN apk add --no-cache --upgrade bash
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
ENTRYPOINT ["/script/run.sh"]

FROM messense/rust-musl-cross:x86_64-musl as builder-amd64
RUN apt-get update && apt-get install --no-install-recommends -y build-essential cmake \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN rustup target add aarch64-unknown-linux-musl
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-keygen
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-sign
RUN cargo build --release --target aarch64-unknown-linux-musl --bin kore-patch

FROM alpine:3.16 as amd64
COPY --from=builder-arm64 /home/rust/src/target/aarch64-unknown-linux-musl/release/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-arm64 /home/rust/src//target/aarch64-unknown-linux-musl/release/kore-patch /usr/local/bin/kore-patch
RUN apk add --no-cache --upgrade bash
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
ENTRYPOINT ["/script/run.sh"]

