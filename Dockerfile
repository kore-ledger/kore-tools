# docker build --platform linux/arm64 -t kore-tools:arm64 --target arm64 -f ./Dockerfile .
# docker build --platform linux/amd64 -t kore-tools:amd64 --target amd64 -f ./Dockerfile .
# docker tag kore-tools:arm64 koreadmin/kore-tools:arm64
# docker tag kore-tools:amd64 koreadmin/kore-tools:amd64
# docker manifest create koreadmin/kore-tools:latest koreadmin/kore-tools:arm64 koreadmin/kore-tools:amd64
# docker manifest push koreadmin/kore-tools:latest
FROM rust:1.78-slim-buster as builder-arm64
RUN apt-get update && apt-get install --no-install-recommends -y build-essential cmake \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo install --path keygen
RUN cargo install --path sign
RUN cargo install --path patch

FROM rust:1.78-slim-buster as arm64
COPY --from=builder-arm64 /usr/local/cargo/bin/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-arm64 /usr/local/cargo/bin/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-arm64 /usr/local/cargo/bin/kore-patch /usr/local/bin/kore-patch
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
ENTRYPOINT ["/script/run.sh"]

FROM rust:1.78-slim-buster as builder-amd64
RUN apt-get update && apt-get install --no-install-recommends -y build-essential cmake \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo install --path keygen
RUN cargo install --path sign
RUN cargo install --path patch

FROM rust:1.78-slim-buster as amd64
COPY --from=builder-amd64 /usr/local/cargo/bin/kore-keygen /usr/local/bin/kore-keygen
COPY --from=builder-amd64 /usr/local/cargo/bin/kore-sign /usr/local/bin/kore-sign
COPY --from=builder-amd64 /usr/local/cargo/bin/kore-patch /usr/local/bin/kore-patch
COPY run.sh ./script/run.sh
RUN chmod +x ./script/run.sh
ENTRYPOINT ["/script/run.sh"]

