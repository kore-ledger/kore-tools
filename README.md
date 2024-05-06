# TAPLE Tools

Kore Tools are a group of utilities designed to facilitate the use of TAPLE Client, especially during testing and prototyping.

## Build From Source

Minimium supported rust versión (MSRV) is 1.67.

```bash
$ git clone git@github.com:kore-ledger/kore-tools.git
$ cd kore-tools
$ sudo apt install -y libprotobuf-dev protobuf-compiler cmake
$ cargo install --locked --path tools/keygen
$ cargo install --locked --path tools/patch
$ cargo install --locked --path tools/sign
$ kore-keygen -h
$ kore-sign -h
$ kore-patch -h
```

## Usage
Visit the [Kore Tools guide](https://www.kore-ledger.net/docs/learn/) to learn how to use the tools.

## Docker images
Prebuilt docker images are available at [Docker Hub]().

If you want to build the image yourself, then you should do it in the following way:
```sh
docker build -f ./Dockerfile.tools -t taple-tools .
```
