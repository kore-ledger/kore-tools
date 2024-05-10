# kore Tools

Kore Tools are a group of utilities designed to facilitate the use of kore Client, especially during testing and prototyping.

## Build From Source

Minimium supported rust versión (MSRV) is 1.67.

```bash
$ git clone git@github.com:kore-ledger/kore-tools.git
$ cd kore-tools
$ sudo apt install -y libprotobuf-dev protobuf-compiler cmake
$ cargo install --locked --path keygen
$ cargo install --locked --path patch
$ cargo install --locked --path sign
$ kore-keygen -h
$ kore-sign -h
$ kore-patch -h
```

## Usage
### Usage ok kore-keygen
```bash
# Generate pkcs8 encrpty with pkcs5(ED25519)
kore-keygen -p a
kore-keygen -p a -r keys-Ed25519/private_key.der
kore-keygen -p a -r keys-Ed25519/public_key.der -d public-key
# Generate pkcs8 encrpty with pkcs5(SECP256K1)
kore-keygen -p a -m secp256k1
kore-keygen -p a -r keys-secp2561k/private_key.der -m secp256k1
kore-keygen -p a -r keys-secp2561k/public_key.der -m secp256k1 -d public-key
```
Visit the [Kore Tools guide](https://www.kore-ledger.net/docs/learn/) to learn how to use the tools.

## Docker images
Prebuilt docker images are available at [Docker Hub]().

If you want to build the image yourself, then you should do it in the following way:
```sh
docker build -f ./Dockerfile.tools -t kore-tools .
```
