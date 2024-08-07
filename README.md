# kore Tools

Kore Tools are a group of utilities designed to facilitate the use of kore Client, especially during testing and prototyping.

## Build Local

```sh
$ git clone git@github.com:kore-ledger/kore-tools.git
$ cd kore-tools
$ sudo apt install -y libprotobuf-dev protobuf-compiler cmake
$ cargo install --locked --path keygen
$ cargo install --locked --path patch
$ cargo install --locked --path sign
$ cargo install --locked --path control
$ kore-keygen -h
$ kore-sign -h
$ kore-patch -h
```

## Usage
### Usage kore-keygen
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

### Usage kore-sign
```bash
# Basic usage example
kore-sign --id-private-key 2a71a0aff12c2de9e21d76e0538741aa9ac6da9ff7f467cf8b7211bd008a3198 '{"Transfer":{"subject_id":"JjyqcA-44TjpwBjMTu9kLV21kYfdIAu638juh6ye1gyU","public_key":"E9M2WgjXLFxJ-zrlZjUcwtmyXqgT1xXlwYsKZv47Duew"}}'
```

### Usage kore-patch
```bash
# Basic usage example
kore-patch '{"members":[]}' '{"members":[{"id":"EtbFWPL6eVOkvMMiAYV8qio291zd3viCMepUL6sY7RjA","name":"ACME"}]}'
```

### Usage control
```bash
# Basic usage example
export SERVERS="0.0.0.0:3040,0.0.0.0:3041"
control
```

## Docker images
Prebuilt docker images are available at [Docker Hub](https://hub.docker.com/repository/docker/koreadmin/kore-tools/tags).

If you want to build the image yourself, then you should do it in the following way:
```sh
docker pull koreadmin/kore-tools:0.5
```

### Usage kore-sign
```sh
# Basic usage example
docker run koreadmin/kore-tools:0.5 kore-sign --id-private-key 2a71a0aff12c2de9e21d76e0538741aa9ac6da9ff7f467cf8b7211bd008a3198 '{"Transfer":{"subject_id":"JjyqcA-44TjpwBjMTu9kLV21kYfdIAu638juh6ye1gyU","public_key":"E9M2WgjXLFxJ-zrlZjUcwtmyXqgT1xXlwYsKZv47Duew"}}'
```

### Usage kore-patch
```sh
# Basic usage example
docker run koreadmin/kore-tools:0.5 kore-patch '{"members":[]}' '{"members":[{"id":"EtbFWPL6eVOkvMMiAYV8qio291zd3viCMepUL6sY7RjA","name":"ACME"}]}'
```

### Usage kore-keygen
```sh
docker run -v $(pwd):/mnt -w /mnt koreadmin/kore-tools:0.5 kore-keygen -p a
docker run -v $(pwd):/mnt -w /mnt koreadmin/kore-tools:0.5 kore-keygen -p a -r keys-Ed25519/private_key.der
docker run -v $(pwd):/mnt -w /mnt koreadmin/kore-tools:0.5 kore-keygen -p a -r keys-Ed25519/public_key.der -d public-key
```

### Usage Control

```sh
# Important to expose the port that is used for the server
docker run -p 3040:3040 -e  SERVERS="0.0.0.0:3040" -e ALLOWLIST="172.0.1.2" koreadmin/kore-tools:0.5 control
```