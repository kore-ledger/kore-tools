use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use hex_literal::hex;
use kore_base::crypto::{Ed25519KeyPair, KeyGenerator, KeyMaterial, KeyPair, Secp256k1KeyPair};
use kore_base::identifier::{Derivable, KeyIdentifier};
use libp2p::identity::{ed25519 as EdIdentify, secp256k1 as SecpIdentify, PublicKey};
use libp2p::PeerId;
use pkcs8::{pkcs5, EncodePrivateKey, EncodePublicKey, PrivateKeyInfo};
use std::fs;
use std::str::FromStr;
/// cargo run -- -p Root1234
/// cargo run -- -p secp256k1 -m secp256k1
#[derive(Parser, Default, Debug)]
#[command(override_help = "
    MC generation utility for KORE nodes\n
\x1b[1m\x1b[4mUsage\x1b[0m: kore-keygen [OPTIONS] \n
\x1b[1m\x1b[4mOptions\x1b[0m:
    \x1b[1m-m, --mode\x1b[0m           Algorithm to use: ed25519 (default), secp256k1
    \x1b[1m-f, --format\x1b[0m         Output format: yaml(default), json
    \x1b[1m-p, --password\x1b[0m       Password for encryption der files
    \x1b[1m-h, --help\x1b[0m           Print help information
    \x1b[1m-V, --version\x1b[0m        Print version information  
    ")]
#[clap(version)]
struct Args {
    /// Algorithm to use. Default to Ed25519
    #[clap(value_enum, short = 'm', long = "mode")]
    mode: Option<Algorithm>,
    #[clap(short = 'f', long = "format")]
    format: Option<Format>,
    #[clap(short = 'p', long = "password")]
    password: Option<String>,
}

#[derive(Parser, Clone, Debug, ValueEnum, Default)]
enum Algorithm {
    #[default]
    Ed25519,
    Secp256k1,
}

#[derive(Parser, Clone, Debug, ValueEnum, Default)]
enum Format {
    #[default]
    Yaml,
    Json,
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "yaml" => Ok(Format::Yaml),
            _ => Err(format!("'{}' is not a valid format", s)),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = Args::parse();
    let format = args.format.unwrap_or(Format::Yaml);

    if args.password.is_none() {
        return Err("Password is required".into());
    }

    let (kp, peer_id) = match args.mode.unwrap_or(Algorithm::Ed25519) {
        Algorithm::Ed25519 => {
            let keys = generate_ed25519();

            let peer_id = PeerId::from_public_key(&PublicKey::from(
                EdIdentify::PublicKey::try_from_bytes(&keys.public_key_bytes())
                    .expect("Error creating PeerId from public key"),
            ));

            let private_key = keys.secret_key_bytes();
            let private_key_slice = private_key.as_slice();
            write_keys(private_key_slice, &args.password.unwrap(), "keys-Ed25519")
                .expect("Error writing keys to file");

            let keys = KeyPair::Ed25519(keys);
            (keys, peer_id)
        }
        Algorithm::Secp256k1 => {
            let keys = generate_secp256k1();
            let peer_id = PeerId::from_public_key(&PublicKey::from(
                SecpIdentify::PublicKey::try_from_bytes(&keys.public_key_bytes())
                    .expect("Error creating PeerId from public key"),
            ));

            let private_key = keys.secret_key_bytes();
            let private_key_slice = private_key.as_slice();
            write_keys(private_key_slice, &args.password.unwrap(), "keys-secp2561k")
                .expect("Error writing keys to file");

            let keys = KeyPair::Secp256k1(keys);
            (keys, peer_id)
        }
    };

    show_data(kp, peer_id, format);
    Ok(())
}

fn write_keys(secret_key: &[u8], password: &str, path: &str) -> Result<(), String> {
    match fs::create_dir_all(path) {
        Ok(_) => {
            let signing_key = secret_key;
            let signing_key = SigningKey::from_bytes(signing_key[0..32].try_into().unwrap());
            let der = match signing_key.to_pkcs8_der() {
                Ok(der) => der,
                Err(e) => {
                    return Err(format!("Error converting to PKCS8 DER: {}", e));
                }
            };
            let der_bytes = der.as_bytes();
            let pbes2_params = match pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(
                2048,
                &hex!("79d982e70df91a88"),
                &hex!("b2d02d78b2efd9dff694cf8e0af40925"),
            ) {
                Ok(pbes2_params) => pbes2_params,
                Err(e) => {
                    return Err(format!("Error creating PBES2 parameters: {}", e));
                }
            };
            let pk_text = match PrivateKeyInfo::try_from(der_bytes) {
                Ok(pk_text) => pk_text,
                Err(e) => {
                    return Err(format!("Error creating PrivateKeyInfo: {}", e));
                }
            };
            let pk_encrypted = match pk_text.encrypt_with_params(pbes2_params, password) {
                Ok(pk_encrypted) => pk_encrypted,
                Err(e) => {
                    return Err(format!("Error encrypting private key: {}", e));
                }
            };
            pk_encrypted
                .write_der_file(format!("{}/private_key.der", path))
                .map_err(|e| format!("Error writing private key to file: {}", e))?;
            signing_key
                .verifying_key()
                .write_public_key_der_file(format!("{}/public_key.der", path))
                .map_err(|e| format!("Error writing public key to file: {}", e))?;
            Ok(())
        }
        Err(e) => Err(format!("Error creating directory: {}", e)),
    }
}

fn show_data(kp: KeyPair, peer_id: PeerId, format: Format) {
    let private_key = kp.secret_key_bytes();
    let hex_private_key = hex::encode(private_key);
    let public_key = kp.public_key_bytes();
    let key_identifier = KeyIdentifier::new(kp.get_key_derivator(), &public_key).to_str();
    match format {
        Format::Json => {
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "private_key": hex_private_key,
                "controller_id": key_identifier,
                "peer_id": peer_id.to_string()
            }))
            .expect("JSON serialization possible");
            println!("{}", json);
        }
        Format::Yaml => {
            let yaml = serde_yaml::to_string(&serde_json::json!({
                "private_key": hex_private_key,
                "controller_id": key_identifier,
                "peer_id": peer_id.to_string()
            }))
            .expect("YAML serialization possible");
            println!("{}", yaml);
        }
    }
}

fn generate_ed25519() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed(&[])
}

fn generate_secp256k1() -> Secp256k1KeyPair {
    Secp256k1KeyPair::from_seed(&[])
}
