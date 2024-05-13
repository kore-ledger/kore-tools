use clap::{Parser, ValueEnum};
use elliptic_curve::SecretKey as Sec1SecretKey;
use hex_literal::hex;
use k256;
use kore_base::crypto::{Ed25519KeyPair, KeyGenerator, KeyMaterial, KeyPair, Secp256k1KeyPair};
use kore_base::identifier::{Derivable, KeyIdentifier};
use libp2p::identity::{ed25519 as EdIdentify, secp256k1 as SecpIdentify, PublicKey};
use libp2p::PeerId;
use pkcs8::{
    pkcs5, DecodePrivateKey, Document, EncodePrivateKey, EncodePublicKey, EncryptedPrivateKeyInfo,
    PrivateKeyInfo,
};
use std::fs;
use std::str::FromStr;

/// cargo run -- -p a
/// cargo run -- -p a -r keys-Ed25519/private_key.der
/// cargo run -- -p a -r keys-Ed25519/public_key.der -d public-key
/// cargo run -- -p a -m secp256k1
/// cargo run -- -p a -r keys-secp2561k/public_key.der -m secp256k1 -d public-key
/// cargo run -- -p a -r keys-secp2561k/private_key.der -m secp256k1
#[derive(Parser, Default, Debug)]
#[command(override_help = "
    MC generation utility for KORE nodes\n
\x1b[1m\x1b[4mUsage\x1b[0m: kore-keygen [OPTIONS] \n
\x1b[1m\x1b[4mOptions\x1b[0m:
    \x1b[1m-m, --mode\x1b[0m           Algorithm to use: ed25519 (default), secp256k1
    \x1b[1m-d, --mode\x1b[0m           File to read: PrivateKey (default), PublicKey
    \x1b[1m-f, --format\x1b[0m         Output format: yaml(default), json
    \x1b[1m-p, --password\x1b[0m       Password for encryption or decrypt der files
    \x1b[1m-r, --path\x1b[0m           Path of der file to decrypt
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
    #[clap(short = 'r', long = "file-path")]
    path: Option<String>,
    #[clap(short = 'd', long = "typefile")]
    typefile: Option<Typefile>,
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
#[derive(Parser, Clone, Debug, ValueEnum, Default)]
enum Typefile {
    PublicKey,
    #[default]
    PrivateKey,
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
    let algorithm = args.mode.unwrap_or(Algorithm::Ed25519);
    let typefile = args.typefile.unwrap_or(Typefile::PrivateKey);
    let path = args.path.clone();
    let password = args.password.clone();
    if path.is_some() {
        let peer_id = read_der_file(
            path.as_deref(),
            typefile.clone(),
            algorithm.clone(),
            password.as_deref(),
        )
        .unwrap();
        println!("Peer ID: {}", peer_id.to_string());
        return Ok(());
    }

    if args.password.is_none() {
        return Err("Password is required to encrypt".into());
    }
    let (kp, peer_id) = generate_data(algorithm.clone());
    let write_path = match algorithm {
        Algorithm::Ed25519 => "keys-Ed25519",
        Algorithm::Secp256k1 => "keys-secp2561k",
        
    };
    write_keys(
        kp.secret_key_bytes().as_slice(),
        kp.public_key_bytes().as_slice(),
        password.as_deref().unwrap(),
        write_path,
        algorithm,
    )
    .map_err(|e| format!("Error writing keys to file: {}", e))
    .unwrap();
    show_data(kp, peer_id, format);
    Ok(())
}
// Generate KeyPair and PeerId from algorithm
fn generate_data(algorithm: Algorithm) -> (KeyPair, PeerId) {
    let (kp, peer_id) = match algorithm {
        Algorithm::Ed25519 => {
            let keys = generate_ed25519();
            let peer_id = PeerId::from_public_key(&PublicKey::from(
                EdIdentify::PublicKey::try_from_bytes(&keys.public_key_bytes())
                    .expect("Error creating PeerId from public key"),
            ));
            let keys = KeyPair::Ed25519(keys);
            (keys, peer_id)
        }
        Algorithm::Secp256k1 => {
            let keys = generate_secp256k1();
            let peer_id = PeerId::from_public_key(&PublicKey::from(
                SecpIdentify::PublicKey::try_from_bytes(&keys.public_key_bytes())
                    .expect("Error creating PeerId from public key"),
            ));
            let keys = KeyPair::Secp256k1(keys);
            (keys, peer_id)
        }
    };
    (kp, peer_id)
}

// Read DER file and return PeerId
fn read_der_file(
    path: Option<&str>,
    typefile: Typefile,
    algorithm: Algorithm,
    password: Option<&str>,
) -> Result<PeerId, String> {
    let path = path.unwrap();
    if fs::metadata(path).is_ok() {
        match typefile {
            Typefile::PrivateKey => {
                let document = Document::read_der_file(path)
                    .map_err(|e| format!("Error reading file: {}", e))
                    .unwrap();
                // Check if private key is encrypted
                match EncryptedPrivateKeyInfo::try_from(document.as_bytes()) {
                    Ok(enc_pk_info) => {
                        if password.is_none() {
                            return Err("Password is required to decrypt".into());
                        }
                        let der_private_key = enc_pk_info
                            .decrypt(password.unwrap())
                            .map_err(|e| format!("Error decrypting file: {}", e))
                            .unwrap();

                        let peer_id = get_peer_id_from_privatekey(
                            der_private_key.as_bytes(),
                            algorithm.clone(),
                        );
                        Ok(peer_id)
                    }
                    Err(_) => {
                        let peer_id =
                            get_peer_id_from_privatekey(document.as_bytes(), algorithm.clone());
                        Ok(peer_id)
                    }
                }
            }
            Typefile::PublicKey => match algorithm {
                Algorithm::Ed25519 => {
                    let document: ed25519::PublicKeyBytes =
                        pkcs8::DecodePublicKey::read_public_key_der_file(path)
                            .map_err(|e| format!("Error reading file: {}", e))
                            .unwrap();
                    let peer_id = get_peer_id_from_publickey(
                        document.to_bytes()[0..32].try_into().unwrap(),
                        algorithm.clone(),
                    );
                    Ok(peer_id)
                }
                Algorithm::Secp256k1 => {
                    let document: k256::PublicKey =
                        pkcs8::DecodePublicKey::read_public_key_der_file(path)
                            .map_err(|e| format!("Error reading file: {}", e))
                            .unwrap();
                    let peer_id =
                        get_peer_id_from_publickey(&document.to_sec1_bytes(), algorithm.clone());
                    Ok(peer_id)
                }
            },
        }
    } else {
        return Err("File not found".into());
    }
}
fn get_peer_id_from_privatekey(document: &[u8], algorithm: Algorithm) -> PeerId {
    match algorithm {
        Algorithm::Ed25519 => {
            let decode_private_key: ed25519::KeypairBytes =
                ed25519::pkcs8::KeypairBytes::from_pkcs8_der(document)
                    .map_err(|e| {
                        format!("Error creating KeypairBytes(ED25519) from PKCS8 DER: {}", e)
                    })
                    .unwrap();
            let public_key = decode_private_key.public_key.unwrap();
            let public_key = EdIdentify::PublicKey::try_from_bytes(
                public_key.to_bytes()[..32].try_into().unwrap(),
            )
            .expect("Error creating PeerId from public key");
            PeerId::from_public_key(&PublicKey::from(public_key))
        }
        Algorithm::Secp256k1 => {
            let decode_private_key: Sec1SecretKey<k256::Secp256k1> =
                elliptic_curve::SecretKey::from_pkcs8_der(document)
                    .map_err(|e| format!("Error creating Sec1SecretKey from PKCS8 DER: {}", e))
                    .unwrap();
            let public_key = decode_private_key.public_key();
            let public_key = SecpIdentify::PublicKey::try_from_bytes(&public_key.to_sec1_bytes())
                .expect("Error creating PeerId from public key");
            PeerId::from_public_key(&PublicKey::from(public_key))
        }
    }
}
fn get_peer_id_from_publickey(document: &[u8], algorithm: Algorithm) -> PeerId {
    match algorithm {
        Algorithm::Ed25519 => {
            let public_key =
                EdIdentify::PublicKey::try_from_bytes(document[0..32].try_into().unwrap())
                    .expect("Error creating PeerId from public key");
            PeerId::from_public_key(&PublicKey::from(public_key))
        }
        Algorithm::Secp256k1 => {
            let public_key = SecpIdentify::PublicKey::try_from_bytes(document)
                .expect("Error creating PeerId from public key");
            PeerId::from_public_key(&PublicKey::from(public_key))
        }
    }
}
// Write keys to file
// Private key is encrypted with password
// Public key is not encrypted
fn write_keys(
    secret_key: &[u8],
    public_key: &[u8],
    password: &str,
    path: &str,
    algorithm: Algorithm,
) -> Result<(), String> {
    match fs::create_dir_all(path) {
        Ok(_) => {
            match algorithm {
                Algorithm::Ed25519 => {
                    let mut keypair_bytes: Vec<u8> = Vec::new();
                    keypair_bytes.extend_from_slice(secret_key);
                    keypair_bytes.extend_from_slice(public_key);

                    let keypair_bytes_array: [u8; 64] = keypair_bytes
                        .try_into()
                        .map_err(|_| "Error al convertir Vec<u8> a [u8; 64]")?;

                    let signing_key = ed25519::KeypairBytes::from_bytes(&keypair_bytes_array);
                    let public_key = signing_key.public_key.unwrap();

                    let der = match signing_key.to_pkcs8_der() {
                        Ok(der) => der,
                        Err(e) => {
                            return Err(format!("Error converting to PKCS8 DER: {}", e));
                        }
                    };

                    let pk_encrypted =
                        encrypt_from_pkcs8_to_pkcs5(der.as_bytes(), password).unwrap();

                    // Private key in pkcs8 encrypted with pkcs5
                    pk_encrypted
                        .write_der_file(format!("{}/private_key.der", path))
                        .map_err(|e| format!("Error writing private key to file: {}", e))?;

                    // Public key in pksc8
                    public_key
                        .write_public_key_der_file(format!("{}/public_key.der", path))
                        .map_err(|e| format!("Error writing public key to file: {}", e))
                        .unwrap();
                }
                Algorithm::Secp256k1 => {
                    let sec1_key: Sec1SecretKey<k256::Secp256k1> =
                        Sec1SecretKey::from_slice(secret_key).unwrap();

                    let sec1_public_key = sec1_key.public_key();
                    let sec1_der = sec1_key
                        .to_pkcs8_der()
                        .map_err(|e| format!("Error converting to PKCS8 DER: {}", e))
                        .unwrap();

                    let pk_encrypted =
                        encrypt_from_pkcs8_to_pkcs5(sec1_der.as_bytes(), password).unwrap();

                    // Private key in pkcs8 encrypted with pkcs5
                    pk_encrypted
                        .write_der_file(format!("{}/private_key.der", path))
                        .map_err(|e| format!("Error writing private key to file: {}", e))
                        .unwrap();

                    // Public key in pksc8
                    sec1_public_key
                        .write_public_key_der_file(format!("{}/public_key.der", path))
                        .map_err(|e| format!("Error writing public key to file: {}", e))
                        .unwrap();
                }
            }

            Ok(())
        }
        Err(e) => Err(format!("Error creating directory: {}", e)),
    }
}

// Encrypt private key with password
fn encrypt_from_pkcs8_to_pkcs5(
    sec1_der_bytes: &[u8],
    password: &str,
) -> Result<pkcs8::SecretDocument, String> {
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
    let pk_text = match PrivateKeyInfo::try_from(sec1_der_bytes) {
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
    Ok(pk_encrypted)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn verify_peer_id_with_ed25519_private_key() {
        let password = "password";
        let algorithm = Algorithm::Ed25519;
        let (kp, peer_id) = generate_data(algorithm.clone());
        let temp_dir = tempdir().unwrap();
        let private_key_path = temp_dir.path().join("private_key.der");
        write_keys(
            kp.secret_key_bytes().as_slice(),
            kp.public_key_bytes().as_slice(),
            password,
            temp_dir.path().to_str().unwrap(),
            algorithm.clone(),
        )
        .unwrap();

        let peer_from_der = read_der_file(
            private_key_path.to_str(),
            Typefile::PrivateKey,
            algorithm.clone(),
            Some(password),
        );
        temp_dir.close().unwrap();
        assert_eq!(peer_id.to_string(), peer_from_der.unwrap().to_string());
    }

    #[test]
    fn verify_peer_id_with_ed25519_public_key() {
        let password = "password";
        let algorithm = Algorithm::Ed25519;
        let (kp, peer_id) = generate_data(algorithm.clone());
        let temp_dir = tempdir().unwrap();
        let public_key_path = temp_dir.path().join("public_key.der");
        write_keys(
            kp.secret_key_bytes().as_slice(),
            kp.public_key_bytes().as_slice(),
            password,
            temp_dir.path().to_str().unwrap(),
            algorithm.clone(),
        )
        .unwrap();

        let peer_from_der = read_der_file(
            public_key_path.to_str(),
            Typefile::PublicKey,
            algorithm.clone(),
            Some(password),
        );

        temp_dir.close().unwrap();
        assert_eq!(peer_id.to_string(), peer_from_der.unwrap().to_string());
    }

    #[test]
    fn verify_peer_id_with_secp256k1_private_key() {
        let password = "password";
        let algorithm = Algorithm::Secp256k1;
        let (kp, peer_id) = generate_data(algorithm.clone());
        let temp_dir = tempdir().unwrap();
        let private_key_path = temp_dir.path().join("private_key.der");
        write_keys(
            kp.secret_key_bytes().as_slice(),
            kp.public_key_bytes().as_slice(),
            password,
            temp_dir.path().to_str().unwrap(),
            algorithm.clone(),
        )
        .unwrap();

        let peer_from_der = read_der_file(
            private_key_path.to_str(),
            Typefile::PrivateKey,
            algorithm.clone(),
            Some(password),
        );
        temp_dir.close().unwrap();
        assert_eq!(peer_id.to_string(), peer_from_der.unwrap().to_string());
    }
    #[test]
    fn verify_peer_id_with_secp256k1_public_key() {
        let password = "password";
        let algorithm = Algorithm::Secp256k1;
        let (kp, peer_id) = generate_data( algorithm.clone());
        let temp_dir = tempdir().unwrap();
        let public_key_path = temp_dir.path().join("public_key.der");
        write_keys(
            kp.secret_key_bytes().as_slice(),
            kp.public_key_bytes().as_slice(),
            password,
            temp_dir.path().to_str().unwrap(),
            algorithm.clone(),
        )
        .unwrap();

        let peer_from_der = read_der_file(
            public_key_path.to_str(),
            Typefile::PublicKey,
            algorithm.clone(),
            Some(password),
        );
        temp_dir.close().unwrap();
        assert_eq!(peer_id.to_string(), peer_from_der.unwrap().to_string());
    }
}
