#![doc = include_str!("README.md")]

use base64::{engine::general_purpose, Engine as _};
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use toml::{Table, Value};

#[derive(Debug, Clone)]
pub enum EtomlError {
    MalformattedToml(String),
    MalformattedPrivateKey,
    MalformattedValue,
    MalformattedEtoml(MalformattedError),
    InvalidCustomValue(String),
    ETomlNotFound,
    PrivateKeyNotFound,
}

impl fmt::Display for EtomlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtomlError::MalformattedToml(e) => {
                write!(f, "The given file is not in valid toml format: {}", e)
            }
            EtomlError::MalformattedPrivateKey => {
                write!(f, "The private key is not in a vaild PEM format")
            }
            EtomlError::MalformattedValue => write!(f, "A value is not in valid base64"),
            EtomlError::MalformattedEtoml(e) => write!(f, "Not a valid Etoml file: {}", e),
            EtomlError::InvalidCustomValue(s) => {
                write!(f, "Can't parse into the given type: {}", s)
            }
            EtomlError::ETomlNotFound => write!(f, "Unable to locate the secrets.etoml"),
            EtomlError::PrivateKeyNotFound => {
                write!(f, "Unable to locate the private key in /opt/etoml/keys")
            }
        }
    }
}

pub struct InitializationResult<V>
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    pub encrypted: Encrypted<V>,
    pub private_key: PrivateKeyFile,
}

#[derive(Serialize)]
pub struct Encrypted<V>
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    #[serde(with = "public_key_b64")]
    pub public_key: PublicKey,
    pub values: V,
}

pub fn public_key_as_str<V>(encrypted: &Encrypted<V>) -> String
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    let toml = toml::to_string(&encrypted).unwrap();
    let table = toml.parse::<Table>().unwrap();
    table["public_key"].as_str().unwrap().to_string()
}

mod public_key_b64 {
    use base64::{engine::general_purpose, Engine as _};
    use crypto_box::PublicKey;
    use serde::{Serializer, Serialize};

    pub fn serialize<S: Serializer>(key: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let base64 = general_purpose::URL_SAFE.encode(key.to_bytes());
        String::serialize(&base64, s)
    }
}

mod secret_key_b64 {
    use base64::{engine::general_purpose, Engine as _};
    use crypto_box::SecretKey;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &SecretKey, s: S) -> Result<S::Ok, S::Error> {
        let base64 = general_purpose::URL_SAFE.encode(&v.to_bytes());
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretKey, D::Error> {
        let base64 = String::deserialize(d)?;
        let bytes = general_purpose::URL_SAFE
            .decode(base64)
            .map_err(|e| serde::de::Error::custom(e))?;
        Ok(SecretKey::from_bytes(
            bytes.as_slice()[0..32].try_into().unwrap(),
        ))
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyFile {
    #[serde(with = "secret_key_b64")]
    private_key: SecretKey,
    etoml_version: String,
}

impl fmt::Display for PrivateKeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", toml::to_string(self).unwrap())
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

const SIGNING_KEY: [u8; 32] = [
    0xe8, 0x98, 0xc, 0x86, 0xe0, 0x32, 0xf1, 0xeb, 0x29, 0x75, 0x5, 0x2e, 0x8d, 0x65, 0xbd, 0xdd,
    0x15, 0xc3, 0xb5, 0x96, 0x41, 0x17, 0x4e, 0xc9, 0x67, 0x8a, 0x53, 0x78, 0x9d, 0x92, 0xc7, 0x54,
];

const SIGNING_PRIVATE_KEY: [u8; 32] = [
    0xb5, 0x81, 0xfb, 0x5a, 0xe1, 0x82, 0xa1, 0x6f, 0x60, 0x3f, 0x39, 0x27, 0xd, 0x4e, 0x3b, 0x95,
    0xbc, 0x0, 0x83, 0x10, 0xb7, 0x27, 0xa1, 0x1d, 0xd4, 0xe7, 0x84, 0xa0, 0x4, 0x4d, 0x46, 0x1b,
];

pub fn encrypt_existing(toml_str: &str) -> Result<String, EtomlError> {
    let mut parsed_toml: Value = toml::from_str(toml_str).unwrap();
    let (alice_pub_key, _) =
        read_public_key(&parsed_toml).map_err(EtomlError::MalformattedEtoml)?;
    let bob_secret_key = SecretKey::from(SIGNING_PRIVATE_KEY);
    let bob_box = ChaChaBox::new(&alice_pub_key, &bob_secret_key);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);

    encrypt_tom(&mut parsed_toml, &bob_box, &nonce)
}

pub fn encrypt_new<V>(value: V) -> Result<InitializationResult<V>, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let pub_key = alice_secret_key.public_key();
    let bob_public_key = PublicKey::from(SIGNING_KEY);

    let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);

    let toml_str = toml::to_string(&value).expect("Failed to serialize given value to toml");
    let mut parsed_toml: Value =
        toml::from_str(&toml_str).expect("Failed to serialize given value to toml");
    let encrypted_toml_str = encrypt_tom(&mut parsed_toml, &alice_box, &nonce)?;
    let encrypted_value: V =
        toml::from_str(&encrypted_toml_str).expect("failed to deserialize encrypted toml");

    let encrypted = Encrypted {
        public_key: pub_key,
        values: encrypted_value,
    };

    let priv_key_file = PrivateKeyFile {
        private_key: alice_secret_key,
        etoml_version: VERSION.to_string(),
    };

    Ok(InitializationResult {
        encrypted,
        private_key: priv_key_file,
    })
}

fn encrypt_tom(
    parsed_toml: &mut Value,
    cypher_box: &ChaChaBox,
    nonce: &Nonce,
) -> Result<String, EtomlError> {
    let enc = |s: &str| -> Result<String, EtomlError> {
        if s.starts_with("ET:") {
            Ok(s.to_string())
        } else {
            let nonce_b64 = general_purpose::URL_SAFE.encode(&nonce);

            let ciphertext = cypher_box.encrypt(&nonce, s.as_bytes()).unwrap();
            let b64 = general_purpose::URL_SAFE.encode(ciphertext);
            Ok(format!("ET:{nonce_b64}:{b64}"))
        }
    };

    transform_toml(parsed_toml, enc)
}

#[derive(Debug, Clone)]
pub enum MalformattedError {
    InvalidToml,
    MissingPublicKey,
    InvalidPublicKey,
}

impl fmt::Display for MalformattedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MalformattedError::InvalidToml => write!(f, "Not a valid toml file"),
            MalformattedError::MissingPublicKey => {
                write!(f, "Etoml file is missing the public_key field")
            }
            MalformattedError::InvalidPublicKey => {
                write!(f, "The value in the public_key field is invalid")
            }
        }
    }
}
pub fn is_etoml(toml_str: &str) -> Result<(), MalformattedError> {
    let parsed_toml: Value =
        toml::from_str(toml_str).map_err(|_| MalformattedError::InvalidToml)?;
    if let Value::Table(ref table) = parsed_toml {
        let key_str = table["public_key"]
            .as_str()
            .ok_or(MalformattedError::InvalidPublicKey)?;
        let _pub_key = deserialize_pubkey(key_str)?;
    } else {
        return Err(MalformattedError::InvalidToml);
    };
    Ok(())
}

fn deserialize_pubkey(input: &str) -> Result<PublicKey, MalformattedError> {
    let bytes = general_purpose::URL_SAFE
        .decode(input)
        .map_err(|_| MalformattedError::InvalidPublicKey)?;
    Ok(PublicKey::from_bytes(
        bytes.as_slice()[0..32].try_into().unwrap(),
    ))
}

/// Returns the decrypted secrets deserialized into the given type.
///
/// It expects to find the "secrets.etoml" in the same directory as
/// from where the process is running.
/// And it looks for the private key in the default location
/// /opt/etoml/keys
///
/// # Example
///
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AppSecrets {
///     github: String
/// }
///
/// fn main() -> Result<(), etoml::EtomlError>  {
///     let secrets = etoml::decrypt_default::<AppSecrets>()?;
///     println!("Github key: {}", secrets.github);
///     Ok(())
/// }
/// ```
pub fn decrypt_default<V>() -> Result<V, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a> + serde::de::DeserializeOwned,
{
    decrypt_file("secrets.etoml")
}

/// Returns the decrypted secrets deserialized into the given type.
///
/// It expects to find the "secrets.etoml" in the same directory as
/// from where the process is running.
/// And it looks for the private key in the default location
/// /opt/etoml/keys
/// # Arguments
///
/// * `etoml` - Path to the .etoml file containing the encrypted data
/// # Example
///
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct AppSecrets {
///     github: String
/// }
///
/// fn main() -> Result<(), etoml::EtomlError>  {
///     let secrets = etoml::decrypt_file::<AppSecrets>("/path/to/some.etoml")?;
///     println!("Github key: {}", secrets.github);
///     Ok(())
/// }
/// ```
pub fn decrypt_file<V, P>(etoml: P) -> Result<V, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a> + serde::de::DeserializeOwned,
    P: AsRef<Path>,
{
    let toml_str = fs::read_to_string(etoml).map_err(|_| EtomlError::ETomlNotFound)?;

    let mut parsed_toml: Value =
        toml::from_str(&toml_str).map_err(|e| EtomlError::MalformattedToml(e.to_string()))?;

    let (_, pub_key_serialized) =
        read_public_key(&parsed_toml).map_err(EtomlError::MalformattedEtoml)?;

    let default_priv_key_dir = Path::new("/opt/etoml/keys");
    let priv_key_file = default_priv_key_dir.join(pub_key_serialized);

    let private_key_content =
        fs::read_to_string(priv_key_file).map_err(|_| EtomlError::PrivateKeyNotFound)?;

    let private_key_file: PrivateKeyFile =
        toml::from_str(&private_key_content).map_err(|_| EtomlError::MalformattedPrivateKey)?;

    decrypt::<_>(&mut parsed_toml, &private_key_file)
}

pub fn decrypt<V>(
    parsed_toml: &mut Value,
    private_key_file: &PrivateKeyFile,
) -> Result<V, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a> + serde::de::DeserializeOwned,
{
    let alice_public_key = PublicKey::from(&private_key_file.private_key);
    let bob_secret_key = SecretKey::from(SIGNING_PRIVATE_KEY);
    let bob_box = ChaChaBox::new(&alice_public_key, &bob_secret_key);

    let dec = |s: &str| -> Result<String, EtomlError> {
        if let Some(nonce_and_value_b64) = s.strip_prefix("ET:") {
            let parts: Vec<&str> = nonce_and_value_b64.split(':').collect();
            if parts.len() == 2 {
                let (nonce_b64, encoded_b64) = (parts[0], parts[1]);
                let nonce_bytes = general_purpose::URL_SAFE
                    .decode(nonce_b64)
                    .map_err(|_| EtomlError::MalformattedValue)?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let from_b64 = general_purpose::URL_SAFE
                    .decode(encoded_b64)
                    .map_err(|_| EtomlError::MalformattedValue)?;

                let err = bob_box.decrypt(nonce, from_b64.as_slice());
                if let Err(e) = err {
                    println!("{:?}, {:?}", from_b64, e);
                }

                let decrypted_plaintext = bob_box.decrypt(nonce, from_b64.as_slice()).unwrap();

                Ok(String::from_utf8_lossy(&decrypted_plaintext).to_string())
            } else {
                Err(EtomlError::MalformattedValue)
            }
        } else {
            Ok(s.to_string())
        }
    };
    let decrypted_toml_str = transform_toml(parsed_toml, dec)?;
    let decrypted_table: Table =
        toml::from_str(&decrypted_toml_str).expect("Failed to parse internal toml");
    let x = &decrypted_table["values"];
    let x_ = toml::to_string(&x).unwrap();
    let v: V = toml::from_str(&x_).map_err(|e| EtomlError::InvalidCustomValue(e.to_string()))?;
    Ok(v)
}

pub fn read_public_key(toml: &Value) -> Result<(PublicKey, String), MalformattedError> {
    if let Value::Table(ref table) = toml {
        let key_str = table["public_key"]
            .as_str()
            .ok_or(MalformattedError::MissingPublicKey)?;
        let pub_key = deserialize_pubkey(key_str)?;
        Ok((pub_key, key_str.to_owned()))
    } else {
        Err(MalformattedError::InvalidToml)
    }
}

fn transform_toml<F>(parsed_toml: &mut Value, transform_fn: F) -> Result<String, EtomlError>
where
    F: Fn(&str) -> Result<String, EtomlError>,
{
    transform_values(parsed_toml, &transform_fn)?;

    Ok(toml::to_string(&parsed_toml).unwrap())
}

fn transform_values<F>(value: &mut Value, transform_fn: &F) -> Result<(), EtomlError>
where
    F: Fn(&str) -> Result<String, EtomlError>,
{
    match value {
        Value::Table(table) => {
            for (key, sub_value) in table.iter_mut() {
                if key != "public_key" {
                    transform_values(sub_value, transform_fn)?;
                }
            }
        }
        Value::String(s) => {
            let transformed = transform_fn(s)?;
            *s = transformed;
        }
        _ => {}
    }
    Ok(())
}

/*
fn serialize_pubkey(pub_key: &RsaPublicKey) -> String {
    format!("{}_{}", pub_key.n(), pub_key.e())
}

fn parse_bigint_pair(s: &str) -> Option<(BigUint, BigUint)> {
    let parts: Vec<&str> = s.split('_').collect();

    if parts.len() == 2 {
        if let (Ok(n), Ok(e)) = (BigUint::from_str(parts[0]), BigUint::from_str(parts[1])) {
            return Some((n, e));
        }
    }

    None
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct MyKeys {
        openai: String,
    }

    const PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA6hhqfgA+g27DgZYs
NdthykWQ2AyitLXGdEzusgomfDv7apOOmS7vbwoBH0Zuoty+wozRrp/H87AnDCrC
GkiXfwIDAQABAkB/B47KHwHNOo7WxBHri8eOBp/pzTmBjF5Lf+/LJxzpLm23i/K+
Rs+Zu/elDjnSgFQnqgO4sX+gkC4zQQuPefTBAiEA8tHTvjP9mBWEs99O5qWkmO1b
6rnm1R6Jipowbs7GVl8CIQD2zVu3h7LFX+4z4dj5d9g1cGzgkq9B0GTdib7YdpwS
4QIhAJxV8kFs0eKgQB9bMD6Z+V6ou9xlsrQWhDGj0nkVUmd7AiAlzilJgNDiqSI8
8lChTjlhXjpfYDjWdQyuXuZMFEcuIQIhAOPQgGl7aBAnv/XbP07cQZaAF/WN2KPo
Xg5m5+uzGyo4
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_decrypt() {
        let toml_str = r#" public_key = "12260569626986955858848812559948534323761734740811373688584155384436822647212591191730567240822045931966214046021411287999488214521023340344863858673358719_65537"

            [values]
            openai = "ET:yX8FO+3gMWRsfzUNepNv7XYxL5drIiHVOTNeyqrEh9apFCThqkk3RlskaidokB58BCb2Hh6Vi+NaGLI+8PkB/g=="
            "#;
        let mut parsed_toml: Value =
            toml::from_str(&toml_str).expect("Failed to serialize given value to toml");
        let decrypted = decrypt::<MyKeys>(&mut parsed_toml, PRIVATE_PEM).unwrap();
        assert_eq!("my first secret", decrypted.openai);
    }

    #[derive(Serialize, Deserialize)]
    struct MyKeysWithNew {
        openai: String,
        github: String,
    }

    #[test]
    fn test_reencrypt() {
        let toml_str = r#" public_key = "12260569626986955858848812559948534323761734740811373688584155384436822647212591191730567240822045931966214046021411287999488214521023340344863858673358719_65537"

            [values]
            openai = "ET:yX8FO+3gMWRsfzUNepNv7XYxL5drIiHVOTNeyqrEh9apFCThqkk3RlskaidokB58BCb2Hh6Vi+NaGLI+8PkB/g=="

            github = "AnotherSecret"
            "#;
        let encrypted = encrypt_existing(toml_str).unwrap();
        let encrypted_parsed: Table = toml::from_str(&encrypted).unwrap();
        let values = encrypted_parsed["values"].as_table().unwrap();
        let github_encrypted = values["github"].as_str().unwrap();

        // making sure value has been encrypted
        assert_eq!(91, github_encrypted.len());

        let mut parsed_toml: Value =
            toml::from_str(&encrypted).expect("Failed to serialize given value to toml");
        let decrypted = decrypt::<MyKeysWithNew>(&mut parsed_toml, PRIVATE_PEM).unwrap();

        assert_eq!("AnotherSecret", decrypted.github);
    }

    #[test]
    fn test_encrypt_new() {
        let unencrypted_value = MyKeys {
            openai: "Secret".to_string(),
        };
        let InitializationResult {
            encrypted,
            private_key,
        } = encrypt_new(unencrypted_value, 512).unwrap();

        // making sure value has been encrypted
        assert_eq!(91, encrypted.values.openai.len());

        let output_toml = toml::to_string(&encrypted).unwrap();

        let mut parsed_toml: Value =
            toml::from_str(&output_toml).expect("Failed to serialize given value to toml");
        let decrypted = decrypt::<MyKeys>(&mut parsed_toml, &private_key).unwrap();

        assert_eq!("Secret", decrypted.openai);
    }
}
