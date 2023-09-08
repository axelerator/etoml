use base64::{engine::general_purpose, Engine as _};

use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;
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

pub struct WithPrivateKeyString<V>
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    pub encrypted: Encrypted<V>,
    pub private_key: String,
}

#[derive(Serialize)]
pub struct Encrypted<V>
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    pub public_key: String,
    pub values: V,
}

pub fn encrypt_new<V>(value: V) -> Result<WithPrivateKeyString<V>, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a>,
{
    let toml_str = toml::to_string(&value).expect("Failed to serialize given value to toml");
    let mut parsed_toml: Value =
        toml::from_str(&toml_str).expect("Failed to serialize given value to toml");
    let line_ending = rsa::pkcs1::LineEnding::LF;
    let mut rng = rand::thread_rng();
    let bits = 512;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let enc = |s: &str| -> Result<String, EtomlError> {
        if s.starts_with("ET:") {
            Ok(s.to_string())
        } else {
            let mut rng_ = rand::thread_rng();
            let enc_data = pub_key
                .encrypt(&mut rng_, Pkcs1v15Encrypt, s.as_bytes())
                .expect("failed to encrypt");
            let b64 = general_purpose::STANDARD.encode(enc_data);
            Ok(format!("ET:{b64}"))
        }
    };

    let encrypted_toml_str = transform_toml(&mut parsed_toml, enc)?;
    let encrypted_value: V =
        toml::from_str(&encrypted_toml_str).expect("failed to deserialize encrypted toml");
    let private_key_pem = priv_key
        .to_pkcs8_pem(line_ending)
        .expect("failed to write private key")
        .to_string();

    let public_key_str = serialize_pubkey(&pub_key);
    let encrypted = Encrypted {
        public_key: public_key_str,
        values: encrypted_value,
    };

    Ok(WithPrivateKeyString {
        encrypted,
        private_key: private_key_pem,
    })
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
        let _pub_key = deserialize_pubkey(key_str);
    } else {
        return Err(MalformattedError::InvalidToml);
    };
    Ok(())
}
pub fn decrypt_to_string(
    parsed_toml: &mut Value,
    priv_key_str: &str,
) -> Result<String, EtomlError> {
    let priv_key = RsaPrivateKey::from_pkcs8_pem(priv_key_str).unwrap();
    let dec = |s: &str| -> Result<String, EtomlError> {
        if let Some(encoded) = s.strip_prefix("ET:") {
            let from_b64 = general_purpose::STANDARD.decode(encoded).unwrap();

            let dec_data = priv_key
                .decrypt(Pkcs1v15Encrypt, from_b64.as_slice())
                .expect("failed to decrypt");
            Ok(String::from_utf8_lossy(&dec_data).to_string())
        } else {
            Ok(s.to_string())
        }
    };
    let decrypted_toml_str = transform_toml(parsed_toml, dec)?;
    Ok(decrypted_toml_str)
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
/// ```
/// #[derive(Serialize, Deserialize)]
/// struct AppSecrets {
///     github: String
/// }
///
/// fn main() {
///     let secrets : AppSecrets = etoml::decrypt_default().unwrap();
///     println!("Github key: {}", secrets.github);
/// }
/// ```
pub fn decrypt_default<V>() -> Result<V, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a> + serde::de::DeserializeOwned,
{
    let toml_str = fs::read_to_string("secrets.etoml").map_err(|_| EtomlError::ETomlNotFound)?;

    let mut parsed_toml: Value =
        toml::from_str(&toml_str).map_err(|e| EtomlError::MalformattedToml(e.to_string()))?;

    let (_, pub_key_serialized) =
        read_public_key(&parsed_toml).map_err(|e| EtomlError::MalformattedEtoml(e))?;

    let default_priv_key_dir = Path::new("/opt/etoml/keys");
    let priv_key_file = default_priv_key_dir.join(pub_key_serialized);

    let private_key_pem =
        fs::read_to_string(priv_key_file).map_err(|_| EtomlError::PrivateKeyNotFound)?;
    decrypt::<_>(&mut parsed_toml, &private_key_pem)
}

pub fn decrypt<V>(parsed_toml: &mut Value, private_pem: &str) -> Result<V, EtomlError>
where
    V: Serialize + for<'a> Deserialize<'a> + serde::de::DeserializeOwned,
{
    let priv_key = RsaPrivateKey::from_pkcs8_pem(private_pem)
        .map_err(|_| EtomlError::MalformattedPrivateKey)?;

    let dec = |s: &str| -> Result<String, EtomlError> {
        if let Some(encoded) = s.strip_prefix("ET:") {
            let from_b64 = general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| EtomlError::MalformattedValue)?;

            let dec_data = priv_key
                .decrypt(Pkcs1v15Encrypt, from_b64.as_slice())
                .expect("failed to decrypt");
            Ok(String::from_utf8_lossy(&dec_data).to_string())
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

pub fn read_public_key(toml: &Value) -> Result<(RsaPublicKey, String), MalformattedError> {
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

pub fn encrypt_existing(toml_str: &str) -> Result<String, EtomlError> {
    let mut parsed_toml: Value = toml::from_str(toml_str).unwrap();
    let (pub_key, _) = read_public_key(&parsed_toml).map_err(EtomlError::MalformattedEtoml)?;

    let enc = |s: &str| -> Result<String, EtomlError> {
        if s.starts_with("ET:") {
            Ok(s.to_string())
        } else {
            let mut rng_ = rand::thread_rng();
            let enc_data = pub_key
                .encrypt(&mut rng_, Pkcs1v15Encrypt, s.as_bytes())
                .expect("failed to encrypt");
            let b64 = general_purpose::STANDARD.encode(enc_data);
            Ok(format!("ET:{b64}"))
        }
    };

    transform_toml(&mut parsed_toml, enc)
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
fn deserialize_pubkey(input: &str) -> Result<RsaPublicKey, MalformattedError> {
    let (n, e) = parse_bigint_pair(input).ok_or(MalformattedError::InvalidPublicKey)?;
    RsaPublicKey::new(n, e).map_err(|_| MalformattedError::InvalidPublicKey)
}

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
        let decrypted = decrypt::<MyKeys>(toml_str, PRIVATE_PEM).unwrap();
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

        let decrypted = decrypt::<MyKeysWithNew>(&encrypted, PRIVATE_PEM).unwrap();

        assert_eq!("AnotherSecret", decrypted.github);
    }

    #[test]
    fn test_encrypt_new() {
        let unencrypted_value = MyKeys {
            openai: "Secret".to_string(),
        };
        let WithPrivateKeyString {
            encrypted,
            private_key,
        } = encrypt_new(unencrypted_value).unwrap();

        // making sure value has been encrypted
        assert_eq!(91, encrypted.values.openai.len());

        let output_toml = toml::to_string(&encrypted).unwrap();

        let decrypted = decrypt::<MyKeys>(&output_toml, &private_key).unwrap();

        assert_eq!("Secret", decrypted.openai);
    }
}
