use clap::{arg, Command, Parser};

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};
use std::{fmt, fs, process};
use toml::{self, Value};

#[derive(Serialize, Deserialize)]
struct MyKeys {
    openai: String,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    name: String,

    /// Write the private key to the default dir (/opt/toml/keys)
    #[arg(short, long)]
    write: bool,
}

fn cli() -> Command {
    Command::new("etoml")
        .about("Manage application secrets in encrytped TOML")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("init")
                .about("Create a new encrypted TOML file")
                .arg(arg!(-w --write "Write the private key to the default directory (/opt/etoml/keys) and a secrets.etoml template"))
                .arg_required_else_help(false),
        )
        .subcommand(
            Command::new("encrypt")
                .about("(Re-)encrypt unencrypted values in an existing etoml file")
                .arg(arg!([PATH] "The etoml file to encrypt").value_parser(clap::value_parser!(PathBuf)))
                .arg_required_else_help(false),
        )
        .subcommand(
            Command::new("decrypt")
                .about("decrypt unencrypted values in an existing etoml file")
                .arg(arg!([PATH] "The etoml file to decrypt").value_parser(clap::value_parser!(PathBuf)))
                .arg_required_else_help(false),
        )
}

fn main() {
    let matches = cli().get_matches();
    let result = match matches.subcommand() {
        Some(("init", sub_matches)) => init(*sub_matches.get_one::<bool>("write").unwrap()),
        Some(("encrypt", _sub_matches)) => encrypt(),
        Some(("decrypt", _sub_matches)) => decrypt(),
        Some((&_, _)) => unreachable!(),
        None => unreachable!(),
    };
    if let Err(e) = result {
        eprintln!("Failure: {}", e);
        process::exit(1);
    }
}

#[derive(Serialize, Deserialize)]
struct Template {
    my_first_key: String,
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CmdError::CantWriteToDefaultDir => write!(
                f,
                "can't write to default dir for private keys: /opt/etoml/keys"
            ),
            CmdError::CantWriteEtoml => write!(f, "can't write secrets.etoml"),
            CmdError::EtomlAlreadyExists => write!(f, "A secrets.etml already exists"),
            CmdError::NoEtomlFile => write!(f, "Can't find secrets.etoml"),
            CmdError::InValidEtomlFile(e) => write!(f, "secrets.etoml has an invalid format: {e}"),
            CmdError::CantReadEtomlFile => write!(f, "can't read secrets.etoml"),
            CmdError::FailedToEncrypt(e) => write!(f, "Failed to encrypt: {}", e),
        }
    }
}

#[derive(Debug, Clone)]
enum CmdError {
    CantWriteToDefaultDir,
    CantWriteEtoml,
    EtomlAlreadyExists,
    NoEtomlFile,
    InValidEtomlFile(etoml::EtomlError),
    CantReadEtomlFile,
    FailedToEncrypt(etoml::EtomlError),
}

fn init(write: bool) -> Result<(), CmdError> {
    let template = Template {
        my_first_key: "my first secret".to_string(),
    };
    let encrypt_result = etoml::encrypt_new(template).expect("Failed to encrypt template");
    let output_toml = toml::to_string(&encrypt_result.encrypted).unwrap();

    if write {
        let default_priv_key_dir = Path::new("/opt/etoml/keys");
        if !default_priv_key_dir.exists() {
            fs::create_dir_all(default_priv_key_dir)
                .map_err(|_| CmdError::CantWriteToDefaultDir)?;
        }

        let etoml_file = Path::new("secrets.etoml");
        if etoml_file.exists() {
            return Err(CmdError::EtomlAlreadyExists);
        }

        let key_filename = etoml::public_key_as_str(&encrypt_result.encrypted);
        let key_file = default_priv_key_dir.join(key_filename);

        fs::write(key_file, encrypt_result.private_key.to_string())
            .map_err(|_| CmdError::CantWriteToDefaultDir)?;

        fs::write(etoml_file, output_toml).map_err(|_| CmdError::CantWriteEtoml)?
    } else {
        println!("Private key:\n{}", encrypt_result.private_key);
        println!("TOML template\n{}", output_toml);
    }

    Ok(())
}
fn encrypt() -> Result<(), CmdError> {
    let etoml_file = Path::new("secrets.etoml");
    if !etoml_file.exists() {
        return Err(CmdError::NoEtomlFile);
    }
    let toml_str = fs::read_to_string(etoml_file).map_err(|_| CmdError::CantReadEtomlFile)?;
    let encrypted_toml = etoml::encrypt_existing(&toml_str).map_err(CmdError::FailedToEncrypt)?;

    fs::write(etoml_file, encrypted_toml).map_err(|_| CmdError::CantWriteEtoml)
}

fn decrypt() -> Result<(), CmdError> {
    let etoml_file = Path::new("secrets.etoml");
    let value: Value = etoml::decrypt_file(etoml_file).map_err(CmdError::InValidEtomlFile)?;

    println!("{}", toml::to_string(&value).unwrap());
    Ok(())
}
