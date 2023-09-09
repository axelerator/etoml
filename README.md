![CI badge](https://github.com/axelerator/etoml/actions/workflows/ci.yml/badge.svg)
[![Latest version](https://img.shields.io/crates/v/etoml.svg)](https://crates.io/crates/etoml)
[![Docs](https://img.shields.io/badge/docs-rs-blue)](https://docs.rs/etoml/latest)
# etoml

A tool to create and manage application secrets securely protected in encrypted
(with [ChaCha](https://docs.rs/crypto_box/latest/crypto_box/index.html?search=ChaChaBox#choosing-chachabox-vs-salsabox)) 
toml files.

This is basically a Rust/Toml port of [ejson](https://github.com/Shopify/ejson).

- It generates a private/public key pair for you
- The publich key is stored with your secrets in a `secrets.etoml` in your repository
- The private key is stored `/opt/etoml/keys` (on your server)
- The values in the `secrets.etoml` are encrypted via the CLI tool

The main difference to ejson is that it gives you [a function](https://docs.rs/etoml/0.2.0/etoml/fn.decrypt_default.html) to decrypt your secrets directly
into a `struct` in your application.

![Demonstration](https://raw.githubusercontent.com/axelerator/etoml/main/etoml.gif)
## Install

`cargo install etoml`

## Usage

To create/manage secret files you use the command line interface:

```ignore
Usage: etoml-write <COMMAND>

Commands:
  init     Create a new encrypted TOML file
  encrypt  (Re-)encrypt unencrypted values in an existing etoml file
  decrypt  decrypt unencrypted values in an existing etoml file
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

In you app you can define a struct with the matching fields to decode your secrets into:

```ignore
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct AppSecrets {
    github: String
}

fn main() -> Result<(), etoml::EtomlError>  {
    let secrets = etoml::decrypt_default::<AppSecrets>()?;
    println!("Github key: {}", secrets.github);
    Ok(())
}
```


