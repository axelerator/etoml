![CI badge](https://github.com/axelerator/etoml/actions/workflows/ci.yml/badge.svg)

# etoml

A tool to create and manage application secrets securely protected in (RSA 2048bits) encrypted toml files.

This is basically a Rust/Toml port of [ejson](https://github.com/Shopify/ejson).
The main features is it gives you a convenience functions to decrypt your secrets directly
into a `struct` in your application.

## Install

`cargo install etoml`

## Usage

To create/manage secret files you use the command line interface:

```ignore
Usage: etoml-write <COMMAND>

Commands:
  init     Create a new encrypted TOML file
  encrypt  (Re-)encrypt unencrypted values in an existinf etoml file
  decrypt  decrypt unencrypted values in an existinf etoml file
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


