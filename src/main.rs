mod crypt;
use anyhow::{Ok, Result};
use clap::{Arg, Command};
use crypt::decrypt::{decrypt_and_extract_folder, decrypt_file};
use crypt::encrypt::{compress_and_encrypt_folder, encrypt_file};
use crypt::utils::{confirm_yes_no, read_and_confirm_password, validate_password};
use zeroize::Zeroize;
use std::fs::{self};
use std::path::PathBuf;

fn main() -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    let long_version_string: &'static str = Box::leak(format!("File Encryptor {} \nAuthor: {}", &version, &authors).into_boxed_str());
    let mut command: Command = Command::new("File Encryptor")
        .version(&version)
        .author(&authors)
        .long_version(&long_version_string)
        .about("Encrypts and decrypts files or folders using AES-256-GCM")
        .subcommand(
            Command::new("lock").about("Encrypt a file or folder").arg(
                Arg::new("input")
                    .help("The input file or folder to encrypt")
                    .required(true)
                    .index(1),
            ),
        )
        .subcommand(
            Command::new("unlock")
                .about("Decrypt a file or folder")
                .arg(
                    Arg::new("input")
                        .help("The input file or folder to decrypt")
                        .required(true)
                        .index(1),
                ),
        );

    let matches = command.clone().get_matches();
    match matches.subcommand() {
        Some(("lock", sub_m)) => {
            let input_path = PathBuf::from(sub_m.get_one::<String>("input").unwrap());
            let metadata = fs::metadata(&input_path)?;

            let mut password = read_and_confirm_password()?;

            confirm_yes_no(
                format!(
                    "You are about to encrypt the file/folder: {:?}",
                    &input_path
                )
                .as_str(),
            )?;

            if metadata.is_file() {
                encrypt_file(&input_path, &input_path, &password)?;
            } else if metadata.is_dir() {
                compress_and_encrypt_folder(&input_path, &password)?;
            } else {
                return Err(anyhow::anyhow!("Unsupported path type"));
            }
            password.zeroize();
            Ok(())
        }
        Some(("unlock", sub_m)) => {
            let input_path = PathBuf::from(sub_m.get_one::<String>("input").unwrap());
            let metadata = fs::metadata(&input_path)?;

            let mut password = validate_password()?;

            confirm_yes_no(
                format!(
                    "You are about to decrypt the file/folder: {:?}",
                    &input_path
                )
                .as_str(),
            )?;

            if metadata.is_file() {
                if input_path.to_string_lossy().ends_with("zip.cryptic") {
                    decrypt_and_extract_folder(&input_path, &password)?;
                } else {
                    decrypt_file(&input_path, &input_path, &password)?;
                }
            } else if metadata.is_dir() {
                decrypt_and_extract_folder(&input_path, &password)?;
            } else {
                return Err(anyhow::anyhow!("Unsupported path type"))
            }
            password.zeroize();
            Ok(())

        }
        _ => {
            println!("{:?}", command.print_help());
            Ok(())
        }
    }
}
