use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use argon2::Argon2;
use clap::{Arg, ArgAction, Command};
use indicatif::{ProgressBar, ProgressStyle};
use password_hash::SaltString;
use rand::RngCore;
use rpassword::read_password;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zip::{write::FileOptions, ZipWriter};

fn main() -> Result<()> {
    let matches = Command::new("File Encryptor")
        .version("1.0")
        .author("Arun V")
        .about("Encrypts and decrypts files or folders using AES-256-GCM")
        .arg(
            Arg::new("input")
                .help("The input file or folder to encrypt or decrypt")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("decrypt")
                .short('x')
                .long("decrypt")
                .help("Decrypt the input file or folder")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let input_path = PathBuf::from(matches.get_one::<String>("input").unwrap());
    let metadata = fs::metadata(&input_path)?;

    println!("Enter password:");
    let password = read_password().context("Failed to read password")?;

    if metadata.is_file() {
        if matches.get_flag("decrypt") {
            println!("DECRYPTING...");
            if input_path.to_string_lossy().ends_with("zip.cryptic") {
                println!("DECRYPTING AND EXTRACTING FOLDER");
                decrypt_and_extract_folder(&input_path, &password)
            } else {
                decrypt_file(&input_path, &input_path, &password)
            }
        } else {
            encrypt_file(&input_path, &input_path, &password)
        }
    } else if metadata.is_dir() {
        if matches.get_flag("decrypt") {
            decrypt_and_extract_folder(&input_path, &password)
        } else {
            compress_and_encrypt_folder(&input_path, &password)
        }
    } else {
        Err(anyhow::anyhow!("Unsupported path type"))
    }
}

fn compress_folder(folder_path: &Path, zip_path: &Path) -> Result<()> {
    let file = File::create(zip_path).context("Failed to create zip file")?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    for entry in WalkDir::new(folder_path) {
        let entry = entry?;
        let path = entry.path();
        let name = path.strip_prefix(folder_path)?;

        if path.is_file() {
            zip.start_file(name.to_str().unwrap(), options)?;
            let mut file = File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
        } else if path.is_dir() {
            zip.add_directory(name.to_str().unwrap(), options)?;
        }
    }

    zip.finish()?;
    Ok(())
}

fn extract_folder(zip_path: &Path, output_folder: &Path) -> Result<()> {
    let file = File::open(zip_path).context("Failed to open zip file")?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = output_folder.join(file.mangled_name());

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                fs::create_dir_all(p)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

fn compress_and_encrypt_folder(folder_path: &Path, password: &str) -> Result<()> {
    let zip_path: PathBuf = folder_path.with_extension("zip");
    compress_folder(folder_path, &zip_path)?;
    
    encrypt_file(&zip_path, &zip_path.with_extension("zip.cryptic"), password)?;
    fs::remove_file(&zip_path)?;
    fs::remove_dir_all(&folder_path)?;
    println!(
        "Folder encrypted successfully as: {:?}",
        &zip_path.with_extension("zip.cryptic")
    );
    Ok(())
}

fn decrypt_and_extract_folder(encrypted_path: &Path, password: &str) -> Result<()> {
    let zip_path = encrypted_path;
    let output_folder = zip_path.with_extension("").with_extension("");
    let decrypted_zip_path = output_folder.with_extension("zip");

    decrypt_file(&zip_path, &decrypted_zip_path, password)?;
    
    extract_folder(&decrypted_zip_path, &output_folder)?;
    
    fs::remove_file(&zip_path)?;
    fs::remove_file(&decrypted_zip_path)?;

    println!(
        "Folder decrypted and extracted successfully to: {:?}",
        output_folder
    );
    Ok(())
}

fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let file_size = fs::metadata(input_path)?.len();
    let temp_path = input_path.with_extension("cryptic.tmp");

    let mut input_file = File::open(input_path)?;
    let mut temp_file = File::create(&temp_path)?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new((&key).into());

    temp_file.write_all(&salt)?;

    let progress_bar = create_progress_bar(file_size);

    let chunk_size = 4096;
    let mut buffer = vec![0u8; chunk_size];

    while let Ok(bytes_read) = input_file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_chunk = cipher
            .encrypt(nonce, &buffer[..bytes_read])
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        temp_file.write_all(&nonce_bytes)?;
        temp_file.write_all(&(encrypted_chunk.len() as u32).to_le_bytes())?;
        temp_file.write_all(&encrypted_chunk)?;

        progress_bar.inc(bytes_read as u64);
    }
    
    progress_bar.finish_with_message("Encryption complete!");

    fs::rename(&temp_path, output_path)?;

    println!("File encrypted successfully: {:?}", output_path);

    Ok(())
}

fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let temp_path = input_path.with_extension("decrypt.tmp");

    let mut input_file = File::open(input_path)?;
    let mut temp_file = File::create(&temp_path)?;

    let mut salt = [0u8; 16];
    input_file.read_exact(&mut salt)?;

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new((&key).into());

    let file_size = fs::metadata(input_path)?.len();
    let progress_bar = create_progress_bar(file_size);

    let mut nonce_bytes = [0u8; 12];

    while let Ok(_) = input_file.read_exact(&mut nonce_bytes) {
        let mut chunk_size_bytes = [0u8; 4];
        input_file.read_exact(&mut chunk_size_bytes)?;
        let encrypted_chunk_size = u32::from_le_bytes(chunk_size_bytes) as usize;

        let mut encrypted_chunk = vec![0u8; encrypted_chunk_size];
        input_file.read_exact(&mut encrypted_chunk)?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted_chunk = cipher
            .decrypt(nonce, encrypted_chunk.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        temp_file.write_all(&decrypted_chunk)?;
        progress_bar.inc(decrypted_chunk.len() as u64);
    }
    progress_bar.finish_with_message("Decryption complete!");

    fs::rename(&temp_path, output_path)?;

    println!(
        "File decrypted successfully: {:?}",
        output_path
    );
    Ok(())
}

fn create_progress_bar(size: u64) -> ProgressBar {
    let progress_bar = ProgressBar::new(size);
    progress_bar.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    progress_bar
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let salt_string = create_salt_string(salt)
        .map_err(|e| anyhow::anyhow!("Failed to create salt string: {:?}", e))?;

    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt_string.as_salt().as_bytes(),
            &mut key,
        )
        .map_err(|e| anyhow::anyhow!("Failed to derive key using Argon2: {:?}", e))?;
    Ok(key)
}

fn create_salt_string(salt: &[u8]) -> Result<SaltString> {
    SaltString::b64_encode(salt)
        .map_err(|e| anyhow::anyhow!("Failed to create salt string: {:?}", e))
}
