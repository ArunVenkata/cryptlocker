use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;


use std::path::{Path, PathBuf};

use crate::crypt::utils::{compress_folder, create_progress_bar, derive_key, sanitize_path};

pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let sanitized_input_path = sanitize_path(input_path)?;
    let sanitized_output_path = sanitize_path(output_path)?;
    let file_size = fs::metadata(input_path)?.len();
    let temp_path = sanitized_input_path.with_extension("cryptic.tmp");

    let mut input_file = File::open(input_path)?;
    let mut temp_file = File::create(&temp_path)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

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
        OsRng.fill_bytes(&mut nonce_bytes);
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

    #[cfg(unix)]
    {
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }


    fs::rename(&temp_path, &sanitized_output_path)?;
    println!("File encrypted successfully: {:?}", &sanitized_output_path);

    Ok(())
}

pub fn compress_and_encrypt_folder(folder_path: &Path, password: &str) -> Result<()> {
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
