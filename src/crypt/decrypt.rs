use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crate::crypt::utils::{create_progress_bar, derive_key, extract_folder, sanitize_path};

pub fn decrypt_and_extract_folder(encrypted_path: &Path, password: &str) -> Result<()> {
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

pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let temp_path: std::path::PathBuf = input_path.with_extension("decrypt.tmp");

    let sanitized_input_path = sanitize_path(input_path)?;
    let sanitized_output_path = sanitize_path(output_path)?;
    let mut input_file: File = File::open(&sanitized_input_path)?;
    let mut temp_file: File = File::create(&temp_path)?;

    let mut salt: [u8; 16] = [0u8; 16];
    input_file.read_exact(&mut salt)?;

    let key: [u8; 32] = derive_key(password, &salt)?;
    let cipher: aes_gcm::AesGcm<aes::Aes256, _, _> = Aes256Gcm::new((&key).into());

    let file_size: u64 = fs::metadata(&sanitized_input_path)?.len();
    let progress_bar: indicatif::ProgressBar = create_progress_bar(file_size);

    let mut nonce_bytes: [u8; 12] = [0u8; 12];

    while let Ok(_) = input_file.read_exact(&mut nonce_bytes) {
        let mut chunk_size_bytes: [u8; 4] = [0u8; 4];
        input_file.read_exact(&mut chunk_size_bytes)?;
        let encrypted_chunk_size: usize = u32::from_le_bytes(chunk_size_bytes) as usize;

        let mut encrypted_chunk: Vec<u8> = vec![0u8; encrypted_chunk_size];
        input_file.read_exact(&mut encrypted_chunk)?;

        let nonce: &aes::cipher::generic_array::GenericArray<u8, _> = Nonce::from_slice(&nonce_bytes);

        let decrypted_chunk: Vec<u8> = cipher
            .decrypt(nonce, encrypted_chunk.as_ref())
            .map_err(|e: aes_gcm::Error| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        temp_file.write_all(&decrypted_chunk)?;
        progress_bar.inc(decrypted_chunk.len() as u64);
    }
    progress_bar.finish_with_message("Decryption complete!");

    fs::rename(&temp_path, &sanitized_output_path)?;

    println!("File decrypted successfully: {:?}", &sanitized_output_path);
    Ok(())
}
