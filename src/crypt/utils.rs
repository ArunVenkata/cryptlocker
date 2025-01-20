use anyhow::{Context, Result};
use argon2::Argon2;
use indicatif::{ProgressBar, ProgressStyle};
use password_hash::SaltString;
use rpassword::prompt_password;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zip::{write::FileOptions, ZipWriter};

pub fn create_progress_bar(size: u64) -> ProgressBar {
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

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let salt_string = create_salt_string(salt)
        .map_err(|e| anyhow::anyhow!("Failed to create salt string: {:?}", e))?;

    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt_string.as_str().as_bytes(),
            &mut key,
        )
        .map_err(|e| anyhow::anyhow!("Failed to derive key using Argon2: {:?}", e))?;
    Ok(key)
}

pub fn create_salt_string(salt: &[u8]) -> Result<SaltString> {
    SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Failed to create salt string: {:?}", e))
}

pub fn compress_folder(folder_path: &Path, zip_path: &Path) -> Result<()> {
    let file = File::create(zip_path).context("Failed to create zip file")?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::<zip::write::ExtendedFileOptions>::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    for entry in WalkDir::new(folder_path) {
        let entry = entry?;
        let path = entry.path();
        let name = path.strip_prefix(folder_path)?;

        if path.is_file() {
            zip.start_file(name.to_str().unwrap(), options.clone())?;
            let mut file = File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
        } else if path.is_dir() {
            zip.add_directory(name.to_str().unwrap(), options.clone())?;
        }
    }

    zip.finish()?;
    Ok(())
}

pub fn extract_folder(zip_path: &Path, output_folder: &Path) -> Result<()> {
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

pub fn validate_password() -> Result<String> {
    let mut retries: i32 = 3;
    loop {
        if retries == 0 {
            println!("You have exceeded the maximum retries. Please try unlocking again.");
            break Err(anyhow::anyhow!("Password confirmation failed"));
        }
        let password = prompt_password("Password: ").context("Failed to read password")?;

        let confirm_password =
            prompt_password("Confirm Password: ").context("Failed to read password")?;

        if password == confirm_password {
            return Ok(password);
        } else {
            println!("Passwords do not match. Please try again.");
            retries -= 1;
        }
    }
}

pub fn read_and_confirm_password() -> Result<String> {
    let mut retries: i32 = 1;
    let strict_mode: bool = false;
    loop {
        let password = prompt_password("Password: ").context("Failed to read password")?;

        let confirm_password =
            prompt_password("Confirm Password: ").context("Failed to read password")?;

        if password == confirm_password {
            if !is_strong_password(&password) {
                println!("Password must be at least 8 characters long and contain a mix of letters, numbers, and special characters.\n");
                retries -= 1;
                if retries == 0 {
                    if strict_mode {
                        println!(
                            "You have exceeded the maximum retries. Please try locking/unlocking again."
                        );
                        break Err(anyhow::anyhow!("Password confirmation failed"));
                    } else {
                        let _ = confirm_yes_no(
                            "Are you sure you want to proceed with a weak password ?",
                        );
                    }
                } else {
                    continue;
                }
            }
            return Ok(password);
        } else {
            println!("Passwords do not match. Please try again.");
        }
    }
}

fn is_strong_password(password: &str) -> bool {
    password.len() >= 8
        && password.chars().any(|c| c.is_ascii_lowercase())
        && password.chars().any(|c| c.is_ascii_uppercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| !c.is_ascii_alphanumeric())
}

pub fn confirm_yes_no(message: &str) -> Result<()> {
    println!("{}", message);

    loop {
        print!("Do you want to proceed? (yes/no): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim().to_lowercase().as_str() {
            "y" => return Ok(()),
            "n" => return Err(anyhow::anyhow!("Operation cancelled by user")),
            "yes" => return Ok(()),
            "no" => return Err(anyhow::anyhow!("Operation cancelled by user")),
            _ => println!("Please enter 'yes' or 'y' or 'no' or 'n'."),
        }
    }
}

pub fn sanitize_path(path: &Path) -> Result<PathBuf> {
    let canonical_path = fs::canonicalize(path)?;
    if canonical_path.starts_with("/etc") || canonical_path.starts_with("/bin") {
        return Err(anyhow::anyhow!(
            "Operation not allowed on critical system paths"
        ));
    }
    Ok(canonical_path)
}
