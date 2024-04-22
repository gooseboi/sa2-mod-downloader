#![deny(
    clippy::enum_glob_use,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used
)]

use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use color_eyre::{
    eyre::{bail, ContextCompat, WrapErr},
    Result,
};
use crossterm::{
    style::{Color, ResetColor, SetForegroundColor, Stylize},
    ExecutableCommand as _,
};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
};
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
struct Mod {
    // Unused, just to tell mods apart
    name: String,
    // Url that returns the mod zipfile
    url: Url,
    // Hash of the downloaded zipfile
    hash: String,
    // Options to change inside the mod file
    opts: Option<HashMap<String, toml::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ModList {
    mods: Vec<Mod>,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input file to download mods with
    input_file: Utf8PathBuf,

    /// Output path to download the mods in
    #[arg(short, default_value_t = Utf8PathBuf::from("down"))]
    output: Utf8PathBuf,
}

#[derive(Debug)]
#[non_exhaustive]
enum ArchiveFileType {
    Zip,
    SevenZ,
}

#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn size_str(size: u64) -> String {
    const BYTE_SIZE: u64 = 1024;

    if size < BYTE_SIZE {
        format!("{size} B")
    } else if size < BYTE_SIZE.pow(2) {
        let size = (size as f64) / (BYTE_SIZE as f64).powi(1);
        format!("{size:.1} KiB")
    } else if size < BYTE_SIZE.pow(3) {
        let size = (size as f64) / (BYTE_SIZE as f64).powi(2);
        format!("{size:.1} MiB")
    } else if size < BYTE_SIZE.pow(4) {
        let size = (size as f64) / (BYTE_SIZE as f64).powi(3);
        format!("{size:.1} GiB")
    } else {
        "You really shouldn't be serving files that big with this tool...".to_owned()
    }
}

fn get_file_extension(bytes: &[u8]) -> Option<ArchiveFileType> {
    if bytes[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        Some(ArchiveFileType::SevenZ)
    } else if (bytes[0..3] == [0x50, 0x4B, 0x03])
        && (bytes[3] == 0x04 || bytes[3] == 0x06 || bytes[3] == 0x08)
    {
        Some(ArchiveFileType::Zip)
    } else {
        None
    }
}

async fn download_file(
    client: &reqwest_middleware::ClientWithMiddleware,
    url: &Url,
    name: &str,
) -> Result<(ArchiveFileType, Vec<u8>)> {
    let mut stdout = std::io::stdout();

    let stylized_name = name.italic().cyan();
    let stylized_url = url.as_str().italic().cyan();

    let res = client
        .get(url.clone())
        .send()
        .await
        .wrap_err("Failed requesting mod zipfile")?;

    let total_size = res
        .content_length()
        .context("Failed to get content length")?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .expect("indicatif template was not valid")
            .progress_chars("#>-"));
    pb.set_message(format!("Downloading {stylized_url}"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    let mut bytes = vec![];

    while let Some(item) = stream.next().await {
        let chunk = item.wrap_err("Failed downloading file")?;
        tokio::io::AsyncWriteExt::write_all(&mut bytes, &chunk)
            .await
            .wrap_err("Failed writing file contents to buffer")?;
        let new = std::cmp::min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    pb.finish_with_message(format!(
        "Successfully download {stylized_name} from {stylized_url}",
    ));

    let extension =
        get_file_extension(&bytes).wrap_err("Failed finding file extension for file")?;

    stdout
        .execute(SetForegroundColor(Color::Green))
        .wrap_err("Failed setting color")?;
    print!("Successfully downloaded file for {stylized_name}: ");
    stdout
        .execute(ResetColor)
        .wrap_err("Failed setting color")?;
    println!(
        "url = {}, size = {}",
        stylized_url,
        size_str(bytes.len() as u64).italic().cyan()
    );

    Ok((extension, bytes))
}

fn validate_file_hash(
    bytes: &[u8],
    hash: &str,
    stylized_name: &crossterm::style::StyledContent<String>,
) -> Result<bool> {
    let mut stdout = std::io::stdout();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let computed_hash = hasher.finalize();
    let computed_hash = format!("{computed_hash:016x}");
    if hash == computed_hash {
        stdout
            .execute(SetForegroundColor(Color::Green))
            .wrap_err("Failed setting color")?;
        print!("Hash validation for ");
        print!("{stylized_name} ");
        stdout
            .execute(SetForegroundColor(Color::Green))
            .wrap_err("Failed setting color")?;
        println!("succeeded");
        stdout
            .execute(ResetColor)
            .wrap_err("Failed setting color")?;
        Ok(true)
    } else {
        let mut stderr = std::io::stderr();
        crossterm::queue!(
            stderr,
            SetForegroundColor(Color::Red),
            crossterm::style::Print(format!("Computed hash for {stylized_name} ")),
            SetForegroundColor(Color::Red),
            crossterm::style::Print("did not match"),
            ResetColor
        )
        .wrap_err("Failed printing hash error")?;
        stderr.flush().wrap_err("Failed flushing stderr")?;
        eprintln!(
            "Expected {}, found {}",
            hash.bold().magenta(),
            computed_hash.bold().magenta()
        );
        Ok(false)
    }
}

fn extract_mod(file_type: &ArchiveFileType, bytes: &[u8]) -> Result<tempfile::TempDir> {
    let tempdir = tempfile::tempdir().wrap_err("Failed creating temporary directory")?;
    let temp_path = Utf8Path::from_path(tempdir.path()).wrap_err("temp path was not UTF-8")?;
    match file_type {
        ArchiveFileType::Zip => {
            let bytes = std::io::Cursor::new(&bytes);
            let mut zip_archive = zip::ZipArchive::new(bytes).wrap_err("Failed opening zipfile")?;

            for i in 0..zip_archive.len() {
                let mut zip_file = zip_archive.by_index(i)?;
                let file_path = temp_path.join(zip_file.name());
                if zip_file.is_dir() {
                    fs::create_dir_all(file_path)
                        .wrap_err("Failed creating directory in temp directory")?;
                } else if zip_file.is_file() {
                    let mut file = fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(file_path)
                        .wrap_err("Failed opening file in temp directory")?;
                    let mut bytes = vec![];
                    zip_file
                        .read_to_end(&mut bytes)
                        .wrap_err("Failed reading from zip file")?;
                    file.write_all(&bytes)
                        .wrap_err("Failed writing file to temp directory")?;
                }
            }
        }
        ArchiveFileType::SevenZ => {
            let bytes = std::io::Cursor::new(&bytes);
            sevenz_rust::decompress(bytes, temp_path).wrap_err("Failed extracting 7z archive")?;
        }
    }

    let entries: Result<Vec<_>, std::io::Error> = fs::read_dir(temp_path)
        .wrap_err("Failed reading directory")?
        .collect();
    let entries = entries.wrap_err("Failed reading directory entries")?;
    match entries.len() {
        0 => bail!("Empty archive file"),
        1 => {
            if entries[0]
                .metadata()
                .wrap_err("Failed statting entry")?
                .is_dir()
            {
                let tempdir =
                    tempfile::tempdir().wrap_err("Failed creating temporary directory")?;
                let temp_path =
                    Utf8Path::from_path(tempdir.path()).wrap_err("temp path was not UTF-8")?;

                for entry in entries[0]
                    .path()
                    .read_dir()
                    .wrap_err("Failed reading directory")?
                {
                    let entry = entry.wrap_err("Failed reading directory entry")?;
                    let old_path = entry.path();
                    let old_path =
                        Utf8Path::from_path(&old_path).wrap_err("File's path was not UTF-8")?;
                    let file_name = old_path
                        .file_name()
                        .wrap_err("Cannot move file without a name")?;
                    let new_path = temp_path.join(file_name);
                    fs::rename(entry.path(), new_path)
                        .wrap_err("Failed moving file to new temp folder")?;
                }

                Ok(tempdir)
            } else {
                bail!("Invalid mod directory layout, only one file inside");
            }
        }
        _ => {
            if entries.into_iter().any(|e| e.file_name() == "mod.ini") {
                bail!("Invalid mod, no mod.ini");
            } else {
                Ok(tempdir)
            }
        }
    }
}

fn get_mod_name(path: &Utf8Path) -> Result<String> {
    let ini_path = path.join("mod.ini");

    let mut mod_ini = fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(ini_path)
        .wrap_err("Failed loading mod ini")?;
    let mod_ini = ini::Ini::read_from(&mut mod_ini).wrap_err("Failed reading data from mod ini")?;
    Ok(mod_ini
        .general_section()
        .get("Name")
        .wrap_err("ini file had no name property")?
        .to_owned())
}

fn _write_output(
    output_path: &Utf8Path,
    mod_name: &str,
    _mod_path: &Utf8Path,
    file_ext: &str,
) -> Result<()> {
    let _stylized_name = mod_name.italic().cyan();

    let fname = output_path.join(mod_name).with_extension(file_ext);
    let _file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(fname)
        .wrap_err_with(|| format!("Failed opening output file for {mod_name}"))?;

    todo!()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let file = tokio::fs::read_to_string(cli.input_file)
        .await
        .wrap_err("Failed to read file")?;
    let list: ModList = toml::from_str(&file).wrap_err("Failed to parse from toml")?;

    let output_path = cli.output;
    match tokio::fs::metadata(&output_path).await {
        Ok(_) => tokio::fs::remove_dir_all(&output_path)
            .await
            .wrap_err("Failed to clear output path")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => Err(e).wrap_err("Failed to get metadata for output path")?,
    }
    tokio::fs::create_dir_all(&output_path)
        .await
        .wrap_err("Failed creating output directory")?;

    let retry_policy =
        reqwest_retry::policies::ExponentialBackoff::builder().build_with_max_retries(3);
    let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(reqwest_retry::RetryTransientMiddleware::new_with_policy(
            retry_policy,
        ))
        .build();

    for Mod {
        url, name, hash, ..
    } in &list.mods
    {
        let stylized_name = name.clone().italic().cyan();
        let stylized_url = url.as_str().italic().cyan();
        println!("Downloading mod file for {stylized_name}, url = {stylized_url}",);

        let (file_ext, bytes) = download_file(&client, url, name)
            .await
            .wrap_err("Failed downloading file")?;

        if !validate_file_hash(&bytes, hash, &stylized_name)
            .wrap_err("Failed verifying the file hash")?
        {
            eprintln!("Skipping");
            continue;
        }

        let mod_dir = extract_mod(&file_ext, &bytes).wrap_err("Failed extracting mod files")?;
        let mod_path = Utf8Path::from_path(mod_dir.path()).wrap_err("Temp dir was not UTF-8")?;

        let mod_name = get_mod_name(mod_path).wrap_err("Failed getting mod name")?;

        println!();
    }

    Ok(())
}
