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
use std::{collections::HashMap, io::Write as _};
use tokio::{fs, io::AsyncWriteExt};
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

fn get_file_extension(bytes: &[u8]) -> Option<String> {
    if bytes[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        Some("7z".to_owned())
    } else if (bytes[0..3] == [0x50, 0x4B, 0x03])
        && (bytes[3] == 0x04 || bytes[3] == 0x06 || bytes[3] == 0x08)
    {
        Some("zip".to_owned())
    } else {
        None
    }
}

async fn download_file(
    client: &reqwest_middleware::ClientWithMiddleware,
    url: &Url,
    name: &str,
) -> Result<(String, Vec<u8>)> {
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
    pb.set_message(format!("Downloading {}", stylized_url));

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
        "Successfully download {} from {}",
        stylized_name, url
    ));

    let extension =
        get_file_extension(&bytes).wrap_err("Failed finding file extension for file")?;

    stdout
        .execute(SetForegroundColor(Color::Green))
        .wrap_err("Failed setting color")?;
    print!("Successfully downloaded file for {}: ", stylized_name);
    stdout
        .execute(ResetColor)
        .wrap_err("Failed setting color")?;
    println!(
        "url = {}, size = {}",
        url.as_str().italic().cyan(),
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
    hasher.update(&bytes);
    let computed_hash = hasher.finalize();
    let computed_hash = format!("{computed_hash:016x}");
    if hash != &computed_hash {
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
    } else {
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
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let file = fs::read_to_string(cli.input_file)
        .await
        .wrap_err("Failed to read file")?;
    let list: ModList = toml::from_str(&file).wrap_err("Failed to parse from toml")?;

    let output_path = cli.output;
    match fs::metadata(&output_path).await {
        Ok(_) => fs::remove_dir_all(&output_path)
            .await
            .wrap_err("Failed to clear output path")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => Err(e).wrap_err("Failed to get metadata for output path")?,
    }
    fs::create_dir_all(&output_path)
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
        println!(
            "Downloading mod file for {stylized_name}, url = {}",
            stylized_url,
        );

        let (file_ext, bytes) = download_file(&client, &url, &name)
            .await
            .wrap_err("Failed downloading file")?;

        if !validate_file_hash(&bytes, &hash, &stylized_name)
            .wrap_err("Failed verifying the file hash")?
        {
            eprintln!("Skipping");
            continue;
        }

        let mod_name;
        match file_ext.as_str() {
            "zip" => {
                // TODO: spawn_blocking?
                let bytes = std::io::Cursor::new(&bytes);
                let mut zip_archive =
                    zip::ZipArchive::new(bytes).wrap_err("Failed opening zipfile")?;

                let mut top_level_dir = None;
                for i in 0..zip_archive.len() {
                    let file = zip_archive.by_index(i)?;
                    let p = Utf8Path::new(file.name());
                    if file.is_dir() && p.components().count() == 1 {
                        top_level_dir = Some(p.to_path_buf());
                        break;
                    }
                }

                let top_level_dir = top_level_dir.wrap_err("No top level directory in zip file")?;
                let ini_path = top_level_dir.join("mod.ini");

                let mut mod_ini = zip_archive
                    .by_name(&ini_path.to_string())
                    .wrap_err("Failed loading mod ini")?;
                let mod_ini = ini::Ini::read_from(&mut mod_ini)
                    .wrap_err("Failed reading data from mod ini")?;
                mod_name = mod_ini
                    .general_section()
                    .get("Name")
                    .wrap_err("ini file had no name property")?
                    .to_owned();
            }
            "7z" => {
                let t = tempfile::tempdir().wrap_err("Failed creating a temporary directory")?;
                let temp_path = Utf8Path::from_path(t.path()).expect("temp path should be utf-8");
                let bytes = std::io::Cursor::new(&bytes);
                sevenz_rust::decompress(bytes, t.path())
                    .wrap_err("Failed extracting 7z archive")?;

                let Some(top_level_dir) = temp_path
                    .read_dir_utf8()
                    .wrap_err("Failed reading temp directory contents")?
                    .next()
                else {
                    bail!("there should be a top level dir in the 7z archive");
                };

                let top_level_dir = top_level_dir
                    .wrap_err("Failed reading directory entry")?
                    .path()
                    .to_path_buf();
                let ini_path = top_level_dir.join("mod.ini");
                let mut mod_ini = std::fs::OpenOptions::new()
                    .read(true)
                    .open(ini_path)
                    .wrap_err("Failed opening mod ini")?;
                let mod_ini = ini::Ini::read_from(&mut mod_ini)
                    .wrap_err("Failed reading data from mod ini")?;
                mod_name = mod_ini
                    .general_section()
                    .get("Name")
                    .wrap_err("ini file had no name property")?
                    .to_owned();
            }
            _ => bail!("Unknown file type {file_ext}"),
        }

        let fname = output_path.join(mod_name).with_extension(file_ext);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&fname)
            .await
            .wrap_err_with(|| format!("Failed opening output file for {name}"))?;
        println!("Writing file for {stylized_name} to {fname}");
        file.write_all(&bytes)
            .await
            .wrap_err("Failed writing response to file")?;
        println!("Wrote file for {stylized_name}");
        println!();
    }

    Ok(())
}
