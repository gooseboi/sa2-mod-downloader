#![deny(
    clippy::enum_glob_use,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used
)]

use camino::Utf8PathBuf;
use clap::Parser;
use color_eyre::{
    eyre::{ContextCompat, WrapErr},
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

    let extension = {
        match res.headers().get("Content-Type") {
            Some(content_type) => {
                let content_type = std::str::from_utf8(content_type.as_bytes())
                    .wrap_err("Content type was not UTF-8")?;
                match content_type {
                    "application/zip" => "zip",
                    "application/x-7z-compressed" => "7z",
                    _ => bail!("Unsupported content type {content_type}"),
                }
                .to_owned()
            }
            None => {
                lazy_static::lazy_static! {
                    static ref CONTENT_DISPOSITION_RE: regex::Regex = regex::Regex::new(r"...").expect("Regex is valid");
                };

                let disposition = res
                    .headers()
                    .get("Content-Disposition")
                    .wrap_err("Failed to get content filename")?
                    .as_bytes();
                let disposition = std::str::from_utf8(disposition)
                    .wrap_err("Content disposition was not UTF-8")?;
                disposition.find("filename=");

                todo!()
            }
        }
    };

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
        let mut stdout = std::io::stdout();
        println!(
            "Downloading mod file for {stylized_name}, url = {}",
            stylized_url,
        );

        let (file_ext, bytes) = download_file(&client, &url, &name)
            .await
            .wrap_err("Failed downloading file")?;

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
            ).wrap_err("Failed printing hash error")?;
            stderr.flush().wrap_err("Failed flushing stderr")?;
            eprintln!(
                "Expected {}, found {}",
                hash.clone().bold().magenta(),
                computed_hash.bold().magenta()
            );
            eprintln!("Skipping...");
            continue;
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
        }

        let fname = output_path.join(name).with_extension(file_ext);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(fname)
            .await
            .wrap_err_with(|| format!("Failed opening output file for {name}"))?;
        println!("Writing file for {name}");
        file.write_all(&bytes)
            .await
            .wrap_err("Failed writing response to file")?;
        println!("Wrote file for {name}");
        println!();
    }

    Ok(())
}
