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
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
};
use tokio::fs;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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
fn size_str(size: u64) -> String {
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

#[must_use]
fn sha256_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let computed_hash = hasher.finalize();
    format!("{computed_hash:016x}")
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

async fn get_file_from_cache(cache_dir: &Utf8Path, url: &Url) -> Result<Option<Vec<u8>>> {
    let encoded_url =
        percent_encoding::utf8_percent_encode(url.as_str(), percent_encoding::NON_ALPHANUMERIC)
            .collect::<String>();
    let file_path = cache_dir.join(encoded_url);
    if file_path.exists() {
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(file_path)
            .await
            .wrap_err("Failed opening cache file")?;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)
            .await
            .wrap_err("Failed reading file contents")?;
        Ok(Some(bytes))
    } else {
        Ok(None)
    }
}

async fn add_file_to_cache(cache_dir: &Utf8Path, url: &Url, bytes: &[u8]) -> Result<()> {
    let encoded_url =
        percent_encoding::utf8_percent_encode(url.as_str(), percent_encoding::NON_ALPHANUMERIC)
            .collect::<String>();
    let file_path = cache_dir.join(encoded_url);

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .truncate(true)
        .open(file_path)
        .await
        .wrap_err("Failed opening cache file for writing")?;

    file.write_all(bytes)
        .await
        .wrap_err("Failed writing content to cache file")?;

    Ok(())
}

async fn download_file(
    client: &reqwest_middleware::ClientWithMiddleware,
    url: &Url,
    name: &str,
    cache_dir: &Utf8Path,
) -> Result<(ArchiveFileType, Vec<u8>, bool)> {
    let mut stdout = std::io::stdout();

    let stylized_name = name.italic().cyan();
    let stylized_url = url.as_str().italic().cyan();

    if let Some(bytes) = get_file_from_cache(cache_dir, url)
        .await
        .wrap_err("Failed loading file from cache")?
    {
        let file_type =
            get_file_extension(&bytes).wrap_err("Failed finding file extension for file")?;
        crossterm::queue!(
            stdout,
            SetForegroundColor(Color::Green),
            crossterm::style::Print(format!("Using cache file for {stylized_name}: ")),
            crossterm::style::Print(format!(
                "url = {}, size = {}\n",
                stylized_url,
                size_str(bytes.len() as u64).italic().cyan()
            ))
        )
        .wrap_err("Failed writing success message")?;
        stdout.flush().wrap_err("Failed flushing stdout")?;
        return Ok((file_type, bytes, true));
    }

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

    let file_type =
        get_file_extension(&bytes).wrap_err("Failed finding file extension for file")?;

    crossterm::queue!(
        stdout,
        SetForegroundColor(Color::Green),
        crossterm::style::Print(format!("Successfully downloaded file for {stylized_name} ")),
        crossterm::style::Print(format!(
            "url = {}, size = {}\n",
            stylized_url,
            size_str(bytes.len() as u64).italic().cyan()
        ))
    )
    .wrap_err("Failed writing success message")?;
    stdout.flush().wrap_err("Failed flushing stdout")?;

    Ok((file_type, bytes, false))
}

fn validate_file_hash(
    bytes: &[u8],
    hash: &str,
    stylized_name: &crossterm::style::StyledContent<String>,
) -> Result<bool> {
    let mut stdout = std::io::stdout();
    let computed_hash = sha256_hash(bytes);
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

async fn extract_mod(file_type: &ArchiveFileType, bytes: &[u8]) -> Result<tempfile::TempDir> {
    let tempdir = tempfile::tempdir().wrap_err("Failed creating temporary directory")?;
    let temp_path = Utf8Path::from_path(tempdir.path()).wrap_err("temp path was not UTF-8")?;
    println!("Extracting files from archive");
    match file_type {
        ArchiveFileType::Zip => {
            let bytes = std::io::Cursor::new(&bytes);
            let mut zip_archive = zip::ZipArchive::new(bytes).wrap_err("Failed opening zipfile")?;

            let total = zip_archive.len();
            for i in 0..total {
                let mut stdout = std::io::stdout();
                stdout
                    .execute(crossterm::cursor::MoveToColumn(0))
                    .wrap_err("Failed moving cursor")?;
                print!("Extracting file {}/{}", i + 1, total);
                let mut zip_file = zip_archive.by_index(i)?;
                let rel_path = Utf8Path::new(zip_file.name());
                if let Some(containing_dir) = rel_path.parent() {
                    let containing_dir = temp_path.join(containing_dir);
                    fs::create_dir_all(containing_dir)
                        .await
                        .wrap_err("Failed creating directory in temp directory")?;
                }

                let full_path = temp_path.join(rel_path);
                if zip_file.is_dir() {
                    fs::create_dir_all(full_path)
                        .await
                        .wrap_err("Failed creating directory in temp directory")?;
                } else if zip_file.is_file() {
                    let mut file = fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(full_path)
                        .await
                        .wrap_err("Failed opening file in temp directory")?;
                    let mut bytes = vec![];
                    zip_file
                        .read_to_end(&mut bytes)
                        .wrap_err("Failed reading from zip file")?;
                    file.write_all(&bytes)
                        .await
                        .wrap_err("Failed writing file to temp directory")?;
                }
            }
            println!()
        }
        ArchiveFileType::SevenZ => {
            let total = {
                let total = bytes.len();
                let mut bytes = std::io::Cursor::new(&bytes);
                sevenz_rust::Archive::read(&mut bytes, total as u64, &[])
                    .wrap_err("Failed reading 7z archive")?
                    .files
                    .len()
            };
            let bytes = std::io::Cursor::new(&bytes);
            let mut i = 1;
            let mut stdout = std::io::stdout();
            sevenz_rust::decompress_with_extract_fn(
                bytes,
                temp_path,
                move |entry, reader, dest| {
                    stdout
                        .execute(crossterm::cursor::MoveToColumn(0))
                        .expect("Failed moving cursor");
                    print!("Extracting file {i}/{total}");
                    i = i + 1;
                    sevenz_rust::default_entry_extract_fn(entry, reader, dest)
                },
            )
            .wrap_err("Failed extracting 7z archive")?;
            println!()
        }
    }

    let mut it = fs::read_dir(temp_path)
        .await
        .wrap_err("Failed reading directory")?;

    let mut entries = vec![];
    while let Some(entry) = it
        .next_entry()
        .await
        .wrap_err("Failed to read item from directory")?
    {
        entries.push(entry);
    }

    let tempdir = match entries.len() {
        0 => bail!("Empty archive file"),
        1 if entries[0]
            .metadata()
            .await
            .wrap_err("Failed statting entry")?
            .is_dir() =>
        {
            let tempdir = tempfile::tempdir().wrap_err("Failed creating temporary directory")?;
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
                    .await
                    .wrap_err("Failed moving file to new temp folder")?;
            }

            Ok(tempdir)
        }
        1 => bail!("Invalid mod directory layout, only one file inside"),
        _ => {
            if entries.into_iter().any(|e| e.file_name() == "mod.ini") {
                bail!("Invalid mod, no mod.ini");
            } else {
                Ok(tempdir)
            }
        }
    };

    println!("Finished extracting archive");

    tempdir
}

async fn get_mod_name(path: &Utf8Path) -> Result<String> {
    let ini_path = path.join("mod.ini");

    let mut mod_ini = fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(ini_path)
        .await
        .wrap_err("Failed loading mod ini")?;
    let mut bytes = vec![];
    mod_ini
        .read_to_end(&mut bytes)
        .await
        .wrap_err("Failed reading data from mod.ini")?;
    let ini_task = tokio::task::spawn_blocking(move || {
        let mut bytes = std::io::Cursor::new(&bytes);
        ini::Ini::read_from(&mut bytes).wrap_err("Failed parsing mod.ini")
    });
    let mod_ini = ini_task.await.wrap_err("Failed awaiting task")??;
    Ok(mod_ini
        .general_section()
        .get("Name")
        .wrap_err("ini file had no name property")?
        .to_owned())
}

enum ValidationResult {
    Success,
    Failure {
        name: String,
        expected_and_computed_hash: Option<(String, String)>,
        expected_and_computed_bytes: Option<(usize, usize)>,
    },
}

async fn validate_file_from_manifest(mod_path: &Utf8Path, line: &str) -> Result<ValidationResult> {
    let mut it = line.split('\t');
    let Some(name) = it.next() else {
        bail!("Line {line} had no name field");
    };
    let name = name.replace('\\', "/");
    let Some(byte_count) = it.next() else {
        bail!("Line {line} had no bytes field");
    };
    let byte_count = byte_count
        .parse::<usize>()
        .wrap_err_with(|| format!("Byte count for {name} was not a number"))?;
    let Some(hash) = it.next() else {
        bail!("Line {line} had no hash field");
    };

    let file_path = mod_path.join(&name);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(file_path)
        .await
        .wrap_err_with(|| format!("Failed opening {name}"))?;
    let mut file_contents = vec![];
    file.read_to_end(&mut file_contents)
        .await
        .wrap_err_with(|| format!("Failed reading file contents for {name}"))?;

    if file_contents.len() != byte_count {
        return Ok(ValidationResult::Failure {
            name,
            expected_and_computed_hash: None,
            expected_and_computed_bytes: Some((byte_count, file_contents.len())),
        });
    }

    let hash_task = tokio::task::spawn_blocking(move || sha256_hash(&file_contents));
    let computed_hash = hash_task.await.wrap_err("Failed joining task")?;
    if computed_hash != hash {
        Ok(ValidationResult::Failure {
            name,
            expected_and_computed_hash: Some((hash.to_owned(), computed_hash)),
            expected_and_computed_bytes: None,
        })
    } else {
        Ok(ValidationResult::Success)
    }
}

async fn validate_manifest(mod_name: &str, mod_path: &Utf8Path) -> Result<bool> {
    let stylized_name = mod_name.italic().cyan();

    println!("Starting manifest validation");
    let manifest_path = mod_path.join("mod.manifest");
    if !manifest_path
        .try_exists()
        .wrap_err("Could not check if manifest exists")?
    {
        println!("Skipping because there is no manifest");
        return Ok(true);
    }

    let manifest = fs::read_to_string(manifest_path)
        .await
        .wrap_err("Failed reading from manifest file")?;
    let lines = manifest.lines();
    let mut tasks = tokio::task::JoinSet::new();
    for line in lines {
        let mod_path = mod_path.to_path_buf();
        let line = line.to_owned();
        tasks.spawn(async move { validate_file_from_manifest(&mod_path, &line).await });
    }
    let mut stderr = std::io::stderr();
    let total = tasks.len();
    let mut stdout = std::io::stdout();
    let mut i = 1;
    while let Some(result) = tasks.join_next().await {
        let result = result
            .wrap_err("Failed joining task")?
            .wrap_err("Failed validating file from manifest")?;
        stdout
            .execute(crossterm::cursor::MoveToColumn(0))
            .expect("Failed moving cursor");
        print!("Validated file {i}/{total}");
        i = i + 1;
        match result {
            ValidationResult::Success => {}
            ValidationResult::Failure {
                name,
                expected_and_computed_hash: None,
                expected_and_computed_bytes: Some((expected_bytes, computed_bytes)),
            } => {
                crossterm::queue!(
                    stderr,
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print(format!(
                        "Failed validating manifest for {stylized_name} at {name}: "
                    )),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print(format!(
                        "Expected {} ",
                        expected_bytes.to_string().bold().magenta()
                    )),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print("bytes, "),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print(format!(
                        "got {} ",
                        computed_bytes.to_string().bold().magenta()
                    )),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print("bytes\n"),
                    ResetColor
                )
                .wrap_err("Failed printing hash error")?;
                stderr.flush().wrap_err("Failed flushing stderr")?;
                return Ok(false);
            }
            ValidationResult::Failure {
                name,
                expected_and_computed_hash: Some((expected_hash, computed_hash)),
                expected_and_computed_bytes: None,
            } => {
                crossterm::queue!(
                    stderr,
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print(format!(
                        "Failed validating manifest for {stylized_name} at {name}: "
                    )),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print(format!(
                        "Expected {} ",
                        expected_hash.bold().magenta()
                    )),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print("as hash, "),
                    SetForegroundColor(Color::Red),
                    crossterm::style::Print(format!("got {} ", computed_hash.bold().magenta())),
                    crossterm::style::Print("as hash\n"),
                    SetForegroundColor(Color::Red),
                )
                .wrap_err("Failed printing hash error")?;
                stderr.flush().wrap_err("Failed flushing stderr")?;
                return Ok(false);
            }
            ValidationResult::Failure { .. } => unreachable!(),
        }
    }
    println!();

    let mut stdout = std::io::stdout();
    crossterm::queue!(
        stdout,
        SetForegroundColor(Color::Green),
        crossterm::style::Print(format!("Manifest validation for {stylized_name} ")),
        SetForegroundColor(Color::Green),
        crossterm::style::Print("succeeded"),
        ResetColor
    )
    .wrap_err("Failed printing success message")?;
    stdout.flush().wrap_err("Failed flushing stdout")?;

    Ok(true)
}

async fn _write_output(
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
        .await
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

    let cache_dir = std::env::var("XDG_CACHE_HOME").unwrap_or("~/.cache".to_owned());
    let cache_dir = Utf8PathBuf::from(cache_dir);
    let cache_dir = cache_dir.join("sa2_mod_downloader");

    tokio::fs::create_dir_all(&cache_dir)
        .await
        .wrap_err("Failed creating cache directory")?;

    let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(reqwest_retry::RetryTransientMiddleware::new_with_policy(
            reqwest_retry::policies::ExponentialBackoff::builder().build_with_max_retries(3),
        ))
        .build();

    let now = std::time::Instant::now();
    let mod_total = list.mods.len();
    for (
        i,
        Mod {
            url, name, hash, ..
        },
    ) in list.mods.iter().enumerate()
    {
        let stylized_name = name.clone().italic().cyan();
        let stylized_url = url.as_str().italic().cyan();
        let i = i + 1;
        println!(
            "Downloading mod file ({i}/{mod_total}) for {stylized_name}, url = {stylized_url}",
        );

        let (file_ext, bytes, is_local) = download_file(&client, url, name, &cache_dir)
            .await
            .wrap_err("Failed downloading file")?;

        if !validate_file_hash(&bytes, hash, &stylized_name)
            .wrap_err("Failed verifying the file hash")?
        {
            if is_local {
                todo!("Invalidate cache after bad local file");
            }
            eprintln!("Skipping");
            println!();
            println!();
            continue;
        }

        if !is_local {
            add_file_to_cache(&cache_dir, url, &bytes)
                .await
                .wrap_err_with(|| format!("Failed adding mod for url {url} into cache"))?;
        }

        let mod_dir = extract_mod(&file_ext, &bytes)
            .await
            .wrap_err("Failed extracting mod files")?;
        let mod_path = Utf8Path::from_path(mod_dir.path()).wrap_err("Temp dir was not UTF-8")?;

        if !validate_manifest(name, mod_path)
            .await
            .wrap_err("Failed validating mod manifest")?
        {
            eprintln!("Skipping");
            println!();
            println!();
            continue;
        }

        let mod_name = get_mod_name(mod_path)
            .await
            .wrap_err("Failed getting mod name")?;

        println!();
        println!();
    }

    let time = now.elapsed();
    println!(
        "Finished downloading all mods. Downloaded a total of {} mods in {} secs",
        list.mods.len(),
        time.as_secs_f64()
    );

    Ok(())
}
