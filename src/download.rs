use camino::Utf8Path;
use color_eyre::{
    eyre::{bail, ContextCompat as _, WrapErr as _},
    Result,
};
use crossterm::{
    style::{Color, ResetColor, SetForegroundColor, Stylize as _},
    ExecutableCommand as _,
};
use futures_util::StreamExt as _;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest_middleware::ClientWithMiddleware;
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    sync::Arc,
};
use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};
use url::Url;

use crate::modfile::{Mod, Override};
use crate::utils::{sha256_hash, size_str};

pub async fn get_file_and_validate(
    client: &ClientWithMiddleware,
    m: &Mod,
    cache_dir: &Utf8Path,
) -> Result<Option<tempfile::TempDir>> {
    let name = &m.name;
    let url = &m.url;
    let stylized_name = name.clone().italic().cyan();

    let (file_ext, bytes, is_local) = download_file(client, &m.url, &m.name, cache_dir)
        .await
        .wrap_err("Failed downloading file")?;

    if !validate_file_hash(&bytes, &m.hash, &stylized_name)
        .wrap_err("Failed verifying the file hash")?
    {
        if is_local {
            todo!("Invalidate cache after bad local file");
        }
        eprintln!("Skipping");
        println!();
        println!();
    }

    if !is_local {
        add_file_to_cache(cache_dir, url, &bytes)
            .await
            .wrap_err_with(|| format!("Failed adding mod for url {url} into cache"))?;
    }

    let mod_dir = extract_mod(&file_ext, &bytes)
        .await
        .wrap_err("Failed extracting mod files")?;
    let mod_path = Utf8Path::from_path(mod_dir.path()).wrap_err("Temp dir was not UTF-8")?;

    if validate_manifest(name, mod_path, &m.overrides)
        .await
        .wrap_err("Failed validating mod manifest")?
    {
        Ok(Some(mod_dir))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
#[non_exhaustive]
enum ArchiveFileType {
    Zip,
    SevenZ,
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
    client: &ClientWithMiddleware,
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

async fn normalise_extracted_mod(tempdir: tempfile::TempDir) -> Result<tempfile::TempDir> {
    let temp_path = Utf8Path::from_path(tempdir.path()).wrap_err("Tempdir path is not UTF-8")?;
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

    match entries.len() {
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
    }
}

async fn extract_mod(file_type: &ArchiveFileType, bytes: &[u8]) -> Result<tempfile::TempDir> {
    let tempdir = tempfile::tempdir().wrap_err("Failed creating temporary directory")?;
    let temp_path = Utf8Path::from_path(tempdir.path()).wrap_err("temp path was not UTF-8")?;
    println!("Extracting files from archive");
    match file_type {
        ArchiveFileType::Zip => {
            let bytes = std::io::Cursor::new(bytes.to_vec());
            let zip_archive = zip::ZipArchive::new(bytes).wrap_err("Failed opening zipfile")?;

            #[allow(clippy::items_after_statements)]
            fn extract_zipfile(
                mut zip_archive: zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
                temp_path: &Utf8Path,
            ) -> Result<()> {
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
                        std::fs::create_dir_all(containing_dir)
                            .wrap_err("Failed creating directory in temp directory")?;
                    }

                    let full_path = temp_path.join(rel_path);
                    if zip_file.is_dir() {
                        std::fs::create_dir_all(full_path)
                            .wrap_err("Failed creating directory in temp directory")?;
                    } else if zip_file.is_file() {
                        let mut file = std::fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(full_path)
                            .wrap_err("Failed opening file in temp directory")?;
                        let mut bytes = vec![];
                        zip_file
                            .read_to_end(&mut bytes)
                            .wrap_err("Failed reading from zip file")?;
                        file.write_all(&bytes)
                            .wrap_err("Failed writing file to temp directory")?;
                    }
                }
                println!();
                Ok(())
            }

            let temp_path = temp_path.to_path_buf();
            tokio::task::spawn_blocking(move || extract_zipfile(zip_archive, &temp_path))
                .await
                .wrap_err("Failed joining task")?
                .wrap_err("Error when extracting zip archive")?;
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
                    i += 1;
                    sevenz_rust::default_entry_extract_fn(entry, reader, dest)
                },
            )
            .wrap_err("Failed extracting 7z archive")?;
            println!();
        }
    }

    let tempdir = normalise_extracted_mod(tempdir)
        .await
        .wrap_err("Failed normalising mod directory layout")?;

    println!("Finished extracting archive");

    Ok(tempdir)
}

enum ValidationResult {
    Success,
    Failure {
        name: String,
        expected_and_computed_hash: Option<(String, String)>,
        expected_and_computed_bytes: Option<(usize, usize)>,
    },
}

async fn validate_file_from_manifest(
    mod_path: &Utf8Path,
    line: &str,
    overrides: &HashMap<String, Override>,
) -> Result<ValidationResult> {
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

    let (hash, byte_count) = if let Some(Override { hash, bytes }) = overrides.get(&name) {
        (hash.to_owned(), *bytes)
    } else {
        (hash.to_owned(), byte_count)
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
    if computed_hash == hash {
        Ok(ValidationResult::Success)
    } else {
        Ok(ValidationResult::Failure {
            name,
            expected_and_computed_hash: Some((hash.clone(), computed_hash)),
            expected_and_computed_bytes: None,
        })
    }
}

#[allow(clippy::too_many_lines)]
async fn validate_manifest(
    mod_name: &str,
    mod_path: &Utf8Path,
    overrides: &HashMap<String, Override>,
) -> Result<bool> {
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
    let overrides = Arc::new(overrides.clone());
    for line in lines {
        let mod_path = mod_path.to_path_buf();
        let line = line.to_owned();
        let overrides = Arc::clone(&overrides);
        tasks.spawn(async move { validate_file_from_manifest(&mod_path, &line, &overrides).await });
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
        i += 1;
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
        crossterm::style::Print("succeeded\n"),
        ResetColor
    )
    .wrap_err("Failed printing success message")?;
    stdout.flush().wrap_err("Failed flushing stdout")?;

    Ok(true)
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
