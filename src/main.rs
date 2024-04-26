#![feature(try_find)]
#![deny(
    clippy::enum_glob_use,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used
)]

use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use color_eyre::{
    eyre::{bail, ensure, ContextCompat, WrapErr},
    Result,
};
use crossterm::style::Stylize;
use tokio::{
    fs,
    io::{self, AsyncReadExt as _, AsyncWriteExt as _},
};

mod config_schema;
mod download;
mod modfile;
mod utils;
use crate::modfile::OptValue;
use modfile::{Mod, ModList, OptMap};
use reqwest_middleware::ClientWithMiddleware;
use std::collections::{HashMap, HashSet};
use utils::sha256_hash;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input file to download mods with
    input_file: Utf8PathBuf,

    /// Output path to download the mods in
    #[arg(short, default_value_t = Utf8PathBuf::from("down"))]
    output: Utf8PathBuf,
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

// TODO: Support writing a bunch of archive files instead of just copying the directories
// over
async fn write_output(output_path: &Utf8Path, mod_name: &str, mod_path: &Utf8Path) -> Result<()> {
    // TODO: What if it has an invalid character?
    let mod_output_path = output_path.join(mod_name);
    for f in walkdir::WalkDir::new(mod_path) {
        let f = f.wrap_err("Failed reading files in mod directory")?;
        let path = Utf8Path::from_path(f.path()).wrap_err("Path should be UTF-8")?;
        let relative_path = path
            .strip_prefix(mod_path)
            .wrap_err("Path should be a child of its parent")?;
        let output_relative_path = mod_output_path.join(relative_path);
        let parent = output_relative_path
            .parent()
            .wrap_err("Directory should have a parent")?;
        std::fs::create_dir_all(parent).wrap_err("Failed creating parent dir")?;
        if path.is_dir() {
            std::fs::create_dir_all(&output_relative_path)
                .wrap_err_with(|| format!("Failed creating directory {output_relative_path}"))?;
        } else if path.is_file() {
            let mut orig_file = fs::OpenOptions::new()
                .read(true)
                .open(path)
                .await
                .wrap_err("Failed opening original file")?;
            let mut new_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(output_relative_path)
                .await
                .wrap_err("Failed opening original file")?;
            io::copy(&mut orig_file, &mut new_file)
                .await
                .wrap_err("Failed copying contents to new file")?;
        } else {
            bail!("Path {path} was not a file nor a directory");
        }
    }

    Ok(())
}

fn is_valid_config(group: &config_schema::Group, opts: &HashMap<String, OptValue>) -> Result<()> {
    let name = &group.name;
    for (key, val) in opts {
        let Some(prop) = group.properties.iter().find(|p| p.name == *key) else {
            bail!("The option {key} was not in group {name}");
        };
        match prop.ty {
            config_schema::PropertyType::Bool => {
                ensure!(
                    matches!(val, OptValue::Bool(_)),
                    "Schema expected a bool for key {key}, did not get one"
                );
            }
            config_schema::PropertyType::ValueSet {
                name: _,
                ref values,
            } => {
                let OptValue::String(val) = val else {
                    bail!("Schema expected a string for key {key}, did not get one");
                };
                if !values.iter().any(|(display_name, name)| {
                    display_name.as_ref().is_some_and(|d| d == val) || name == val
                }) {
                    bail!("Schema expected a string of one of {values:#?}, found {val}");
                }
            }
        };
    }
    Ok(())
}

fn generate_ini_config(
    mod_path: &Utf8Path,
    config_schema: &config_schema::Config,
    opts: &OptMap,
) -> Result<()> {
    let ini_path = mod_path.join("config.ini");

    let mut ini = ini::Ini::new();

    for group in &config_schema.groups {
        let mut written_keys = HashSet::new();
        let name = &group.name;
        let ini_section_name = if name.is_empty() { None } else { Some(name) };
        if let Some(opts) = opts.get(name) {
            is_valid_config(group, opts).wrap_err("Failed validating config")?;
            for (key, val) in opts {
                let key = group
                    .get_option_name(key)
                    .wrap_err("Failed getting option name for key")?;
                let mut ini_section = ini.with_section(ini_section_name);
                ini_section.set(key, val.clone());
                if !written_keys.insert(key) {
                    bail!("Overrwritten key {key}, duplicate write to same key");
                }
            }
        }

        for property in &group.properties {
            let mut ini_section = ini.with_section(ini_section_name);
            if ini_section.get(&property.name).is_some() {
                continue;
            }
            if written_keys.contains(property.name.as_str()) {
                continue;
            }
            let mut ini_section = ini.with_section(ini_section_name);
            ini_section.set(&property.name, &property.default_value);
        }
    }

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(ini_path)
        .wrap_err("Failed opening config.ini")?;

    ini.write_to(&mut f)
        .wrap_err("Failed writing config.ini contents")?;

    Ok(())
}

async fn generate_manifest(mod_path: &Utf8Path) -> Result<()> {
    let mut output = String::new();
    for f in walkdir::WalkDir::new(mod_path) {
        let f = f.wrap_err("Failed reading file from directory")?;
        let path = Utf8Path::from_path(f.path()).wrap_err("Path should be UTF-8")?;
        let relative_path = path
            .strip_prefix(mod_path)
            .wrap_err("Path should be prefixed by mod path")?;
        if relative_path == "mod.manifest" {
            continue;
        }
        if path.is_dir() {
            continue;
        }
        let bytes = fs::read(path)
            .await
            .wrap_err("Failed reading bytes from file")?;
        let len = bytes.len();
        let hash = sha256_hash(&bytes);
        let line = format!("{relative_path}\t{len}\t{hash}\n");
        output.push_str(&line);
    }

    let manifest_path = mod_path.join("mod.manifest");
    let mut output_file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        // some don't include it
        .create(true)
        .open(manifest_path)
        .await
        .wrap_err("Failed opening mod.manifest")?;
    output_file
        .write_all(output.as_bytes())
        .await
        .wrap_err("Failed writing manifest to file")?;

    Ok(())
}

async fn setup(cli: &Cli) -> Result<(ClientWithMiddleware, ModList, Utf8PathBuf, Utf8PathBuf)> {
    let file = tokio::fs::read_to_string(&cli.input_file)
        .await
        .wrap_err("Failed to read file")?;
    let list: ModList = toml::from_str(&file).wrap_err("Failed to parse from toml")?;

    let output_path = &cli.output;
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

    let cache_dir = std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| "~/.cache".to_owned());
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

    Ok((client, list, cache_dir, output_path.clone()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (client, modlist, cache_dir, output_path) =
        setup(&cli).await.wrap_err("Failed setting up")?;

    let now = std::time::Instant::now();
    let mod_total = modlist.mods.len();
    for (
        i,
        m @ Mod {
            url, name, opts, ..
        },
    ) in modlist.mods.iter().enumerate()
    {
        let stylized_name = name.clone().italic().cyan();
        let stylized_url = url.as_str().italic().cyan();
        let i = i + 1;
        println!(
            "Downloading mod file ({i}/{mod_total}) for {stylized_name}, url = {stylized_url}",
        );

        let Some(mod_dir) = download::get_file_and_validate(&client, m, &cache_dir)
            .await
            .wrap_err("Failed downloading file")?
        else {
            eprintln!("Found an error when downloading the file!");
            eprintln!("Skipping");
            println!();
            println!();
            continue;
        };

        let mod_path = Utf8Path::from_path(mod_dir.path()).wrap_err("tmp path was not UTF-8")?;

        let mod_name = get_mod_name(mod_path)
            .await
            .wrap_err("Failed getting mod name")?;

        let config_schema = config_schema::parse(mod_path)
            .await
            .wrap_err("Failed getting config schema")?;

        if let (Some(config_schema), Some(opts)) = (config_schema, opts) {
            generate_ini_config(mod_path, &config_schema, opts)
                .wrap_err("Failed generating ini for mod")?;
        }

        generate_manifest(mod_path)
            .await
            .wrap_err("Failed generating manifest for mod")?;

        write_output(&output_path, &mod_name, mod_path)
            .await
            .wrap_err("Failed writing output to output path")?;

        println!();
        println!();
    }

    let time = now.elapsed();
    println!(
        "Finished downloading all mods. Downloaded a total of {} mods in {} secs",
        mod_total,
        time.as_secs_f64()
    );

    Ok(())
}
