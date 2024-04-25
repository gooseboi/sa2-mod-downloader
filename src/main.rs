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
    eyre::{ContextCompat, WrapErr},
    Result,
};
use crossterm::style::Stylize;
use tokio::{fs, io::AsyncReadExt as _};

mod config_schema;
mod download;
mod modfile;
mod utils;
use modfile::{Mod, ModList, OptMap};
use reqwest_middleware::ClientWithMiddleware;

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

fn generate_ini_config(
    mod_path: &Utf8Path,
    config_schema: &config_schema::Config,
    opts: &OptMap,
) -> Result<()> {
    let ini_path = mod_path.join("config.ini");

    let mut ini = ini::Ini::new();

    // There is only one group, os the config for the group
    // can be picked up from mod.opts, or mod.opts.{group.name}
    // let mut written_keys = HashSet::new();
    if let [group] = &config_schema.groups[..] {
        let name = &group.name;
        let ini_section_name = if name.is_empty() { None } else { Some(name) };
        if let Some(opts) = opts.get(name) {
            for (key, val) in opts {
                let mut ini_section = ini.with_section(ini_section_name);
                ini_section.set(key, val.clone());
            }
        }
        for property in &group.properties {
            let mut ini_section = ini.with_section(ini_section_name);
            if ini_section.get(&property.name).is_some() {
                continue;
            }
            let mut ini_section = ini.with_section(ini_section_name);
            ini_section.set(&property.name, &property.default_value);
        }
    }
    println!("{ini:#?}");

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

async fn setup(cli: &Cli) -> Result<(ClientWithMiddleware, ModList, Utf8PathBuf)> {
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

    Ok((client, list, cache_dir))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (client, modlist, cache_dir) = setup(&cli).await.wrap_err("Failed setting up")?;

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
