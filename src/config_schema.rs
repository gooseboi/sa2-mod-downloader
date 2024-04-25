use camino::Utf8Path;
use color_eyre::{eyre::WrapErr as _, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::{
    fs,
    io::{AsyncReadExt as _, BufReader},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "ConfigSchema")]
struct UnresolvedConfig {
    #[serde(rename = "Groups")]
    pub groups: UnresolvedGroups,
    #[serde(rename = "Enums")]
    pub enums: Option<UnresolvedEnums>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnresolvedGroups {
    #[serde(rename = "Group")]
    pub groups: Vec<UnresolvedGroup>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnresolvedEnums {
    #[serde(rename = "Enum")]
    pub en: Vec<UnresolvedEnum>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnresolvedGroup {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@display")]
    display_name: Option<String>,
    #[serde(rename = "Property")]
    properties: Vec<UnresolvedProperty>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnresolvedEnum {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "EnumMember")]
    members: Vec<UnresolvedEnumMember>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnresolvedEnumMember {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@display")]
    display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnresolvedProperty {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@display")]
    display_name: String,
    #[serde(rename = "@type")]
    ty: String,
    #[serde(rename = "@defaultvalue")]
    default: String,
    #[serde(rename = "HelpText")]
    help_text: Option<String>,
}

#[derive(Debug)]
pub struct Config {
    pub groups: Vec<Group>,
}

#[derive(Debug)]
pub struct Group {
    pub name: String,
    pub display_name: Option<String>,
    pub properties: Vec<Property>,
}

#[derive(Clone, Debug)]
pub enum PropertyType {
    Bool,
    ValueSet {
        name: String,
        values: HashSet<(Option<String>, String)>,
    },
}

#[derive(Debug)]
pub struct Property {
    pub name: String,
    pub display_name: String,
    pub ty: PropertyType,
    pub default_value: String,
}

pub async fn parse(mod_path: &Utf8Path) -> Result<Option<Config>> {
    let schema_path = mod_path.join("configschema.xml");

    if !schema_path.exists() {
        return Ok(None);
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(schema_path)
        .await
        .wrap_err("Failed opening config file")?;
    let mut file = BufReader::new(file);
    let mut s = String::new();
    file.read_to_string(&mut s)
        .await
        .wrap_err("Failed reading from file")?;

    let unresolved_config: UnresolvedConfig =
        quick_xml::de::from_str(&s).wrap_err("Failed reading xml from file")?;

    let enums: Vec<_> = unresolved_config
        .enums
        .map(|e| e.en)
        .unwrap_or_default()
        .into_iter()
        .map(|e| PropertyType::ValueSet {
            name: e.name,
            values: e
                .members
                .into_iter()
                .map(|e| (e.display_name, e.name))
                .collect(),
        })
        .collect();
    let groups = unresolved_config
        .groups
        .groups
        .into_iter()
        .map(|g| Group {
            name: g.name,
            display_name: g.display_name,
            properties: g
                .properties
                .into_iter()
                .map(|p| Property {
                    name: p.name,
                    display_name: p.display_name,
                    ty: match p.ty.as_str() {
                        "bool" => PropertyType::Bool,
                        ty => enums
                            .iter()
                            .find(|e| {
                                let PropertyType::ValueSet { name, .. } = e else {
                                    unreachable!()
                                };
                                ty == name
                            })
                            .unwrap_or_else(|| panic!("Failed to find type {ty} in enums"))
                            .clone(),
                    },
                    default_value: p.default,
                })
                .collect(),
        })
        .collect();
    let config = Config { groups };
    Ok(Some(config))
}
