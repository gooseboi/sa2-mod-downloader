use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Override {
    pub hash: String,
    pub bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OptMap {
    #[serde(flatten)]
    top_level: Option<HashMap<String, OptValue>>,
    #[serde(flatten)]
    nested: Option<HashMap<String, HashMap<String, OptValue>>>,
}

impl OptMap {
    pub fn get(&self, k: &impl AsRef<str>) -> Option<&HashMap<String, OptValue>> {
        let k = k.as_ref();
        if self.nested.is_none() || k.is_empty() {
            self.top_level.as_ref()
        } else {
            self.nested.as_ref().and_then(|n| n.get(k))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mod {
    // Unused, just to tell mods apart
    pub name: String,
    // Url that returns the mod zipfile
    pub url: Url,
    // Hash of the downloaded zipfile
    pub hash: String,
    // Options to change inside the mod file
    pub opts: Option<OptMap>,
    // Overrides for hashes or file sizes for mod.manifest
    #[serde(default)]
    pub overrides: HashMap<String, Override>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OptValue {
    Bool(bool),
    String(String),
}

impl Into<String> for OptValue {
    fn into(self) -> String {
        match self {
            OptValue::Bool(b) => b.to_string(),
            OptValue::String(s) => s,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModList {
    pub mods: Vec<Mod>,
}
