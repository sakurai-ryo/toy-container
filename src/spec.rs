use crate::errors::Errcode;

use log::error;
use serde;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    pub hostname: String,
    pub mounts: Vec<Mount>,
    pub linux: Linux,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    pub terminal: bool,
    pub user: User,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub capabilities: Capabilities,
    pub rlimits: Vec<Rlimit>,
    pub no_new_privileges: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: i64,
    pub gid: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub ambient: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub type_field: String,
    pub hard: i64,
    pub soft: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub path: String,
    pub readonly: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub source: String,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    pub resources: Resources,
    pub namespaces: Vec<Namespace>,
    pub masked_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    pub devices: Vec<Device>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub allow: bool,
    pub access: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Namespace {
    #[serde(rename = "type")]
    pub type_field: String,
}

pub fn load_spec(bundle_path: PathBuf) -> Result<Spec, Errcode> {
    let content = match fs::read_to_string(bundle_path) {
        Ok(c) => Ok(c),
        Err(_) => Err(Errcode::ArgumentInvalid("bundle")),
    }?;

    match serde_json::from_str(content.as_str()) {
        Ok(spec) => Ok(spec),
        Err(_) => Err(Errcode::ArgumentInvalid("bundle")),
    }

    // fs::read_to_string(bundle_path)
    //     .map_err(|_| Err(Errcode::ArgumentInvalid("bundle")))
    //     .and_then(|content: String| serde_json::from_str(content.as_str()))
    //     .unwrap_or(Err(Errcode::ArgumentInvalid("bundle")))
}

// TODO: 実装(https://github.com/opencontainers/runc/blob/526d3b33742eaf502d8bf156ca794aae58ade8c7/utils_linux.go#L312)
pub fn validate_process_spec(spec: &Spec) -> Result<(), Errcode> {
    Ok(())
}
