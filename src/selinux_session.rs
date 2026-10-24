//! P11: process-local protected-session state, fixed at startup.

use std::env;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context};
use niri_config::misc::{Environment, EnvironmentVariable};

pub struct Session {
    pub libinput_plugins: Vec<PathBuf>,
}

static SESSION: OnceLock<Session> = OnceLock::new();

pub fn get() -> Option<&'static Session> {
    SESSION.get()
}

fn compositor_context(context: &str) -> bool {
    let fields: Vec<_> = context.trim_matches(['\0', '\n']).splitn(4, ':').collect();
    fields.len() == 4
        && !fields[0].is_empty()
        && !fields[1].is_empty()
        && fields[2] == "niri_t"
        && !fields[3].is_empty()
}

fn store_path(path: &Path) -> anyhow::Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {path:?}"))?;
    if !path.starts_with("/nix/store") || path == Path::new("/nix/store") {
        bail!("protected-session path must resolve inside /nix/store: {path:?}");
    }
    Ok(path)
}

pub fn initialize(plugins: &[PathBuf]) -> anyhow::Result<()> {
    let context = std::fs::read_to_string("/proc/self/attr/current")
        .context("cannot query the protected compositor context")?;
    if !compositor_context(&context) {
        bail!("--selinux-session requires the niri_t process context");
    }
    // The entry fixes these paths before exec, including when debugging a
    // permissive policy. User layer/config directories are never searched.
    for name in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "VK_LAYER_PATH",
        "VK_IMPLICIT_LAYER_PATH",
    ] {
        let value = env::var_os(name).with_context(|| format!("missing fixed {name}"))?;
        store_path(Path::new(&value))?;
    }
    let libinput_plugins = plugins
        .iter()
        .map(|path| store_path(path))
        .collect::<anyhow::Result<_>>()?;
    SESSION
        .set(Session { libinput_plugins })
        .map_err(|_| anyhow::anyhow!("session already initialized"))
}

pub fn restore_child_directories(environment: &mut Environment) {
    // Applications run in the ordinary domain and use their own settings.
    for name in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "VK_LAYER_PATH",
        "VK_IMPLICIT_LAYER_PATH",
    ] {
        if !environment.0.iter().any(|variable| variable.name == name) {
            environment.0.push(EnvironmentVariable {
                name: name.into(),
                value: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p11_only_the_kernel_compositor_type_is_accepted() {
        assert!(compositor_context(
            "unconfined_u:unconfined_r:niri_t:s0-s0:c0.c1023\0"
        ));
        for context in [
            "unconfined",
            "",
            "u:r:unconfined_t:s0",
            "u:r:niri_t_extra:s0",
            "u:r:niri_t:",
        ] {
            assert!(!compositor_context(context));
        }
    }

    #[test]
    fn p11_child_directories_are_separate_from_compositor_search_paths() {
        let mut environment = Environment::default();
        restore_child_directories(&mut environment);
        assert_eq!(environment.0.len(), 4);
        assert!(environment
            .0
            .iter()
            .all(|variable| variable.value.is_none()));
    }

    #[test]
    fn p11_user_plugin_path_is_refused() {
        assert!(store_path(Path::new("/tmp")).is_err());
    }
}
