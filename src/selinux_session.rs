//! P11: process-local protected-session state, fixed at startup.

use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::OnceLock;

use anyhow::{bail, Context};
use niri_config::misc::{Environment, EnvironmentVariable};

pub struct Session {
    pub libinput_plugins: Vec<PathBuf>,
    pub wayland_display: String,
    bridge: PathBuf,
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

fn listener_name(name: &str) -> bool {
    name.strip_prefix("wayland-")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_digit()))
}

pub fn initialize(plugins: &[PathBuf], bridge: &Path, wayland_display: &str) -> anyhow::Result<()> {
    let context = std::fs::read_to_string("/proc/self/attr/current")
        .context("cannot query the protected compositor context")?;
    if !compositor_context(&context) {
        bail!("--selinux-session requires the niri_t process context");
    }
    if !listener_name(wayland_display) {
        bail!("protected-session listener must be a fixed wayland-N name");
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
    journal_stderr()?;
    SESSION
        .set(Session {
            libinput_plugins,
            wayland_display: wayland_display.into(),
            bridge: store_path(bridge)?,
        })
        .map_err(|_| anyhow::anyhow!("session already initialized"))
}

#[cfg(feature = "systemd")]
fn journal_stderr() -> anyhow::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[link(name = "systemd")]
    unsafe extern "C" {
        fn sd_journal_stream_fd(
            identifier: *const libc::c_char,
            priority: libc::c_int,
            level_prefix: libc::c_int,
        ) -> libc::c_int;
    }
    // greetd supplies the login terminal. Open the journal stream here so
    // its credentials identify the running compositor, not a user service.
    let fd = unsafe { sd_journal_stream_fd(c"niri".as_ptr(), libc::LOG_INFO, 0) };
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-fd))
            .context("cannot open compositor journal stream");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::dup2(fd.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot redirect compositor stderr");
    }
    Ok(())
}

#[cfg(not(feature = "systemd"))]
fn journal_stderr() -> anyhow::Result<()> {
    bail!("--selinux-session requires systemd support")
}

/// The pipe is kept until compositor exit. Its close-on-exec writer cannot
/// leak to applications; EOF also reaches the bridge after a fatal signal.
pub fn start_bridge() -> anyhow::Result<Option<ChildStdin>> {
    let Some(session) = get() else {
        return Ok(None);
    };
    let mut child = Command::new(&session.bridge)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("cannot start the desktop session bridge")?;
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line)?;
    if line != "ready\n" {
        bail!("desktop session bridge failed before readiness");
    }
    Ok(child.stdin.take())
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
    fn p12_fixed_listener_is_a_name_in_the_runtime_directory() {
        assert!(listener_name("wayland-1"));
        for name in [
            "",
            "wayland-",
            "/tmp/wayland-1",
            "../wayland-1",
            "wayland-1/other",
        ] {
            assert!(!listener_name(name));
        }
    }

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
