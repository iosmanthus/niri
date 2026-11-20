//! The `is-secondary` and `security-context-app-id` window rule matchers.
//!
//! A window is secondary when, as it opens, a tiled window of the same app is already
//! mapped. A client that connected through a security context with an app id belongs to
//! the app that the context's sandbox engine and app id name, whichever process or X11
//! bridge opens the window; any other client is one app per window app id.

use client::ClientId;
use niri_config::Config;
use wayland_client::protocol::wl_surface::WlSurface;

use super::*;
use crate::utils::with_toplevel_role;

const FLOAT_SECONDARY: &str = r##"
window-rule {
    match is-secondary=true
    exclude app-id="^peers$"
    open-floating true
}
"##;

fn fixture(config: &str) -> Fixture {
    let mut f = Fixture::with_config(Config::parse_mem(config).unwrap());
    f.add_output(1, (1920, 1080));
    f
}

/// Opens and maps a window of client `id`; `fixed` gives it min = max size, `parent` a
/// parent toplevel of the same client.
fn open_with(
    f: &mut Fixture,
    id: ClientId,
    app_id: &str,
    title: &str,
    parent: Option<&WlSurface>,
    fixed: bool,
) -> WlSurface {
    let parent = parent.map(|p| f.client(id).window(p).xdg_toplevel.clone());
    let window = f.client(id).create_window();
    window.xdg_toplevel.set_app_id(app_id.to_owned());
    window.set_title(title);
    if parent.is_some() {
        window.set_parent(parent.as_ref());
    }
    if fixed {
        window.xdg_toplevel.set_min_size(100, 100);
        window.xdg_toplevel.set_max_size(100, 100);
    }
    let surface = window.surface.clone();
    window.commit();
    f.roundtrip(id);

    let window = f.client(id).window(&surface);
    window.attach_new_buffer();
    window.set_size(100, 100);
    window.ack_last_and_commit();
    f.double_roundtrip(id);
    surface
}

fn open(f: &mut Fixture, id: ClientId, app_id: &str, title: &str) -> WlSurface {
    open_with(f, id, app_id, title, None, false)
}

/// Whether the mapped window titled `title` is floating.
fn floating(f: &mut Fixture, title: &str) -> bool {
    f.niri()
        .layout
        .windows()
        .find_map(|(_, mapped)| {
            let t = with_toplevel_role(mapped.toplevel(), |role| role.title.clone());
            (t.as_deref() == Some(title)).then(|| mapped.is_floating())
        })
        .unwrap_or_else(|| panic!("no mapped window titled {title}"))
}

#[test]
fn second_window_of_an_app_is_secondary() {
    let mut f = fixture(FLOAT_SECONDARY);
    let id = f.add_client();
    open(&mut f, id, "chat", "main");
    open(&mut f, id, "chat", "viewer");

    assert!(!floating(&mut f, "main"));
    assert!(floating(&mut f, "viewer"));
}

#[test]
fn windows_of_other_apps_are_not_secondary() {
    // Another client with the same app id, and another app id of the same client (one
    // X11 bridge serves several X11 apps).
    let mut f = fixture(FLOAT_SECONDARY);
    let a = f.add_client();
    let b = f.add_client();
    open(&mut f, a, "chat", "main");
    open(&mut f, b, "chat", "other client");
    open(&mut f, a, "music", "other app");

    assert!(!floating(&mut f, "other client"));
    assert!(!floating(&mut f, "other app"));
}

#[test]
fn clients_of_one_sandbox_are_one_app() {
    // A sandboxed app's processes and its X11 bridge connect as separate clients, and its
    // X11 windows can have other app ids (Feishu's meetings are "Meeting").
    let mut f = fixture(FLOAT_SECONDARY);
    let a = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    let b = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    let c = f.add_security_context_client(Some("org.flatpak"), "com.tencent.WeChat");
    open(&mut f, a, "Bytedance-feishu", "main");
    open(&mut f, b, "Meeting", "meeting");
    open(&mut f, c, "wechat", "wechat");

    assert!(!floating(&mut f, "main"));
    assert!(floating(&mut f, "meeting"));
    assert!(!floating(&mut f, "wechat"));
}

#[test]
fn floating_first_window_does_not_make_the_next_secondary() {
    // A login or splash window of a fixed size floats; the main window after it tiles.
    let mut f = fixture(FLOAT_SECONDARY);
    let id = f.add_client();
    open_with(&mut f, id, "chat", "login", None, true);
    open(&mut f, id, "chat", "main");

    assert!(floating(&mut f, "login"));
    assert!(!floating(&mut f, "main"));
}

#[test]
fn excluded_app_tiles_its_windows_and_floats_its_dialogs() {
    // The exclusion only takes the rule away: a dialog (a window with a parent) still
    // floats by default.
    let mut f = fixture(FLOAT_SECONDARY);
    let id = f.add_client();
    let first = open(&mut f, id, "peers", "first");
    open(&mut f, id, "peers", "second");
    open_with(&mut f, id, "peers", "dialog", Some(&first), false);

    assert!(!floating(&mut f, "second"));
    assert!(floating(&mut f, "dialog"));
}

#[test]
fn secondary_is_decided_when_the_window_opens() {
    // The floating window stays floating when the main window goes; a window opened after
    // that, with no tiled window of the app left, tiles.
    let mut f = fixture(FLOAT_SECONDARY);
    let id = f.add_client();
    let main = open(&mut f, id, "chat", "main");
    open(&mut f, id, "chat", "viewer");

    let window = f.client(id).window(&main);
    window.attach_null();
    window.commit();
    f.double_roundtrip(id);

    open(&mut f, id, "chat", "reopened");

    assert!(floating(&mut f, "viewer"));
    assert!(!floating(&mut f, "reopened"));
}

#[test]
fn same_app_id_of_another_engine_is_another_app() {
    // The app id is the sandbox engine's own: only the engine and the app id together
    // name an app, and an engine may be unset.
    let mut f = fixture(FLOAT_SECONDARY);
    let a = f.add_security_context_client(Some("org.flatpak"), "org.example.App");
    let b = f.add_security_context_client(Some("org.example.engine"), "org.example.App");
    let c = f.add_security_context_client(None, "org.example.App");
    open(&mut f, a, "app", "flatpak");
    open(&mut f, b, "app", "other engine");
    open(&mut f, c, "app", "no engine");

    assert!(!floating(&mut f, "other engine"));
    assert!(!floating(&mut f, "no engine"));
}

#[test]
fn security_context_app_id_matches_the_context_not_the_window() {
    let config = r##"
window-rule {
    match security-context-app-id=r#"^cn\.feishu\.Feishu$"#
    open-floating true
}
"##;
    let mut f = fixture(config);
    let sandboxed = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    let plain = f.add_client();
    open(&mut f, sandboxed, "Bytedance-feishu", "sandboxed");
    open(&mut f, plain, "cn.feishu.Feishu", "app id only");

    assert!(floating(&mut f, "sandboxed"));
    assert!(!floating(&mut f, "app id only"));
}
