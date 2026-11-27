//! A client that connects through a security context keeps what the context says about it.

use client::ClientId;
use smithay::reexports::wayland_server::Resource;

use super::*;
use crate::niri::{ClientState, SecurityContextInfo};

fn flatpak() -> SecurityContextInfo {
    SecurityContextInfo::new(
        Some("org.flatpak"),
        Some("com.example.App"),
        Some("2097152"),
    )
}

fn open_window(f: &mut Fixture, id: ClientId) {
    let window = f.client(id).create_window();
    let surface = window.surface.clone();
    window.commit();
    f.roundtrip(id);

    let window = f.client(id).window(&surface);
    window.attach_new_buffer();
    window.set_size(100, 100);
    window.ack_last_and_commit();
    f.double_roundtrip(id);
}

/// The security context that niri keeps for the client of the only window.
fn context_of_the_window(f: &mut Fixture) -> Option<SecurityContextInfo> {
    let (_, mapped) = f.niri().layout.windows().next().unwrap();
    let client = mapped.toplevel().wl_surface().client().unwrap();
    client
        .get_data::<ClientState>()
        .unwrap()
        .security_context
        .clone()
}

#[test]
fn a_client_in_a_security_context_keeps_it() {
    let mut f = Fixture::new();
    f.add_output(1, (1920, 1080));
    let id = f.add_client_in_security_context(flatpak());
    open_window(&mut f, id);
    assert_eq!(context_of_the_window(&mut f), Some(flatpak()));
}

#[test]
fn a_client_outside_security_contexts_has_none() {
    let mut f = Fixture::new();
    f.add_output(1, (1920, 1080));
    let id = f.add_client();
    open_window(&mut f, id);
    assert_eq!(context_of_the_window(&mut f), None);
}

#[test]
fn empty_values_are_unset() {
    assert_eq!(
        SecurityContextInfo::new(Some(""), Some("com.example.App"), Some("")),
        SecurityContextInfo {
            sandbox_engine: None,
            app_id: Some("com.example.App".into()),
            instance_id: None,
        }
    );
}
