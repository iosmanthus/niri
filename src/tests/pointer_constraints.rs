use std::sync::atomic::Ordering;
use std::sync::Arc;

use smithay::reexports::wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_shell_v1::Layer;
use smithay::reexports::wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_surface_v1::{
    Anchor, KeyboardInteractivity,
};
use smithay::utils::Point;

use super::client::{ClientId, LayerConfigureProps, LockedPointerData};
use super::*;

/// Locks the pointer to a fullscreen window, near the bottom-right corner of the output.
fn set_up_locked_fullscreen() -> (Fixture, ClientId, Arc<LockedPointerData>) {
    let mut f = Fixture::new();
    f.add_output(1, (1920, 1080));
    let id = f.add_client();

    let window = f.client(id).create_window();
    let surface = window.surface.clone();
    window.set_fullscreen(None);
    window.commit();
    f.roundtrip(id);

    let window = f.client(id).window(&surface);
    window.attach_new_buffer();
    window.set_size(1920, 1080);
    window.ack_last_and_commit();
    f.double_roundtrip(id);

    // Pointer contents are not refreshed while the view is moving.
    f.niri_complete_animations();

    f.niri_state().move_cursor(Point::from((1800., 1000.)));
    let lock = f.client(id).state.lock_pointer(&surface);
    f.double_roundtrip(id);
    assert!(lock.locked.load(Ordering::Relaxed));

    (f, id, lock)
}

/// Maps an overlay layer surface under the pointer, where notification popups show up.
fn map_overlay_under_pointer(f: &mut Fixture, id: ClientId, kb: KeyboardInteractivity) {
    let layer = f.client(id).create_layer(None, Layer::Overlay, "notifications");
    let surface = layer.surface.clone();
    layer.set_configure_props(LayerConfigureProps {
        anchor: Some(Anchor::Bottom | Anchor::Right),
        size: Some((400, 300)),
        kb_interactivity: Some(kb),
        ..Default::default()
    });
    layer.commit();
    f.roundtrip(id);

    let layer = f.client(id).layer(&surface);
    layer.attach_new_buffer();
    layer.set_size(400, 300);
    layer.ack_last_and_commit();
    f.double_roundtrip(id);

    f.niri_complete_animations();
    f.double_roundtrip(id);

    let niri = f.niri();
    let under = niri.contents_under(Point::from((1800., 1000.)));
    assert!(under.layer.is_some(), "the layer surface is not under the pointer");
}

#[test]
fn overlay_without_keyboard_focus_keeps_lock() {
    let (mut f, id, lock) = set_up_locked_fullscreen();

    map_overlay_under_pointer(&mut f, id, KeyboardInteractivity::None);

    assert!(f.niri().pointer_contents.window.is_some());
    assert!(!lock.unlocked.load(Ordering::Relaxed));
}

#[test]
fn overlay_taking_keyboard_focus_breaks_lock() {
    let (mut f, id, lock) = set_up_locked_fullscreen();

    map_overlay_under_pointer(&mut f, id, KeyboardInteractivity::Exclusive);

    assert!(f.niri().pointer_contents.layer.is_some());
    assert!(lock.unlocked.load(Ordering::Relaxed));
}
