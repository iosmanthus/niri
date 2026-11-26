//! Keyboard focus of popup grabs, also while an input method holds the keyboard grab.
//!
//! Smithay has one keyboard grab at a time, and a popup grab does not replace the keyboard grab
//! of an input method (zwp_input_method_v2). The popup still gets the keyboard focus, at once:
//! the input method's grab sends keys to the focus, and text-input follows the focus, so an input
//! field in the popup (a search field in a menu) can use the input method from its first key.
//! (Without an input method, Smithay's popup keyboard grab moves the focus on the first key.)

use client::ClientId;
use smithay::wayland::input_method::InputMethodSeat as _;
use wayland_client::protocol::wl_surface::WlSurface;

use super::*;

fn open_window(f: &mut Fixture, id: ClientId) -> WlSurface {
    let window = f.client(id).create_window();
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

fn open_popup(f: &mut Fixture, id: ClientId, parent: &WlSurface, grab: bool) -> WlSurface {
    let surface = f
        .client(id)
        .state
        .create_popup(parent, grab)
        .surface
        .clone();
    f.roundtrip(id);
    f.client(id).state.popup(&surface).map();
    f.double_roundtrip(id);
    surface
}

fn keyboard_focus(f: &mut Fixture, id: ClientId) -> Option<WlSurface> {
    f.client(id).state.keyboard_focus()
}

/// Whether keys go to the input method: it holds a keyboard grab, and the seat's keyboard is
/// still grabbed (a popup grab must not have replaced or removed the input method's grab).
fn ime_has_keyboard_grab(f: &mut Fixture) -> bool {
    let seat = &f.niri().seat;
    seat.input_method().keyboard_grabbed() && seat.get_keyboard().unwrap().is_grabbed()
}

fn fixture_with_ime() -> (Fixture, ClientId) {
    let mut f = Fixture::new();
    f.add_output(1, (1920, 1080));
    let ime = f.add_client();
    f.client(ime).state.grab_keyboard_as_input_method();
    f.double_roundtrip(ime);
    (f, ime)
}

#[test]
fn popup_grab_takes_keyboard_focus_while_ime_grabs_keyboard() {
    let (mut f, _ime) = fixture_with_ime();
    assert!(ime_has_keyboard_grab(&mut f));

    let id = f.add_client();
    let window = open_window(&mut f, id);
    assert_eq!(keyboard_focus(&mut f, id), Some(window.clone()));

    let popup = open_popup(&mut f, id, &window, true);
    assert!(!f.client(id).state.popup(&popup).done);
    assert_eq!(keyboard_focus(&mut f, id), Some(popup.clone()));
    assert!(ime_has_keyboard_grab(&mut f));

    // A nested grabbing popup takes the focus, and gives it back when it goes.
    let nested = open_popup(&mut f, id, &popup, true);
    assert_eq!(keyboard_focus(&mut f, id), Some(nested.clone()));
    f.client(id).state.popup(&nested).destroy();
    f.double_roundtrip(id);
    assert_eq!(keyboard_focus(&mut f, id), Some(popup.clone()));

    f.client(id).state.popup(&popup).destroy();
    f.double_roundtrip(id);
    assert_eq!(keyboard_focus(&mut f, id), Some(window));
    assert!(ime_has_keyboard_grab(&mut f));
}

#[test]
fn focus_moving_away_dismisses_the_popup_and_keeps_the_ime_grab() {
    let (mut f, _ime) = fixture_with_ime();
    let id = f.add_client();
    let window = open_window(&mut f, id);
    let popup = open_popup(&mut f, id, &window, true);
    assert_eq!(keyboard_focus(&mut f, id), Some(popup.clone()));

    // A new window takes the focus from the popup's root.
    let other = f.add_client();
    let other_window = open_window(&mut f, other);
    f.double_roundtrip(id);
    assert_eq!(keyboard_focus(&mut f, other), Some(other_window));
    assert!(f.client(id).state.popup(&popup).done);
    assert_eq!(keyboard_focus(&mut f, id), None);
    assert!(ime_has_keyboard_grab(&mut f));
}

#[test]
fn popup_without_grab_leaves_the_focus() {
    let (mut f, _ime) = fixture_with_ime();
    let id = f.add_client();
    let window = open_window(&mut f, id);
    open_popup(&mut f, id, &window, false);
    assert_eq!(keyboard_focus(&mut f, id), Some(window));
}
