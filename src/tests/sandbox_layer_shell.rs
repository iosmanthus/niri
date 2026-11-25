//! `sandbox-layer-shell`: wlr-layer-shell for the sandboxed apps that the config names.
//!
//! A restricted client (one that connected through a security context) sees the layer-shell
//! global only when the config names its app by sandbox engine and app id. Its surfaces stack
//! below the host's on the same layer, cannot take the keyboard exclusively, cannot reserve an
//! exclusive zone, and do not take the keyboard by mapping.

use client::ClientId;
use niri_config::Config;
use smithay::reexports::wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_shell_v1::Layer;
use smithay::reexports::wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_surface_v1::{
    Anchor, KeyboardInteractivity,
};
use smithay::utils::Point;
use wayland_client::protocol::wl_surface::WlSurface;

use super::*;
use crate::niri::LayerStack;
use crate::tests::client::LayerConfigureProps;

const ALLOW_FEISHU: &str = r##"
sandbox-layer-shell sandbox-engine="org.flatpak" app-id="cn.feishu.Feishu"
"##;

fn fixture(config: &str) -> Fixture {
    let mut f = Fixture::with_config(Config::parse_mem(config).unwrap());
    f.add_output(1, (1920, 1080));
    f
}

fn sees_layer_shell(f: &mut Fixture, id: ClientId) -> bool {
    f.roundtrip(id);
    f.client(id).state.layer_shell.is_some()
}

/// Maps a layer surface of client `id` on the overlay layer with `props` (100 × 100 unless
/// `props` gives a size).
fn map_layer(f: &mut Fixture, id: ClientId, props: LayerConfigureProps) -> WlSurface {
    let layer = f.client(id).create_layer(None, Layer::Overlay, "");
    let surface = layer.surface.clone();
    layer.set_configure_props(LayerConfigureProps {
        size: props.size.or(Some((100, 100))),
        ..props
    });
    layer.commit();
    f.roundtrip(id);

    let (w, h) = match props.size {
        Some((w, h)) if w > 0 && h > 0 => (w as u16, h as u16),
        _ => (100, 100),
    };
    let layer = f.client(id).layer(&surface);
    if !layer.close_requested {
        layer.attach_new_buffer();
        layer.set_size(w, h);
        layer.ack_last_and_commit();
    }
    f.double_roundtrip(id);
    surface
}

fn stack_under(f: &mut Fixture, x: f64, y: f64) -> Option<LayerStack> {
    let contents = f.niri().contents_under(Point::from((x, y)));
    contents
        .layer
        .map(|layer| LayerStack::of(layer.wl_surface()))
}

#[test]
fn hidden_from_sandboxes_by_default() {
    let mut f = fixture("");
    let host = f.add_client();
    let sandbox = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    assert!(sees_layer_shell(&mut f, host));
    assert!(!sees_layer_shell(&mut f, sandbox));
}

#[test]
fn shown_to_the_named_sandbox_only() {
    let mut f = fixture(ALLOW_FEISHU);
    let feishu = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    let other_app = f.add_security_context_client(Some("org.flatpak"), "com.tencent.WeChat");
    let other_engine = f.add_security_context_client(Some("other.engine"), "cn.feishu.Feishu");
    let no_engine = f.add_security_context_client(None, "cn.feishu.Feishu");
    assert!(sees_layer_shell(&mut f, feishu));
    assert!(!sees_layer_shell(&mut f, other_app));
    assert!(!sees_layer_shell(&mut f, other_engine));
    assert!(!sees_layer_shell(&mut f, no_engine));
}

#[test]
fn sandbox_cannot_take_the_keyboard_exclusively() {
    let mut f = fixture(ALLOW_FEISHU);
    let sandbox = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    let host = f.add_client();
    let props = || LayerConfigureProps {
        kb_interactivity: Some(KeyboardInteractivity::Exclusive),
        ..Default::default()
    };

    let surface = map_layer(&mut f, sandbox, props());
    assert!(f.client(sandbox).layer(&surface).close_requested);

    let surface = map_layer(&mut f, host, props());
    assert!(!f.client(host).layer(&surface).close_requested);
}

#[test]
fn sandbox_cannot_reserve_an_exclusive_zone() {
    let mut f = fixture(ALLOW_FEISHU);
    let sandbox = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    let zone = |zone| LayerConfigureProps {
        anchor: Some(Anchor::Left | Anchor::Right | Anchor::Bottom),
        size: Some((0, 30)),
        exclusive_zone: Some(zone),
        ..Default::default()
    };

    let surface = map_layer(&mut f, sandbox, zone(30));
    assert!(f.client(sandbox).layer(&surface).close_requested);

    // xwayland-satellite places its overlay from the output corner: exclusive zone -1.
    let surface = map_layer(&mut f, sandbox, zone(-1));
    assert!(!f.client(sandbox).layer(&surface).close_requested);
}

#[test]
fn sandbox_stacks_below_the_host() {
    let mut f = fixture(ALLOW_FEISHU);
    let host = f.add_client();
    let sandbox = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");

    // The host's overlay covers 200 × 200 px at the top-left corner; the sandbox's, mapped
    // later, 300 × 300 px there.
    map_layer(
        &mut f,
        host,
        LayerConfigureProps {
            anchor: Some(Anchor::Left | Anchor::Top),
            size: Some((200, 200)),
            ..Default::default()
        },
    );
    map_layer(
        &mut f,
        sandbox,
        LayerConfigureProps {
            anchor: Some(Anchor::Left | Anchor::Top),
            size: Some((300, 300)),
            ..Default::default()
        },
    );

    assert_eq!(stack_under(&mut f, 60., 60.), Some(LayerStack::Host));
    assert_eq!(stack_under(&mut f, 250., 250.), Some(LayerStack::Sandbox));
}

#[test]
fn sandbox_takes_the_keyboard_only_when_clicked() {
    let mut f = fixture(ALLOW_FEISHU);
    let on_demand = || LayerConfigureProps {
        kb_interactivity: Some(KeyboardInteractivity::OnDemand),
        ..Default::default()
    };

    let sandbox = f.add_security_context_client(Some("org.flatpak"), "cn.feishu.Feishu");
    map_layer(&mut f, sandbox, on_demand());
    assert!(f.niri().layer_shell_on_demand_focus.is_none());

    let host = f.add_client();
    map_layer(&mut f, host, on_demand());
    let focus = f.niri().layer_shell_on_demand_focus.clone();
    assert_eq!(
        focus.map(|layer| LayerStack::of(layer.wl_surface())),
        Some(LayerStack::Host)
    );
}
