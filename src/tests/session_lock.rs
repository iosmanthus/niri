use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use smithay::reexports::wayland_server::backend::ObjectId;
use smithay::reexports::wayland_server::Resource;

use super::client::{ClientId, LockEvent};
use super::Fixture;
use crate::niri::LockState;
use crate::selinux::{PeerLabel, SecurityContext, UnknownReason};

fn known(kind: &str) -> PeerLabel {
    PeerLabel::Known(SecurityContext::for_test(&format!("u:r:{kind}:s0")))
}

fn request(fixture: &mut Fixture, id: ClientId) -> LockEvent {
    let client = fixture.client(id);
    client
        .state
        .lock_manager
        .as_ref()
        .unwrap()
        .lock(&client.qh, ());
    fixture.roundtrip(id);
    fixture.client(id).state.lock_events.last().unwrap().1
}

fn owner(fixture: &mut Fixture) -> (ObjectId, bool) {
    match &fixture.niri().lock_state {
        LockState::Locked(lock) => (lock.id(), lock.is_alive()),
        state => panic!("expected a retained lock, got {state:?}"),
    }
}

struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn p13_first_and_dead_lock_admission_preserve_state_and_emit_user_avc() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = bytes.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || Capture(writer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut fixture = Fixture::new();
        fixture.niri().protect_locks_for_test();
        let ordinary = fixture.add_client_with_peer(Some(known("unconfined_t")));
        let unknown = fixture.add_client_with_peer(None);
        assert_eq!(request(&mut fixture, ordinary), LockEvent::Finished);
        assert_eq!(request(&mut fixture, unknown), LockEvent::Finished);
        assert!(matches!(fixture.niri().lock_state, LockState::Unlocked));

        let trusted = fixture.add_client_with_peer(Some(known("locker_t")));
        assert_eq!(request(&mut fixture, trusted), LockEvent::Locked);
        let live = owner(&mut fixture);
        assert!(live.1);
        assert_eq!(request(&mut fixture, ordinary), LockEvent::Finished);
        assert_eq!(owner(&mut fixture), live);

        fixture.remove_client(trusted);
        fixture.double_roundtrip(ordinary);
        let dead = owner(&mut fixture);
        assert!(!dead.1);
        assert_eq!(request(&mut fixture, ordinary), LockEvent::Finished);
        assert_eq!(request(&mut fixture, unknown), LockEvent::Finished);
        assert_eq!(owner(&mut fixture), dead);
        let replacement = fixture.add_client_with_peer(Some(known("locker_t")));
        assert_eq!(request(&mut fixture, replacement), LockEvent::Locked);
        let replaced = owner(&mut fixture);
        assert!(replaced.1 && replaced.0 != dead.0);
    });
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    let events: Vec<serde_json::Value> = output
        .lines()
        .filter_map(|line| {
            line.split_once("avc: denied ")
                .map(|(_, event)| serde_json::from_str(event).unwrap())
        })
        .collect();
    assert_eq!(events.len(), 5, "{output}");
    for event in &events {
        assert_eq!(event["manager"], "niri");
        assert_eq!(event["op"], "session-lock");
        assert_eq!(event["server_context"], "system_u:system_r:niri_t:s0");
        assert!(event["connection"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| event["peer_context"].is_null())
            .count(),
        2
    );
}

#[test]
fn p13_ordinary_compositor_retains_the_protocol_control() {
    for peer in [
        known("unconfined_t"),
        PeerLabel::Unknown(UnknownReason::NotDirect),
    ] {
        let mut fixture = Fixture::new();
        let id = fixture.add_client_with_peer(Some(peer));
        assert_eq!(request(&mut fixture, id), LockEvent::Locked);
    }
}

#[test]
fn p15_snapshot_reports_a_dead_owner_without_changing_the_lock() {
    use niri_ipc::SessionLockPhase;
    let mut fixture = Fixture::new();
    fixture.niri().protect_locks_for_test();
    let observer = fixture.add_client();
    let trusted = fixture.add_client_with_peer(Some(known("locker_t")));
    assert_eq!(
        fixture.niri().session_lock_status().phase,
        SessionLockPhase::Unlocked
    );
    assert_eq!(request(&mut fixture, trusted), LockEvent::Locked);
    let before = owner(&mut fixture);
    let snapshot = fixture.niri().session_lock_status();
    assert_eq!(snapshot.phase, SessionLockPhase::Locked);
    assert!(snapshot.client_alive && snapshot.outputs.is_empty());
    assert_eq!(owner(&mut fixture), before);
    fixture.remove_client(trusted);
    fixture.double_roundtrip(observer);
    let dead = owner(&mut fixture);
    let snapshot = fixture.niri().session_lock_status();
    assert_eq!(snapshot.phase, SessionLockPhase::Locked);
    assert!(!snapshot.client_alive);
    assert_eq!(owner(&mut fixture), dead);
}
