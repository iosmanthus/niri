//! Reads of file references that cross a sandbox boundary go to the broker of the config
//! (`clipboard { file-reference-broker }`); other reads go to the source as usual.

use std::fs::File;
use std::io::{IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use client::ClientId;
use niri_config::Config;
use smithay::reexports::rustix::cmsg_space;
use smithay::reexports::rustix::event::{poll, PollFd, PollFlags, Timespec};
use smithay::reexports::rustix::net::{
    accept_with, bind, listen, recvmsg, socket_with, AddressFamily, RecvAncillaryBuffer,
    RecvAncillaryMessage, RecvFlags, SocketAddrUnix, SocketFlags, SocketType,
};

use super::*;
use crate::niri::SecurityContextInfo;

const URI_LIST: &str = "text/uri-list";
const TEXT: &str = "text/plain;charset=utf-8";

/// A broker socket that the test plays the broker on.
struct FakeBroker {
    dir: PathBuf,
    path: PathBuf,
    listener: OwnedFd,
    connection: Option<OwnedFd>,
}

/// One message to the broker: the header and the file descriptors.
struct Message {
    header: serde_json::Value,
    fds: Vec<OwnedFd>,
}

impl FakeBroker {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "niri-test-broker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket");
        let listener = Self::listen(&path);
        Self {
            dir,
            path,
            listener,
            connection: None,
        }
    }

    fn listen(path: &std::path::Path) -> OwnedFd {
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        bind(&listener, &SocketAddrUnix::new(path).unwrap()).unwrap();
        listen(&listener, 4).unwrap();
        listener
    }

    fn config(&self) -> String {
        format!(
            "clipboard {{ file-reference-broker \"{}\"; }}",
            self.path.display()
        )
    }

    /// The broker restarts: the connection breaks and a new socket listens at the same path.
    fn restart(&mut self) {
        self.connection = None;
        std::fs::remove_file(&self.path).unwrap();
        self.listener = Self::listen(&self.path);
    }

    /// The next message, if niri sent one.
    fn receive(&mut self) -> Option<Message> {
        if let Ok(connection) = accept_with(&self.listener, SocketFlags::CLOEXEC) {
            self.connection = Some(connection);
        }
        let connection = self.connection.as_ref()?;
        let mut buf = [0u8; 4096];
        let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(8))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            connection,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::DONTWAIT,
        )
        .ok()?;
        let mut fds = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                fds.extend(rights);
            }
        }
        if received.bytes == 0 {
            // niri closed the connection.
            self.connection = None;
            return None;
        }
        let header = serde_json::from_slice(&buf[..received.bytes]).unwrap();
        Some(Message { header, fds })
    }
}

impl Drop for FakeBroker {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Everything until EOF; the test fails instead of hanging when the write end stays open.
fn read_to_end(fd: OwnedFd) -> String {
    let mut file = File::from(fd);
    let mut got = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let mut fds = [PollFd::new(&file, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        assert!(
            poll(&mut fds, Some(&timeout)).unwrap() > 0,
            "the read did not end within 5 s"
        );
        match file.read(&mut chunk).unwrap() {
            0 => return String::from_utf8(got).unwrap(),
            n => got.extend_from_slice(&chunk[..n]),
        }
    }
}

fn fixture(config: &str) -> Fixture {
    let mut f = Fixture::with_config(Config::parse_mem(config).unwrap());
    f.add_output(1, (1920, 1080));
    f
}

fn sandbox(app_id: &str, instance_id: &str) -> SecurityContextInfo {
    SecurityContextInfo::new(Some("org.flatpak"), Some(app_id), Some(instance_id))
}

fn wechat() -> SecurityContextInfo {
    sandbox("com.tencent.WeChat", "1")
}

fn feishu() -> SecurityContextInfo {
    sandbox("cn.feishu.Feishu", "2")
}

/// Client `id` opens a window, which takes the keyboard focus.
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

/// Client `id` (focused) copies, offering a file list and text.
fn copy(f: &mut Fixture, id: ClientId) {
    copy_types(f, id, &[URI_LIST, TEXT]);
}

fn copy_types(f: &mut Fixture, id: ClientId, mime_types: &[&str]) {
    f.client(id).state.set_clipboard(mime_types);
    f.roundtrip(id);
}

/// Client `id` reads `mime_type` from its data device (`by_data_control`: from its data-control
/// device); returns the read end.
fn read(f: &mut Fixture, id: ClientId, mime_type: &str, by_data_control: bool) -> OwnedFd {
    let (from, to) = std::io::pipe().unwrap();
    let state = &f.client(id).state;
    if by_data_control {
        state.receive_clipboard_by_data_control(mime_type, to.into());
    } else {
        state.receive_clipboard(mime_type, to.into());
    }
    f.roundtrip(id);
    from.into()
}

/// Client `id` answers its sources' requests with `data`; returns how many there were.
fn answer(f: &mut Fixture, id: ClientId, data: &str) -> usize {
    f.roundtrip(id);
    let sends: Vec<_> = f.client(id).state.clipboard.sends.drain(..).collect();
    let count = sends.len();
    for (_, fd) in sends {
        // The reader may have closed its end already.
        let _ = File::from(fd).write_all(data.as_bytes());
    }
    count
}

/// A host clipboard manager: a host client reading through data control.
fn add_clipboard_manager(f: &mut Fixture) -> ClientId {
    let id = f.add_client();
    f.client(id).state.data_control_device();
    f.roundtrip(id);
    id
}

#[test]
fn a_file_list_from_a_sandbox_goes_to_the_broker() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);

    let got = read(&mut f, reader, URI_LIST, true);
    let message = broker.receive().expect("no message to the broker");
    assert_eq!(
        answer(&mut f, source, "file:///home/u/xwechat_files/a.png\r\n"),
        1
    );
    let [list, to_reader, _source_pidfd, _reader_pidfd] =
        <[OwnedFd; 4]>::try_from(message.fds).unwrap();
    assert_eq!(read_to_end(list), "file:///home/u/xwechat_files/a.png\r\n");
    File::from(to_reader)
        .write_all(b"file:///run/user/1000/doc/x/a.png\r\n")
        .unwrap();

    assert_eq!(read_to_end(got), "file:///run/user/1000/doc/x/a.png\r\n");
    assert_eq!(
        message.header,
        serde_json::json!({
            "version": 1,
            "target": "clipboard",
            "device": "ext-data-control",
            "mime_type": URI_LIST,
            "generation": 1,
            "source": {
                "sandbox_engine": "org.flatpak",
                "app_id": "com.tencent.WeChat",
                "instance_id": "1",
            },
            "reader": null,
            "fds": ["source", "reader", "source-pidfd", "reader-pidfd"],
        })
    );
}

#[test]
fn a_file_list_between_sandboxes_goes_to_the_broker() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    copy(&mut f, source);
    let reader = f.add_client_in_security_context(feishu());
    f.client(reader).state.data_device();
    open_window(&mut f, reader);

    let got = read(&mut f, reader, URI_LIST, false);
    let message = broker.receive().expect("no message to the broker");
    drop(message.fds);

    assert_eq!(answer(&mut f, source, "file:///never"), 1);
    assert_eq!(message.header["device"], "data-device");
    assert_eq!(message.header["reader"]["app_id"], "cn.feishu.Feishu");
    assert_eq!(read_to_end(got), "");
}

#[test]
fn other_types_go_to_the_source() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);

    let got = read(&mut f, reader, TEXT, true);

    assert_eq!(answer(&mut f, source, "hello"), 1);
    assert_eq!(read_to_end(got), "hello");
    assert!(broker.receive().is_none());
}

#[test]
fn a_file_list_within_one_side_goes_to_the_source() {
    for sandboxed in [false, true] {
        let mut broker = FakeBroker::new();
        let mut f = fixture(&broker.config());
        let add = |f: &mut Fixture| match sandboxed {
            true => f.add_client_in_security_context(wechat()),
            false => f.add_client(),
        };
        let source = add(&mut f);
        open_window(&mut f, source);
        copy(&mut f, source);
        let reader = add(&mut f);
        f.client(reader).state.data_device();
        open_window(&mut f, reader);

        let got = read(&mut f, reader, URI_LIST, false);

        assert_eq!(
            answer(&mut f, source, "file:///a"),
            1,
            "sandboxed: {sandboxed}"
        );
        assert_eq!(read_to_end(got), "file:///a");
        assert!(broker.receive().is_none());
    }
}

#[test]
fn without_a_broker_a_file_list_goes_to_the_source() {
    let mut f = fixture("");
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);

    let got = read(&mut f, reader, URI_LIST, true);

    assert_eq!(answer(&mut f, source, "file:///a"), 1);
    assert_eq!(read_to_end(got), "file:///a");
}

#[test]
fn when_the_broker_is_away_the_reader_gets_nothing() {
    let broker = FakeBroker::new();
    let config = broker.config();
    drop(broker);
    let mut f = fixture(&config);
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);

    let got = read(&mut f, reader, URI_LIST, true);

    assert_eq!(answer(&mut f, source, "file:///never"), 0);
    assert_eq!(read_to_end(got), "");
}

#[test]
fn a_restarted_broker_gets_the_next_read() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);
    read(&mut f, reader, URI_LIST, true);
    assert!(broker.receive().is_some());

    broker.restart();
    read(&mut f, reader, URI_LIST, true);

    assert!(broker.receive().is_some(), "no message after the restart");
}

#[test]
fn a_file_list_from_the_host_to_a_sandbox_goes_to_the_broker() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client();
    open_window(&mut f, source);
    copy(&mut f, source);
    let reader = f.add_client_in_security_context(feishu());
    f.client(reader).state.data_device();
    open_window(&mut f, reader);

    let got = read(&mut f, reader, URI_LIST, false);
    let message = broker.receive().expect("no message to the broker");
    drop(message.fds);

    assert_eq!(answer(&mut f, source, "file:///never"), 1);
    assert_eq!(message.header["source"], serde_json::Value::Null);
    assert_eq!(message.header["reader"]["app_id"], "cn.feishu.Feishu");
    assert_eq!(read_to_end(got), "");
}

#[test]
fn every_file_list_type_goes_to_the_broker() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    let types = [
        "x-special/gnome-copied-files",
        "text/uri-list;charset=utf-8",
    ];
    copy_types(&mut f, source, &types);
    f.roundtrip(reader);

    for mime_type in types {
        read(&mut f, reader, mime_type, true);
        let message = broker.receive().expect("no message to the broker");
        assert_eq!(message.header["mime_type"], mime_type);
    }
}

#[test]
fn reads_of_one_copy_share_a_generation() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    let mut generation = |f: &mut Fixture| {
        read(f, reader, URI_LIST, true);
        broker.receive().expect("no message to the broker").header["generation"].clone()
    };

    copy(&mut f, source);
    f.roundtrip(reader);
    let first = generation(&mut f);
    let again = generation(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);
    let next = generation(&mut f);

    assert_eq!(first, again);
    assert_eq!(next, first.as_u64().unwrap() + 1);
}

#[test]
fn contexts_without_instance_ids_are_separate_sandboxes() {
    let mut broker = FakeBroker::new();
    let mut f = fixture(&broker.config());
    let context = SecurityContextInfo::new(Some("org.flatpak"), Some("com.tencent.WeChat"), None);
    let source = f.add_client_in_security_context(context.clone());
    open_window(&mut f, source);
    copy(&mut f, source);
    let reader = f.add_client_in_security_context(context);
    f.client(reader).state.data_device();
    open_window(&mut f, reader);

    read(&mut f, reader, URI_LIST, false);

    assert!(broker.receive().is_some());
}

#[test]
fn the_broker_follows_the_config() {
    let mut broker = FakeBroker::new();
    let mut f = fixture("");
    let source = f.add_client_in_security_context(wechat());
    open_window(&mut f, source);
    let reader = add_clipboard_manager(&mut f);
    copy(&mut f, source);
    f.roundtrip(reader);

    f.niri_state()
        .reload_config(Ok(Config::parse_mem(&broker.config()).unwrap()));
    read(&mut f, reader, URI_LIST, true);
    assert!(broker.receive().is_some(), "a broker in the new config");
    // The source writes into the broker's pipe.
    assert_eq!(answer(&mut f, source, "file:///to-the-broker"), 1);

    f.niri_state()
        .reload_config(Ok(Config::parse_mem("").unwrap()));
    let got = read(&mut f, reader, URI_LIST, true);
    assert_eq!(answer(&mut f, source, "file:///a"), 1);
    assert_eq!(read_to_end(got), "file:///a");
    assert!(broker.receive().is_none());
    assert!(broker.connection.is_none(), "niri closed the connection");
}
