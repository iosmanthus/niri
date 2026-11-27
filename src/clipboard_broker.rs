//! Reads of file references that cross a sandbox boundary go to an external broker.
//!
//! Sandboxed apps (clients of a security context, such as Flatpak apps) copy files as
//! `text/uri-list` or `x-special/gnome-copied-files` lists of paths that only exist inside their
//! sandbox. When such a list crosses a sandbox boundary (a client reads it from a client of another
//! sandbox, a sandboxed client reads it from a host client, or a host client reads it from a
//! sandboxed client), niri passes the read to the broker that the config names
//! (`clipboard { file-reference-broker "PATH" }`) instead of the source. The broker can make the
//! files available to the reader, for example through the document portal, and writes the
//! rewritten list. niri does not parse the list or touch the files.
//!
//! The broker gets one `SOCK_SEQPACKET` message per read: a JSON [`Header`] and the file
//! descriptors that its `fds` field names, in that order. When the broker cannot be reached or is
//! busy, the reader gets no data (end of file).

use std::ffi::OsStr;
use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use serde::Serialize;
use smithay::reexports::rustix::net::{
    connect, sendmsg, socket_with, AddressFamily, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags, SocketAddrUnix, SocketFlags, SocketType,
};
use smithay::reexports::rustix::pipe::{pipe_with, PipeFlags};
use smithay::wayland::selection::{
    SelectionDeviceKind, SelectionRead, SelectionReadSource, SelectionSource, SelectionTarget,
};

use crate::niri::{ClientState, SecurityContextInfo};

/// The version of the message format; it changes when a change breaks brokers.
pub const VERSION: u32 = 1;

/// Whether `mime_type` is a list of file references (parameters such as `charset` aside).
pub fn is_file_reference(mime_type: &str) -> bool {
    let base = mime_type.split(';').next().unwrap_or_default().trim();
    ["text/uri-list", "x-special/gnome-copied-files"]
        .iter()
        .any(|ty| base.eq_ignore_ascii_case(ty))
}

/// One side of a read: a host client or a client of a security context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Party {
    Host,
    Sandbox(SecurityContextInfo),
}

impl Party {
    pub fn of(client: &ClientState) -> Self {
        if client.restricted {
            Self::Sandbox(client.security_context.clone().unwrap_or_default())
        } else {
            Self::Host
        }
    }

    fn context(&self) -> Option<Context<'_>> {
        match self {
            Self::Host => None,
            Self::Sandbox(info) => Some(Context {
                sandbox_engine: info.sandbox_engine.as_deref(),
                app_id: info.app_id.as_deref(),
                instance_id: info.instance_id.as_deref(),
            }),
        }
    }
}

/// Whether a read by `reader` from `source` crosses a sandbox boundary: from one sandbox (or
/// instance) to another, or between a sandbox and the host. Clients of security contexts without an
/// instance ID cannot be told to share a sandbox, so they do not.
pub fn crosses_boundary(source: &Party, reader: &Party) -> bool {
    match (source, reader) {
        (Party::Host, Party::Host) => false,
        (Party::Sandbox(source), Party::Sandbox(reader)) => {
            source.instance_id.is_none() || source != reader
        }
        _ => true,
    }
}

/// The JSON header of a message to the broker.
#[derive(Debug, Serialize)]
pub struct Header<'a> {
    pub version: u32,
    /// `clipboard` or `primary`.
    pub target: &'static str,
    /// `data-device`, `primary-selection`, `wlr-data-control`, `ext-data-control`, or `other`.
    pub device: &'static str,
    pub mime_type: &'a str,
    /// The number of changes of the selection when the reader's offer was made: reads with the
    /// same target and generation read the same selection.
    pub generation: u64,
    /// The security context of the source's client; `null` for a host client.
    pub source: Option<Context<'a>>,
    /// The security context of the reader; `null` for a host client.
    pub reader: Option<Context<'a>>,
    /// Names of the file descriptors of the message, in order: `source` (read end of the pipe the
    /// source writes the list into), `reader` (where the reader reads), then `source-pidfd` and
    /// `reader-pidfd` when known.
    pub fds: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Context<'a> {
    pub sandbox_engine: Option<&'a str>,
    pub app_id: Option<&'a str>,
    pub instance_id: Option<&'a str>,
}

/// The socket path of the config's `file-reference-broker`: a relative path is in
/// `$XDG_RUNTIME_DIR`, as Wayland socket names are.
pub fn socket_path(configured: &str, runtime_dir: Option<&OsStr>) -> Option<PathBuf> {
    let path = Path::new(configured);
    if path.is_absolute() {
        Some(path.to_owned())
    } else {
        runtime_dir.map(|dir| Path::new(dir).join(path))
    }
}

/// The connection to the broker of the config.
#[derive(Debug, Default)]
pub struct FileReferenceBroker {
    configured: Option<String>,
    path: Option<PathBuf>,
    socket: Option<OwnedFd>,
}

impl FileReferenceBroker {
    /// Follows the config: a changed path drops the connection.
    pub fn set_path(&mut self, configured: Option<&str>) {
        if self.configured.as_deref() != configured {
            self.configured = configured.map(String::from);
            let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR");
            self.path = configured.and_then(|path| socket_path(path, runtime_dir.as_deref()));
            if configured.is_some() && self.path.is_none() {
                warn!("file reference broker: no XDG_RUNTIME_DIR for the relative path");
            }
            self.socket = None;
        }
    }

    /// Takes over a read that goes to the broker; gives the fd back otherwise, for the caller to
    /// serve the read as usual. A read that should go to the broker but cannot gets no data.
    pub fn take<U>(&mut self, read: &SelectionRead<U>, fd: OwnedFd) -> Option<OwnedFd> {
        if self.configured.is_none() || !is_file_reference(&read.mime_type) {
            return Some(fd);
        }
        // niri's own selection is not a sandbox's.
        let SelectionReadSource::Client(source) = &read.source else {
            return Some(fd);
        };
        // The source went away, or a client is not one of niri's.
        let source_client = source.client()?;
        let (Some(source_state), Some(reader_state)) = (
            source_client.get_data::<ClientState>(),
            read.reader.get_data::<ClientState>(),
        ) else {
            return None;
        };
        let (from, to) = (Party::of(source_state), Party::of(reader_state));
        if !crosses_boundary(&from, &to) {
            return Some(fd);
        }
        if self.path.is_none() {
            warn!("file reference broker: no socket path; the reader gets no data");
            return None;
        }

        let header = Header {
            version: VERSION,
            target: match read.target {
                SelectionTarget::Clipboard => "clipboard",
                SelectionTarget::Primary => "primary",
            },
            device: match read.device_kind {
                SelectionDeviceKind::DataDevice => "data-device",
                SelectionDeviceKind::PrimarySelection => "primary-selection",
                SelectionDeviceKind::WlrDataControl => "wlr-data-control",
                SelectionDeviceKind::ExtDataControl => "ext-data-control",
                _ => "other",
            },
            mime_type: &read.mime_type,
            generation: read.generation,
            source: from.context(),
            reader: to.context(),
            fds: Vec::new(),
        };
        let pidfds = [
            ("source-pidfd", source_state.peer_pidfd.as_ref()),
            ("reader-pidfd", reader_state.peer_pidfd.as_ref()),
        ];
        if let Err(err) = self.hand_over(header, source, &read.mime_type, fd, pidfds) {
            warn!("file reference broker: {err}; the reader gets no data");
        }
        None
    }

    fn hand_over(
        &mut self,
        mut header: Header<'_>,
        source: &SelectionSource,
        mime_type: &str,
        reader: OwnedFd,
        pidfds: [(&'static str, Option<&OwnedFd>); 2],
    ) -> io::Result<()> {
        let (pipe_read, pipe_write) = pipe_with(PipeFlags::CLOEXEC)?;
        let mut fds = vec![pipe_read.as_fd(), reader.as_fd()];
        header.fds = vec!["source", "reader"];
        for (name, pidfd) in pidfds {
            if let Some(pidfd) = pidfd {
                fds.push(pidfd.as_fd());
                header.fds.push(name);
            }
        }
        let message = serde_json::to_vec(&header)?;
        self.send(&message, &fds)?;
        // The broker has the read end and the reader's fd; the source writes into the pipe.
        source.send(mime_type.to_owned(), pipe_write);
        Ok(())
    }

    fn send(&mut self, message: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        // A kept connection may have broken since (the broker restarted): retry once on a new
        // one.
        let reused = self.socket.is_some();
        match self.send_once(message, fds) {
            Err(err) if reused && self.socket.is_none() => {
                debug!("file reference broker: {err}; connecting again");
                self.send_once(message, fds)
            }
            result => result,
        }
    }

    fn send_once(&mut self, message: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let result = self.socket().and_then(|socket| {
            let mut space =
                [MaybeUninit::uninit(); smithay::reexports::rustix::cmsg_space!(ScmRights(4))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            control.push(SendAncillaryMessage::ScmRights(fds));
            let flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
            Ok(sendmsg(
                socket,
                &[IoSlice::new(message)],
                &mut control,
                flags,
            )?)
        });
        match result {
            Ok(sent) if sent == message.len() => Ok(()),
            Ok(_) => {
                self.socket = None;
                Err(io::Error::other("the message was cut"))
            }
            // The broker is busy; the connection is fine.
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                Err(io::Error::new(err.kind(), "the broker is busy"))
            }
            Err(err) => {
                self.socket = None;
                Err(err)
            }
        }
    }

    fn socket(&mut self) -> io::Result<BorrowedFd<'_>> {
        if self.socket.is_none() {
            let path = self.path.as_deref().expect("set");
            let socket = socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            connect(&socket, &SocketAddrUnix::new(path)?)?;
            self.socket = Some(socket);
        }
        Ok(self.socket.as_ref().unwrap().as_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(app_id: &str, instance_id: &str) -> Party {
        Party::Sandbox(SecurityContextInfo::new(
            Some("org.flatpak"),
            Some(app_id),
            Some(instance_id),
        ))
    }

    #[test]
    fn file_reference_types() {
        assert!(is_file_reference("text/uri-list"));
        assert!(is_file_reference("text/uri-list;charset=utf-8"));
        assert!(is_file_reference("Text/URI-List"));
        assert!(is_file_reference("x-special/gnome-copied-files"));
        assert!(!is_file_reference("text/plain"));
        assert!(!is_file_reference("image/png"));
        assert!(!is_file_reference("text/uri-list-x"));
    }

    #[test]
    fn a_busy_broker_keeps_its_connection() {
        use smithay::reexports::rustix::net::{recv, socketpair, RecvFlags};

        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let mut broker = FileReferenceBroker {
            configured: Some("broker".into()),
            path: Some(PathBuf::from("/nonexistent/broker")),
            socket: Some(ours),
        };
        let (pipe, _) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        let message = [b'x'; 1024];
        let send = |broker: &mut FileReferenceBroker| broker.send(&message, &[pipe.as_fd()]);

        let err = (0..10_000)
            .find_map(|_| send(&mut broker).err())
            .expect("the socket never filled");

        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(broker.socket.is_some(), "the connection is kept");
        // The broker catches up; the next message goes over the same connection.
        let mut buf = [0; 2048];
        while recv(&theirs, &mut buf, RecvFlags::DONTWAIT).is_ok() {}
        send(&mut broker).unwrap();
    }

    #[test]
    fn socket_paths() {
        let runtime = Some(OsStr::new("/run/user/1000"));
        assert_eq!(
            socket_path("/srv/broker", runtime),
            Some(PathBuf::from("/srv/broker"))
        );
        assert_eq!(
            socket_path("sandbox-permd/socket", runtime),
            Some(PathBuf::from("/run/user/1000/sandbox-permd/socket"))
        );
        assert_eq!(socket_path("sandbox-permd/socket", None), None);
    }

    #[test]
    fn boundaries() {
        let wechat = sandbox("com.tencent.WeChat", "1");
        let feishu = sandbox("cn.feishu.Feishu", "2");
        assert!(!crosses_boundary(&Party::Host, &Party::Host));
        assert!(!crosses_boundary(&wechat, &wechat.clone()));
        assert!(crosses_boundary(&wechat, &feishu));
        assert!(crosses_boundary(&wechat, &Party::Host));
        assert!(crosses_boundary(&Party::Host, &feishu));
        // Two instances of one app have separate sandboxes.
        assert!(crosses_boundary(
            &wechat,
            &sandbox("com.tencent.WeChat", "3")
        ));
        // Without instance IDs, even equal contexts may be separate sandboxes.
        let anonymous = Party::Sandbox(SecurityContextInfo::new(
            Some("org.flatpak"),
            Some("com.tencent.WeChat"),
            None,
        ));
        assert!(crosses_boundary(&anonymous, &anonymous.clone()));
        let empty = Party::Sandbox(SecurityContextInfo::default());
        assert!(crosses_boundary(&empty, &empty.clone()));
    }
}
