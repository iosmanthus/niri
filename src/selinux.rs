//! P13: labels belong to accepted connections, never to a client-reported PID.

use std::ffi::CStr;
#[cfg(test)]
use std::ffi::CString;
use std::os::fd::RawFd;
use std::ptr::NonNull;

use libc::{c_char, c_int, c_void};

unsafe extern "C" {
    fn is_selinux_enabled() -> c_int;
    fn getcon_raw(context: *mut *mut c_char) -> c_int;
    fn getpeercon_raw(fd: c_int, context: *mut *mut c_char) -> c_int;
    fn freecon(context: *mut c_char);
    fn context_new(context: *const c_char) -> *mut c_void;
    fn context_free(context: *mut c_void);
    fn context_type_get(context: *mut c_void) -> *const c_char;
    fn context_user_get(context: *mut c_void) -> *const c_char;
    fn context_role_get(context: *mut c_void) -> *const c_char;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityContext {
    raw: String,
    type_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    NotDirect,
    QueryFailed,
    Empty,
    Invalid,
}

impl UnknownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotDirect => "unknown-provenance",
            Self::QueryFailed => "peer-query-failed",
            Self::Empty => "empty-peer-context",
            Self::Invalid => "invalid-peer-context",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerLabel {
    Known(SecurityContext),
    Unknown(UnknownReason),
}

struct RawContext(NonNull<c_char>);

impl Drop for RawContext {
    fn drop(&mut self) {
        unsafe { freecon(self.0.as_ptr()) };
        #[cfg(test)]
        FREED.with(|count| count.set((count.get().0 + 1, count.get().1)));
    }
}

struct ParsedContext(NonNull<c_void>);

impl Drop for ParsedContext {
    fn drop(&mut self) {
        unsafe { context_free(self.0.as_ptr()) };
        #[cfg(test)]
        FREED.with(|count| count.set((count.get().0, count.get().1 + 1)));
    }
}

impl SecurityContext {
    fn parse(raw: &CStr) -> Result<Self, UnknownReason> {
        let text = raw.to_str().map_err(|_| UnknownReason::Invalid)?;
        if text.is_empty() {
            return Err(UnknownReason::Empty);
        }
        let parsed = NonNull::new(unsafe { context_new(raw.as_ptr()) })
            .map(ParsedContext)
            .ok_or(UnknownReason::Invalid)?;
        let component = |getter: unsafe extern "C" fn(*mut c_void) -> *const c_char| {
            let ptr = unsafe { getter(parsed.0.as_ptr()) };
            if ptr.is_null() {
                return Err(UnknownReason::Invalid);
            }
            let value = unsafe { CStr::from_ptr(ptr) }
                .to_str()
                .map_err(|_| UnknownReason::Invalid)?;
            if value.is_empty() {
                return Err(UnknownReason::Invalid);
            }
            Ok(value.to_owned())
        };
        component(context_user_get)?;
        component(context_role_get)?;
        let type_name = component(context_type_get)?;
        Ok(Self {
            raw: text.to_owned(),
            type_name,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    #[cfg(test)]
    pub(crate) fn for_test(raw: &str) -> Self {
        Self::parse(&CString::new(raw).unwrap()).unwrap()
    }
}

fn query_context(
    query: impl FnOnce(*mut *mut c_char) -> c_int,
) -> Result<SecurityContext, UnknownReason> {
    let mut ptr = std::ptr::null_mut();
    let status = query(&mut ptr);
    // Own even a non-null error result before taking any early return.
    let raw = NonNull::new(ptr).map(RawContext);
    if status < 0 {
        return Err(UnknownReason::QueryFailed);
    }
    let raw = raw.ok_or(UnknownReason::Empty)?;
    SecurityContext::parse(unsafe { CStr::from_ptr(raw.0.as_ptr()) })
}

pub fn compositor_context() -> anyhow::Result<SecurityContext> {
    anyhow::ensure!(
        unsafe { is_selinux_enabled() } > 0,
        "SELinux is unavailable"
    );
    let context = query_context(|ptr| unsafe { getcon_raw(ptr) })
        .map_err(|reason| anyhow::anyhow!("cannot query compositor context: {reason:?}"))?;
    require_compositor(context)
}

fn require_compositor(context: SecurityContext) -> anyhow::Result<SecurityContext> {
    anyhow::ensure!(
        context.type_name() == "niri_t",
        "protected session requires niri_t"
    );
    Ok(context)
}

pub fn lock_denial(restricted: bool, peer: &PeerLabel) -> Option<&'static str> {
    if restricted {
        return Some("restricted-client");
    }
    match peer {
        PeerLabel::Known(context) if context.type_name() == "locker_t" => None,
        PeerLabel::Known(_) => Some("peer-type"),
        PeerLabel::Unknown(reason) => Some(reason.as_str()),
    }
}

pub fn audit_lock_denial(
    peer: &PeerLabel,
    server: &SecurityContext,
    connection: String,
    reason: &str,
) {
    let peer_context = match peer {
        PeerLabel::Known(context) => Some(context.raw()),
        PeerLabel::Unknown(_) => None,
    };
    let event = serde_json::json!({
        "manager": "niri", "op": "session-lock", "peer_context": peer_context,
        "server_context": server.raw(), "connection": connection, "reason": reason,
    });
    warn!("avc: denied {event}");
}

pub fn peer_label(fd: RawFd, direct: bool) -> PeerLabel {
    if !direct {
        return PeerLabel::Unknown(UnknownReason::NotDirect);
    }
    match query_context(|ptr| unsafe { getpeercon_raw(fd, ptr) }) {
        Ok(context) => PeerLabel::Known(context),
        Err(reason) => PeerLabel::Unknown(reason),
    }
}

#[cfg(test)]
thread_local! {
    static FREED: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p13_compositor_context_requires_its_exact_kernel_type() {
        assert!(require_compositor(SecurityContext::for_test("u:r:niri_t:s0")).is_ok());
        assert!(require_compositor(SecurityContext::for_test("u:r:unconfined_t:s0")).is_err());
        assert!(require_compositor(SecurityContext::for_test("u:r:niri_t_extra:s0")).is_err());
    }

    #[test]
    fn p13_restricted_and_unknown_peers_cannot_acquire_the_lock() {
        let locker = PeerLabel::Known(SecurityContext::for_test("u:r:locker_t:s0"));
        assert_eq!(lock_denial(false, &locker), None);
        assert_eq!(lock_denial(true, &locker), Some("restricted-client"));
        assert_eq!(
            lock_denial(false, &PeerLabel::Unknown(UnknownReason::NotDirect)),
            Some("unknown-provenance")
        );
        assert_eq!(
            lock_denial(
                false,
                &PeerLabel::Known(SecurityContext::for_test("u:r:locker_t_extra:s0"))
            ),
            Some("peer-type")
        );
    }

    fn supplied(text: &CStr, status: c_int) -> Result<SecurityContext, UnknownReason> {
        query_context(|ptr| unsafe {
            *ptr = libc::strdup(text.as_ptr());
            status
        })
    }

    #[test]
    fn p13_context_api_extracts_exact_type_and_preserves_raw_context() {
        let raw = c"system_u:system_r:locker_t:s0:c1,c3";
        let context = supplied(raw, 0).unwrap();
        assert_eq!(context.raw(), raw.to_str().unwrap());
        assert_eq!(context.type_name(), "locker_t");
        assert_ne!(
            supplied(c"u:r:locker_t_extra:s0", 0).unwrap().type_name(),
            "locker_t"
        );
        assert!(supplied(c"invalid", 0).is_err());
        assert!(supplied(c"u::locker_t:s0", 0).is_err());
    }

    #[test]
    fn p13_query_errors_empty_and_invalid_contexts_release_resources() {
        FREED.with(|count| count.set((0, 0)));
        assert_eq!(
            supplied(c"u:r:locker_t:s0", -1),
            Err(UnknownReason::QueryFailed)
        );
        assert_eq!(supplied(c"", 0), Err(UnknownReason::Empty));
        assert_eq!(supplied(c"invalid", 0), Err(UnknownReason::Invalid));
        assert_eq!(query_context(|_| 0), Err(UnknownReason::Empty));
        assert!(supplied(c"u::locker_t:s0", 0).is_err());
        assert!(supplied(c"u:r:locker_t:s0", 0).is_ok());
        FREED.with(|count| assert_eq!(count.get(), (5, 2)));
    }

    #[test]
    fn p13_every_non_listener_origin_is_unknown_even_with_a_socket_label() {
        assert_eq!(
            peer_label(-1, false),
            PeerLabel::Unknown(UnknownReason::NotDirect)
        );
        assert_eq!(
            peer_label(-1, true),
            PeerLabel::Unknown(UnknownReason::QueryFailed)
        );
    }
}
