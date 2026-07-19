//! chitin — on-access malware scanning for Linux.
//!
//! Intercepts execution via fanotify permission events, scans the target with
//! YARA-X, and returns an allow/deny verdict to the kernel. Requires
//! CAP_SYS_ADMIN and kernel >= 3.8 (>= 5.0 for FAN_OPEN_EXEC_PERM).

use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};
use nix::sys::stat::fstat;

/// Files above this size are allowed unscanned.
/// ponytail: flat cap; make it per-rule or stream into the scanner if large
/// binaries turn out to matter.
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;

/// Identifies file content without hashing it. Cheap enough to check on every
/// exec, which is the point — /bin/sh is scanned once, not thousands of times.
/// ponytail: stat-based, so content swapped without touching mtime/size is
/// missed. Switch to blake3 of the contents if that threat matters.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
struct FileId {
    dev: u64,
    ino: u64,
    mtime: i64,
    size: i64,
}

impl FileId {
    fn of(fd: BorrowedFd) -> nix::Result<Self> {
        let st = fstat(fd)?;
        Ok(FileId {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mtime: st.st_mtime,
            size: st.st_size,
        })
    }
}

/// What we tell the kernel to do with the pending exec.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Verdict {
    Allow,
    Deny,
}

impl From<Verdict> for Response {
    fn from(v: Verdict) -> Response {
        match v {
            Verdict::Allow => Response::FAN_ALLOW,
            Verdict::Deny => Response::FAN_DENY,
        }
    }
}

/// The actual detection decision. Split out from the event loop so it can be
/// tested without root or a live fanotify group.
fn scan_verdict(rules: &yara_x::Rules, data: &[u8]) -> (Verdict, Vec<String>) {
    let mut scanner = yara_x::Scanner::new(rules);
    match scanner.scan(data) {
        Ok(results) => {
            let hits: Vec<String> = results
                .matching_rules()
                .map(|r| r.identifier().to_string())
                .collect();
            if hits.is_empty() {
                (Verdict::Allow, hits)
            } else {
                (Verdict::Deny, hits)
            }
        }
        // A scanner error must not brick the machine: an unscannable file is
        // allowed, not blocked. Availability beats a fail-closed exec path.
        Err(e) => {
            eprintln!("chitin: scan error, allowing: {e}");
            (Verdict::Allow, Vec::new())
        }
    }
}

fn read_capped(fd: BorrowedFd, max: usize) -> nix::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = nix::unistd::read(fd, &mut chunk)?;
        if n == 0 || buf.len() >= max {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    buf.truncate(max);
    Ok(buf)
}

fn path_of(fd: BorrowedFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".into())
}

fn compile_rules(dir: &str) -> Result<yara_x::Rules, Box<dyn std::error::Error>> {
    let mut compiler = yara_x::Compiler::new();
    let mut count = 0;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "yar" || e == "yara") {
            let src = std::fs::read_to_string(&path)?;
            compiler.add_source(src.as_str())?;
            count += 1;
        }
    }
    if count == 0 {
        return Err(format!("no .yar/.yara rules found in {dir}").into());
    }
    eprintln!("chitin: compiled {count} rule file(s) from {dir}");
    Ok(compiler.build())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <rules-dir> [mount-point]", args[0]);
        eprintln!("  scans on exec under <mount-point> (default /), needs root");
        std::process::exit(2);
    }
    let rules = compile_rules(&args[1])?;
    let target = args.get(2).map(String::as_str).unwrap_or("/");

    // FAN_CLASS_CONTENT is required for permission events — notify-class
    // groups cannot return a verdict.
    let fan = Fanotify::init(
        InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC,
        EventFFlags::O_RDONLY,
    )?;

    // AT_FDCWD is ignored for an absolute path, but mark() still wants an fd.
    let cwd = unsafe { BorrowedFd::borrow_raw(nix::libc::AT_FDCWD) };
    fan.mark(
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
        MaskFlags::FAN_OPEN_EXEC_PERM,
        cwd,
        Some(target),
    )?;
    eprintln!("chitin: watching exec on {target}");

    let me = std::process::id() as i32;
    let mut cache: HashMap<FileId, Verdict> = HashMap::new();

    loop {
        for event in fan.read_events()? {
            // Queue overflow: no fd, nothing to respond to.
            let Some(fd) = event.fd() else {
                eprintln!("chitin: event queue overflow");
                continue;
            };

            // Every permission event must get a response or the calling process
            // blocks forever, so the verdict is computed defensively and always
            // written below.
            let verdict = if event.pid() == me {
                // Never adjudicate our own execs — that deadlocks the scanner.
                Verdict::Allow
            } else {
                match FileId::of(fd) {
                    Ok(id) if id.size as usize > MAX_SCAN_BYTES => Verdict::Allow,
                    Ok(id) => match cache.get(&id) {
                        Some(&cached) => cached,
                        None => {
                            let v = match read_capped(fd, MAX_SCAN_BYTES) {
                                Ok(data) => {
                                    let (v, hits) = scan_verdict(&rules, &data);
                                    if v == Verdict::Deny {
                                        println!(
                                            "chitin: DENY pid={} {} [{}]",
                                            event.pid(),
                                            path_of(fd),
                                            hits.join(", ")
                                        );
                                    }
                                    v
                                }
                                Err(e) => {
                                    eprintln!("chitin: read error, allowing: {e}");
                                    Verdict::Allow
                                }
                            };
                            cache.insert(id, v);
                            v
                        }
                    },
                    Err(e) => {
                        eprintln!("chitin: fstat error, allowing: {e}");
                        Verdict::Allow
                    }
                }
            };

            fan.write_response(FanotifyResponse::new(fd, verdict.into()))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> yara_x::Rules {
        let mut c = yara_x::Compiler::new();
        c.add_source(r#"rule eicar_ish { strings: $a = "X5O!P%@AP" condition: $a }"#)
            .unwrap();
        c.build()
    }

    #[test]
    fn denies_matching_content_and_allows_clean() {
        let r = rules();

        let (v, hits) = scan_verdict(&r, b"harmless ELF-ish bytes");
        assert_eq!(v, Verdict::Allow);
        assert!(hits.is_empty());

        let (v, hits) = scan_verdict(&r, b"prefix X5O!P%@AP suffix");
        assert_eq!(v, Verdict::Deny, "matching rule must deny");
        assert_eq!(hits, vec!["eicar_ish"]);
    }

    #[test]
    fn read_cap_is_enforced() {
        // Guards the truncate: a file larger than the cap must not blow memory.
        let f = std::fs::File::open("/dev/zero").unwrap();
        let fd = unsafe { BorrowedFd::borrow_raw(f.as_raw_fd()) };
        let data = read_capped(fd, 1024).unwrap();
        assert_eq!(data.len(), 1024);
    }
}
