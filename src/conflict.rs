//! Conflict handling for bidirectional Auto-Sync.
//!
//! Per `PLAN/05-autosync.md` §7. A conflict exists when a `commit`/`delete` arrives with
//! `base_cid != receiver's current file_cid` — the receiver's file changed since the initiator last
//! saw it. Policies:
//!   - **LWW (default):** newer `mtime_ms` wins; ties broken by the lexicographically-larger
//!     `file_cid` (deterministic, content-derived). The loser is **always** written as a conflict
//!     copy — LWW never silently destroys data.
//!   - **Copy:** never overwrite; the incoming version always lands as a conflict copy.
//!   - **Crdt:** for registered text extensions, 3-way merge via the shared `TextDoc` engine
//!     (co-developed with Notes). Not implemented in this substrate (M5); falls back to LWW. See
//!     the explicit TODO below.
//!
//! This module is pure decision logic (no I/O), so the LWW tie-break and conflict-copy naming are
//! unit-testable in isolation.

use serde::{Deserialize, Serialize};

/// The conflict resolution policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Last-writer-wins by mtime, cid tie-break; loser kept as a conflict copy.
    #[default]
    Lww,
    /// Never overwrite; incoming always becomes a conflict copy.
    Copy,
    /// CRDT 3-way merge for registered text types (M5; falls back to LWW today).
    Crdt,
}

impl std::str::FromStr for Policy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "lww" => Ok(Policy::Lww),
            "copy" => Ok(Policy::Copy),
            "crdt" => Ok(Policy::Crdt),
            other => Err(anyhow::anyhow!("unknown conflict policy '{other}' (lww|copy|crdt)")),
        }
    }
}

/// What the receiver should do with an incoming write that conflicts with its current file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Apply the incoming bytes as the canonical file (overwrite). `conflict_copy` names a copy of
    /// the LOSER (the previous local version) to preserve, if any.
    TakeIncoming { conflict_copy: Option<String> },
    /// Keep the local file; write the incoming bytes to `conflict_copy` instead.
    KeepLocal { conflict_copy: String },
    /// 3-way merge produced converged bytes (CRDT). The caller writes `merged` as the file.
    Merged { merged: Vec<u8> },
}

/// The inputs a conflict decision needs.
#[derive(Debug, Clone)]
pub struct ConflictInput<'a> {
    /// Relative path under the root (forward-slash).
    pub rel_path: &'a str,
    /// The receiver's current file CID (None == receiver has no such file → no conflict).
    pub local_cid: Option<&'a str>,
    /// The receiver's current file mtime (ms).
    pub local_mtime_ms: u64,
    /// The incoming file CID.
    pub incoming_cid: &'a str,
    /// The incoming file mtime (ms).
    pub incoming_mtime_ms: u64,
    /// What the initiator believed the receiver's file was (the conflict base).
    pub base_cid: Option<&'a str>,
    /// The initiator's node id (short hex) — used to name conflict copies.
    pub initiator_short: &'a str,
}

/// Is this incoming write a conflict? True iff the receiver's current file differs from the
/// initiator's declared base (someone changed the receiver's copy since the initiator last saw it),
/// AND the incoming content actually differs from the local content.
pub fn is_conflict(input: &ConflictInput) -> bool {
    // Same content as local -> idempotent, never a conflict.
    if input.local_cid == Some(input.incoming_cid) {
        return false;
    }
    match (input.local_cid, input.base_cid) {
        // Receiver has no file and initiator expected none -> clean create.
        (None, None) | (None, Some("")) => false,
        // Receiver has a file the initiator did not expect -> conflict.
        (Some(_), None) | (Some(_), Some("")) => true,
        // Receiver's current differs from the base the initiator assumed -> conflict.
        (Some(local), Some(base)) => local != base,
        // Initiator thought receiver had a file; receiver now has none -> not a write conflict
        // (the receiver deleted it; treat the incoming as a re-create).
        (None, Some(_)) => false,
    }
}

/// Decide what to do with an incoming write under `policy`. Pure: returns the action; the caller
/// performs the filesystem effects (and CRDT merge, when wired). When there is no conflict the
/// incoming bytes are simply taken.
pub fn resolve(policy: Policy, input: &ConflictInput) -> Resolution {
    if !is_conflict(input) {
        return Resolution::TakeIncoming { conflict_copy: None };
    }

    match policy {
        Policy::Copy => Resolution::KeepLocal {
            conflict_copy: conflict_copy_name(input.rel_path, input.initiator_short, input.incoming_mtime_ms),
        },
        Policy::Crdt => {
            // The actual 3-way merge needs the file BYTES (base/local/incoming), which is I/O — so
            // it can't happen in this pure decision function. The commit handler attempts
            // `merge3()` for registered text types BEFORE calling `resolve`, and only reaches this
            // arm when the merge wasn't applicable (non-text, missing ancestor, or overlapping
            // edits). In all those cases LWW is the right, lossless fallback (keeps a conflict copy).
            lww(input)
        }
        Policy::Lww => lww(input),
    }
}

/// Last-writer-wins: newer mtime wins; tie broken by lexicographically-larger cid. The loser is
/// always preserved as a conflict copy (never silent data loss).
fn lww(input: &ConflictInput) -> Resolution {
    let incoming_wins = match input.incoming_mtime_ms.cmp(&input.local_mtime_ms) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Tie: deterministic content-derived tie-break.
        std::cmp::Ordering::Equal => {
            input.incoming_cid > input.local_cid.unwrap_or("")
        }
    };
    if incoming_wins {
        // Incoming becomes canonical; preserve the local loser as a conflict copy.
        Resolution::TakeIncoming {
            conflict_copy: Some(conflict_copy_name(
                input.rel_path,
                input.initiator_short,
                input.local_mtime_ms,
            )),
        }
    } else {
        // Local wins; the incoming loser lands as a conflict copy.
        Resolution::KeepLocal {
            conflict_copy: conflict_copy_name(
                input.rel_path,
                input.initiator_short,
                input.incoming_mtime_ms,
            ),
        }
    }
}

/// Conflict-copy name: `<stem>.conflict-<short>-<unixsecs><ext>`. Keeps the original extension so
/// editors still recognise the type.
pub fn conflict_copy_name(rel_path: &str, short: &str, mtime_ms: u64) -> String {
    let secs = mtime_ms / 1000;
    // Split off the final path component and its extension.
    let (dir, name) = match rel_path.rsplit_once('/') {
        Some((d, n)) => (Some(d), n),
        None => (None, rel_path),
    };
    let (stem, ext) = match name.rsplit_once('.') {
        // Avoid treating a leading-dot dotfile (".bashrc") as all-extension.
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    let renamed = format!("{stem}.conflict-{short}-{secs}{ext}");
    match dir {
        Some(d) => format!("{d}/{renamed}"),
        None => renamed,
    }
}

/// Outcome of a 3-way text merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merge3 {
    /// Non-overlapping concurrent edits merged cleanly into these bytes.
    Clean(Vec<u8>),
    /// Both sides changed the same region — caller falls back to LWW (which keeps both via a
    /// conflict copy, so still lossless).
    Conflict,
    /// One of the three inputs wasn't valid UTF-8 — not a text file, don't merge.
    NotText,
}

/// File extensions whose conflicts are safe to merge as line-oriented text. Anything not listed
/// (binaries, images, archives) falls back to LWW so we never interleave non-text bytes.
pub fn is_mergeable_text(rel_path: &str) -> bool {
    const EXTS: &[&str] = &[
        // code
        "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "java", "kt", "swift", "rb",
        "php", "c", "h", "cc", "cpp", "hpp", "cs", "scala", "lua", "ex", "exs", "dart", "sh",
        "bash", "zsh", "sql", "r", "pl", "m",
        // prose / docs
        "md", "markdown", "txt", "rst", "adoc", "tex", "org",
        // config / data
        "toml", "yaml", "yml", "json", "jsonc", "ini", "cfg", "conf", "env", "properties",
        // web
        "html", "htm", "css", "scss", "sass", "less", "xml", "svg", "vue", "svelte",
        // dotfiles-as-extension
        "gitignore", "ceignore", "dockerignore", "editorconfig", "gitattributes",
    ];
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => EXTS.contains(&ext.to_ascii_lowercase().as_str()),
        // Leading-dot dotfile like ".gitignore": treat the name-after-the-dot as the type.
        _ => name
            .strip_prefix('.')
            .map(|n| EXTS.contains(&n.to_ascii_lowercase().as_str()))
            .unwrap_or(false),
    }
}

/// Three-way merge: reconcile `local` and `incoming` against their common ancestor `base`.
/// Non-overlapping concurrent edits converge into one file; edits to the same region report
/// [`Merge3::Conflict`]. This is the git-style merge — exactly what you want when two machines edit
/// one tree: a change to the top of a file and a change to the bottom merge automatically, and only
/// genuine same-line collisions need fallback handling.
pub fn merge3(base: &[u8], local: &[u8], incoming: &[u8]) -> Merge3 {
    let (b, ours, theirs) = match (
        std::str::from_utf8(base),
        std::str::from_utf8(local),
        std::str::from_utf8(incoming),
    ) {
        (Ok(b), Ok(o), Ok(t)) => (b, o, t),
        _ => return Merge3::NotText,
    };
    match diffy::merge(b, ours, theirs) {
        Ok(merged) => Merge3::Clean(merged.into_bytes()),
        Err(_) => Merge3::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        local: Option<&'a str>,
        local_mt: u64,
        incoming: &'a str,
        incoming_mt: u64,
        base: Option<&'a str>,
    ) -> ConflictInput<'a> {
        ConflictInput {
            rel_path: "docs/x.md",
            local_cid: local,
            local_mtime_ms: local_mt,
            incoming_cid: incoming,
            incoming_mtime_ms: incoming_mt,
            base_cid: base,
            initiator_short: "laptop01",
        }
    }

    #[test]
    fn policy_from_str() {
        assert_eq!("lww".parse::<Policy>().unwrap(), Policy::Lww);
        assert_eq!("COPY".parse::<Policy>().unwrap(), Policy::Copy);
        assert_eq!("crdt".parse::<Policy>().unwrap(), Policy::Crdt);
        assert!("nope".parse::<Policy>().is_err());
    }

    #[test]
    fn no_conflict_on_clean_update() {
        // Receiver's current == base the initiator assumed -> no conflict.
        let inp = input(Some("old"), 100, "new", 200, Some("old"));
        assert!(!is_conflict(&inp));
        assert_eq!(
            resolve(Policy::Lww, &inp),
            Resolution::TakeIncoming { conflict_copy: None }
        );
    }

    #[test]
    fn no_conflict_on_idempotent_same_content() {
        let inp = input(Some("same"), 100, "same", 50, None);
        assert!(!is_conflict(&inp));
    }

    #[test]
    fn conflict_when_receiver_diverged_from_base() {
        // initiator assumed base "old" but receiver now holds "mine".
        let inp = input(Some("mine"), 150, "theirs", 200, Some("old"));
        assert!(is_conflict(&inp));
    }

    #[test]
    fn lww_incoming_newer_takes_incoming_and_keeps_local_copy() {
        let inp = input(Some("mine"), 100, "theirs", 200, Some("old"));
        match resolve(Policy::Lww, &inp) {
            Resolution::TakeIncoming { conflict_copy: Some(name) } => {
                assert!(name.contains(".conflict-laptop01-"));
                assert!(name.ends_with(".md"));
            }
            other => panic!("expected TakeIncoming with copy, got {other:?}"),
        }
    }

    #[test]
    fn lww_local_newer_keeps_local_writes_incoming_copy() {
        let inp = input(Some("mine"), 300, "theirs", 200, Some("old"));
        match resolve(Policy::Lww, &inp) {
            Resolution::KeepLocal { conflict_copy } => {
                assert!(conflict_copy.contains(".conflict-laptop01-"));
            }
            other => panic!("expected KeepLocal, got {other:?}"),
        }
    }

    #[test]
    fn lww_tie_broken_by_larger_cid() {
        // equal mtime; incoming cid "zzz" > local "aaa" -> incoming wins.
        let inp = input(Some("aaa"), 100, "zzz", 100, Some("old"));
        assert!(matches!(resolve(Policy::Lww, &inp), Resolution::TakeIncoming { .. }));
        // reversed: incoming "aaa" < local "zzz" -> local wins.
        let inp2 = input(Some("zzz"), 100, "aaa", 100, Some("old"));
        assert!(matches!(resolve(Policy::Lww, &inp2), Resolution::KeepLocal { .. }));
    }

    #[test]
    fn copy_policy_never_overwrites() {
        let inp = input(Some("mine"), 100, "theirs", 999, Some("old"));
        assert!(matches!(resolve(Policy::Copy, &inp), Resolution::KeepLocal { .. }));
    }

    #[test]
    fn conflict_copy_naming_preserves_extension_and_dir() {
        let n = conflict_copy_name("docs/notes.md", "abc123", 1_718_900_000_000);
        assert_eq!(n, "docs/notes.conflict-abc123-1718900000.md");
        // no extension
        let n2 = conflict_copy_name("README", "abc123", 2000);
        assert_eq!(n2, "README.conflict-abc123-2");
        // dotfile is not split on its leading dot
        let n3 = conflict_copy_name(".bashrc", "abc123", 2000);
        assert_eq!(n3, ".bashrc.conflict-abc123-2");
    }

    #[test]
    fn merge3_non_overlapping_edits_converge() {
        // base, then each side edits a DIFFERENT line — a clean 3-way merge.
        let base = b"line1\nline2\nline3\n";
        let local = b"LINE1\nline2\nline3\n"; // edited the first line
        let incoming = b"line1\nline2\nLINE3\n"; // edited the last line
        match merge3(base, local, incoming) {
            Merge3::Clean(m) => {
                let s = String::from_utf8(m).unwrap();
                assert!(s.contains("LINE1"), "kept local edit: {s}");
                assert!(s.contains("LINE3"), "kept incoming edit: {s}");
            }
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn merge3_same_line_collision_is_conflict() {
        let base = b"hello\n";
        let local = b"hello local\n";
        let incoming = b"hello remote\n";
        assert_eq!(merge3(base, local, incoming), Merge3::Conflict);
    }

    #[test]
    fn merge3_identical_sides_is_clean() {
        let base = b"a\nb\n";
        let same = b"a\nB\n";
        assert!(matches!(merge3(base, same, same), Merge3::Clean(_)));
    }

    #[test]
    fn merge3_non_utf8_is_not_text() {
        let bin = &[0xff, 0xfe, 0x00, 0x01][..];
        assert_eq!(merge3(b"base", bin, b"x"), Merge3::NotText);
    }

    #[test]
    fn mergeable_text_extensions() {
        for p in ["a.rs", "src/b.ts", "C.MD", "deep/dir/x.toml", ".gitignore", "ce/.ceignore", "n.py"] {
            assert!(is_mergeable_text(p), "{p} should be mergeable");
        }
        for p in ["logo.png", "a.bin", "archive.tar", "data.sqlite", "noext", "x.exe"] {
            assert!(!is_mergeable_text(p), "{p} should NOT be mergeable");
        }
    }
}
