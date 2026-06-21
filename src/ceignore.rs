//! `.ceignore` — gitignore-semantics path matching for Auto-Sync.
//!
//! Per `PLAN/05-autosync.md` §5: full gitignore semantics — negation (`!`), `**`, anchored
//! patterns (`/foo`), directory-only patterns (`dir/`), and built-in low-priority defaults
//! (`.git`, `target`, `node_modules`, `.DS_Store`, editor temp suffixes) that a user's `.ceignore`
//! can re-include with a `!` rule. Later rules win (last-match semantics, like gitignore).
//!
//! This is a self-contained matcher (no external `ignore` crate) so it is pure, deterministic, and
//! unit-testable, and so the substrate carries no heavy dependency for `ce-pin`/Notes to inherit.
//! It implements the subset of gitignore semantics Auto-Sync needs; it is intentionally not a
//! byte-for-byte git reimplementation (no `.gitignore`-precedence across nested directories — a
//! single root `.ceignore` plus built-in defaults).

/// A compiled set of ignore rules. Match a forward-slash relative path with [`Matcher::is_ignored`].
#[derive(Debug, Clone)]
pub struct Matcher {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct Rule {
    /// The glob, normalised (leading slash stripped into `anchored`).
    pattern: String,
    /// `true` for a `!pattern` rule (re-include).
    negated: bool,
    /// `true` if the pattern was anchored to the root (had a leading `/` or a non-trailing `/`).
    anchored: bool,
    /// `true` if the pattern ended with `/` (matches directories only).
    dir_only: bool,
}

/// Built-in default ignores, applied at lowest priority so a `.ceignore` `!rule` can re-include.
/// Mirrors (and extends) rdev's historic hard-coded `SKIP` set.
pub const BUILTIN_DEFAULTS: &[&str] =
    &[".git/", "target/", "node_modules/", ".DS_Store", "*~", "*.swp", "*.tmp", ".#*"];

impl Matcher {
    /// Build a matcher from the built-in defaults only.
    pub fn builtin() -> Self {
        let mut rules = Vec::new();
        for p in BUILTIN_DEFAULTS {
            if let Some(r) = Rule::parse(p) {
                rules.push(r);
            }
        }
        Matcher { rules }
    }

    /// Build a matcher from `.ceignore` file contents, with built-in defaults prepended at lowest
    /// priority (so user rules — including `!`-negations of a default — override them).
    pub fn from_ceignore(contents: &str) -> Self {
        let mut m = Self::builtin();
        for line in contents.lines() {
            let line = strip_comment_and_trim(line);
            if line.is_empty() {
                continue;
            }
            if let Some(r) = Rule::parse(line) {
                m.rules.push(r);
            }
        }
        m
    }

    /// Is `rel_path` (forward-slash, relative to the tree root) ignored? `is_dir` selects whether
    /// directory-only (`dir/`) rules apply. Last matching rule wins; a negated last match
    /// re-includes.
    pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let path = rel_path.trim_start_matches('/');
        let mut ignored = false;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                // A `dir/` rule matches a directory, OR any path *under* that directory. We model
                // the latter by also testing the rule's pattern (without dir_only) as a prefix.
                if rule.matches_prefix(path) {
                    ignored = !rule.negated;
                }
                continue;
            }
            if rule.matches(path) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

fn strip_comment_and_trim(line: &str) -> &str {
    // A leading '#' is a comment; '\#' would be a literal but we don't support escapes (no real
    // file starts with '#'). Trailing whitespace is stripped; gitignore keeps trailing-backslash
    // spaces, which we don't support.
    let line = line.trim_end();
    if line.starts_with('#') {
        return "";
    }
    line
}

impl Rule {
    fn parse(raw: &str) -> Option<Rule> {
        let mut s = raw;
        let negated = s.starts_with('!');
        if negated {
            s = &s[1..];
        }
        if s.is_empty() {
            return None;
        }
        let dir_only = s.ends_with('/');
        let s = s.trim_end_matches('/');
        // Anchored if it had a leading '/', or contains a '/' anywhere (a slash makes it
        // root-relative in gitignore). A leading '/' is stripped.
        let leading_slash = s.starts_with('/');
        let s = s.trim_start_matches('/');
        if s.is_empty() {
            return None;
        }
        let anchored = leading_slash || s.contains('/');
        Some(Rule { pattern: s.to_string(), negated, anchored, dir_only })
    }

    /// Does this rule match `path` exactly (as a file or directory entry)?
    fn matches(&self, path: &str) -> bool {
        if self.anchored {
            glob_match(&self.pattern, path)
        } else {
            // Unanchored: match against the path's basename OR any path component segment.
            // gitignore unanchored patterns match at any depth.
            if glob_match(&self.pattern, path) {
                return true;
            }
            // match against the final component and against any suffix segment.
            path.split('/').any(|seg| glob_match(&self.pattern, seg))
                || self.matches_any_suffix(path)
        }
    }

    /// For a `dir/` rule applied to a NON-directory `path`: does `path` sit strictly *inside* the
    /// matched directory? Tests each *ancestor* directory of `path` (never the full path itself —
    /// a file whose name equals the dir pattern is not matched by a directory-only rule).
    fn matches_prefix(&self, path: &str) -> bool {
        let segs: Vec<&str> = path.split('/').collect();
        // Build each proper prefix (ancestor dir): segs[0], segs[0]/segs[1], ... up to len-1.
        for end in 1..segs.len() {
            let ancestor = segs[..end].join("/");
            if self.matches(&ancestor) {
                return true;
            }
        }
        false
    }

    fn matches_any_suffix(&self, path: &str) -> bool {
        // e.g. pattern "node_modules" should match "a/node_modules/x"? Only the segment form
        // handles that; this catches multi-segment unanchored patterns like "a/b".
        let parts: Vec<&str> = path.split('/').collect();
        for start in 0..parts.len() {
            let suffix = parts[start..].join("/");
            if glob_match(&self.pattern, &suffix) {
                return true;
            }
        }
        false
    }
}

/// Glob match supporting `*` (any run of non-`/` chars), `?` (one non-`/` char), and `**` (any run
/// including `/`). Anchored at both ends. No character classes (`[a-z]`) — not needed by `.ceignore`
/// in practice and kept out to stay deterministic and small.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_inner(pat: &[u8], txt: &[u8]) -> bool {
    // Handle `**` first (matches across '/').
    if let Some(idx) = find_double_star(pat) {
        let (before, after_raw) = pat.split_at(idx);
        // after_raw starts with "**"; skip it and an optional following '/'.
        let mut after = &after_raw[2..];
        if after.first() == Some(&b'/') {
            after = &after[1..];
        }
        // `**` can consume zero or more leading segments of txt.
        // Try every split point of txt where `before` matches the prefix.
        // Simplest: `before` must match a prefix that ends at a '/' boundary (or empty),
        // then `after` (which may itself contain `**`) matches some suffix.
        // Iterate all suffixes.
        for start in 0..=txt.len() {
            // `before` (no `**`) must match txt[..start] exactly via single-segment glob,
            // but `before` can contain `*`/`?`. Use a boundary-respecting single match.
            if single_glob(before, &txt[..start]) {
                let rest = &txt[start..];
                // `**` at the very end (empty `after`) consumes the entire remaining text.
                if after.is_empty() {
                    return true;
                }
                // Otherwise match `after` against every remaining suffix that begins at a segment
                // boundary (so `**` eats whole segments).
                for s in seg_starts(rest) {
                    if glob_inner(after, &rest[s..]) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    single_glob(pat, txt)
}

/// Offsets within `txt` that begin a new path segment (0 and each index after a '/').
fn seg_starts(txt: &[u8]) -> Vec<usize> {
    let mut v = vec![0usize];
    for (i, &b) in txt.iter().enumerate() {
        if b == b'/' {
            v.push(i + 1);
        }
    }
    v
}

fn find_double_star(pat: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < pat.len() {
        if pat[i] == b'*' && pat[i + 1] == b'*' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Single-level glob: `*` and `?` do NOT cross '/'. No `**` here.
fn single_glob(pat: &[u8], txt: &[u8]) -> bool {
    // Iterative backtracking matcher.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while t < txt.len() {
        if p < pat.len() && (pat[p] == txt[t] || (pat[p] == b'?' && txt[t] != b'/')) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            // Backtrack: let the last '*' consume one more char, but never across '/'.
            if txt[star_t] == b'/' {
                return false;
            }
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_glob_basics() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "main.txt"));
        assert!(glob_match("foo?", "foob"));
        assert!(!glob_match("*.rs", "src/main.rs")); // * does not cross '/'
        assert!(glob_match("a/b.rs", "a/b.rs"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn double_star_crosses_slashes() {
        assert!(glob_match("**/main.rs", "src/deep/main.rs"));
        assert!(glob_match("**/main.rs", "main.rs"));
        assert!(glob_match("src/**", "src/a/b/c.rs"));
        assert!(glob_match("src/**/x.rs", "src/a/b/x.rs"));
        assert!(!glob_match("src/**/x.rs", "other/a/x.rs"));
    }

    #[test]
    fn builtin_defaults_ignore_common() {
        let m = Matcher::builtin();
        assert!(m.is_ignored("target", true));
        assert!(m.is_ignored("target/debug/foo", false));
        assert!(m.is_ignored(".git", true));
        assert!(m.is_ignored("src/.git/config", false));
        assert!(m.is_ignored(".DS_Store", false));
        assert!(m.is_ignored("foo.swp", false));
        assert!(m.is_ignored("a/b/foo~", false));
        assert!(!m.is_ignored("src/main.rs", false));
    }

    #[test]
    fn negation_reincludes() {
        let m = Matcher::from_ceignore("*.log\n!keep.log\n");
        assert!(m.is_ignored("app.log", false));
        assert!(!m.is_ignored("keep.log", false));
    }

    #[test]
    fn negation_can_reinclude_a_builtin() {
        let m = Matcher::from_ceignore("!target/\n");
        // user re-included target -> no longer ignored
        assert!(!m.is_ignored("target", true));
    }

    #[test]
    fn anchored_vs_unanchored() {
        // anchored: only at root
        let m = Matcher::from_ceignore("/build\n");
        assert!(m.is_ignored("build", true));
        assert!(!m.is_ignored("sub/build", true));
        // unanchored: any depth
        let m2 = Matcher::from_ceignore("build\n");
        assert!(m2.is_ignored("build", true));
        assert!(m2.is_ignored("sub/build", true));
    }

    #[test]
    fn dir_only_rule_matches_dir_and_contents_not_file() {
        let m = Matcher::from_ceignore("logs/\n");
        assert!(m.is_ignored("logs", true));
        assert!(m.is_ignored("logs/today.txt", false));
        // a *file* named logs is not ignored by a dir-only rule
        assert!(!m.is_ignored("logs", false));
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let m = Matcher::from_ceignore("# a comment\n\n  \n*.bak\n");
        assert!(m.is_ignored("x.bak", false));
        assert!(!m.is_ignored("x.rs", false));
    }

    #[test]
    fn last_match_wins() {
        // ignore everything in dist, then re-include dist/keep.txt, then re-ignore it
        let m = Matcher::from_ceignore("dist/**\n!dist/keep.txt\ndist/keep.txt\n");
        assert!(m.is_ignored("dist/keep.txt", false));
    }
}
