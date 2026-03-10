use std::collections::HashSet;
use std::sync::{Arc, Mutex};

// Verbosity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Notice,
    Info,
    Verbose,
}

// Emoji constants
#[allow(dead_code)]
pub const EMOJI_GLOBE: &str = "\u{1F30D}";
pub const EMOJI_WARNING: &str = "\u{26A0}\u{FE0F}";
pub const EMOJI_ERROR: &str = "\u{274C}";
#[allow(dead_code)]
pub const EMOJI_SUCCESS: &str = "\u{2705}";
pub const EMOJI_LAUNCH: &str = "\u{1F680}";
pub const EMOJI_STOP: &str = "\u{1F6D1}";
pub const EMOJI_SLEEP: &str = "\u{1F634}";
pub const EMOJI_DETECT: &str = "\u{1F50D}";
pub const EMOJI_UPDATE: &str = "\u{2B06}\u{FE0F}";
pub const EMOJI_CREATE: &str = "\u{2795}";
pub const EMOJI_DELETE: &str = "\u{2796}";
pub const EMOJI_SKIP: &str = "\u{23ED}\u{FE0F}";
pub const EMOJI_NOTIFY: &str = "\u{1F514}";
pub const EMOJI_HEARTBEAT: &str = "\u{1F493}";
pub const EMOJI_CONFIG: &str = "\u{2699}\u{FE0F}";
#[allow(dead_code)]
pub const EMOJI_HINT: &str = "\u{1F4A1}";

const INDENT_PREFIX: &str = "   ";

pub struct PP {
    pub verbosity: Verbosity,
    pub emoji: bool,
    indent: usize,
    seen: Arc<Mutex<HashSet<String>>>,
}

impl PP {
    pub fn new(emoji: bool, quiet: bool) -> Self {
        Self {
            verbosity: if quiet { Verbosity::Quiet } else { Verbosity::Verbose },
            emoji,
            indent: 0,
            seen: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn default_pp() -> Self {
        Self::new(false, false)
    }

    pub fn is_showing(&self, level: Verbosity) -> bool {
        self.verbosity >= level
    }

    pub fn indent(&self) -> PP {
        PP {
            verbosity: self.verbosity,
            emoji: self.emoji,
            indent: self.indent + 1,
            seen: Arc::clone(&self.seen),
        }
    }

    fn output(&self, emoji: &str, msg: &str) {
        let prefix = INDENT_PREFIX.repeat(self.indent);
        if self.emoji && !emoji.is_empty() {
            println!("{prefix}{emoji} {msg}");
        } else {
            println!("{prefix}{msg}");
        }
    }

    fn output_err(&self, emoji: &str, msg: &str) {
        let prefix = INDENT_PREFIX.repeat(self.indent);
        if self.emoji && !emoji.is_empty() {
            eprintln!("{prefix}{emoji} {msg}");
        } else {
            eprintln!("{prefix}{msg}");
        }
    }

    pub fn infof(&self, emoji: &str, msg: &str) {
        if self.is_showing(Verbosity::Info) {
            self.output(emoji, msg);
        }
    }

    pub fn noticef(&self, emoji: &str, msg: &str) {
        if self.is_showing(Verbosity::Notice) {
            self.output(emoji, msg);
        }
    }

    pub fn warningf(&self, emoji: &str, msg: &str) {
        self.output_err(emoji, msg);
    }

    pub fn errorf(&self, emoji: &str, msg: &str) {
        self.output_err(emoji, msg);
    }

    #[allow(dead_code)]
    pub fn info_once(&self, key: &str, emoji: &str, msg: &str) {
        if self.is_showing(Verbosity::Info) {
            let mut seen = self.seen.lock().unwrap();
            if seen.insert(key.to_string()) {
                self.output(emoji, msg);
            }
        }
    }

    #[allow(dead_code)]
    pub fn notice_once(&self, key: &str, emoji: &str, msg: &str) {
        if self.is_showing(Verbosity::Notice) {
            let mut seen = self.seen.lock().unwrap();
            if seen.insert(key.to_string()) {
                self.output(emoji, msg);
            }
        }
    }

    #[allow(dead_code)]
    pub fn blank_line_if_verbose(&self) {
        if self.is_showing(Verbosity::Verbose) {
            println!();
        }
    }
}

#[allow(dead_code)]
pub fn english_join(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} and {}", items[0], items[1]),
        _ => {
            let (last, rest) = items.split_last().unwrap();
            format!("{}, and {last}", rest.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PP::new with emoji flag ----

    #[test]
    fn new_with_emoji_true() {
        let pp = PP::new(true, false);
        assert!(pp.emoji);
    }

    #[test]
    fn new_with_emoji_false() {
        let pp = PP::new(false, false);
        assert!(!pp.emoji);
    }

    // ---- PP::new with quiet flag (verbosity levels) ----

    #[test]
    fn new_quiet_true_sets_verbosity_quiet() {
        let pp = PP::new(false, true);
        assert_eq!(pp.verbosity, Verbosity::Quiet);
    }

    #[test]
    fn new_quiet_false_sets_verbosity_verbose() {
        let pp = PP::new(false, false);
        assert_eq!(pp.verbosity, Verbosity::Verbose);
    }

    // ---- PP::is_showing at different verbosity levels ----

    #[test]
    fn quiet_shows_only_quiet_level() {
        let pp = PP::new(false, true);
        assert!(pp.is_showing(Verbosity::Quiet));
        assert!(!pp.is_showing(Verbosity::Notice));
        assert!(!pp.is_showing(Verbosity::Info));
        assert!(!pp.is_showing(Verbosity::Verbose));
    }

    #[test]
    fn verbose_shows_all_levels() {
        let pp = PP::new(false, false);
        assert!(pp.is_showing(Verbosity::Quiet));
        assert!(pp.is_showing(Verbosity::Notice));
        assert!(pp.is_showing(Verbosity::Info));
        assert!(pp.is_showing(Verbosity::Verbose));
    }

    #[test]
    fn notice_level_shows_quiet_and_notice_only() {
        let mut pp = PP::new(false, false);
        pp.verbosity = Verbosity::Notice;
        assert!(pp.is_showing(Verbosity::Quiet));
        assert!(pp.is_showing(Verbosity::Notice));
        assert!(!pp.is_showing(Verbosity::Info));
        assert!(!pp.is_showing(Verbosity::Verbose));
    }

    #[test]
    fn info_level_shows_up_to_info() {
        let mut pp = PP::new(false, false);
        pp.verbosity = Verbosity::Info;
        assert!(pp.is_showing(Verbosity::Quiet));
        assert!(pp.is_showing(Verbosity::Notice));
        assert!(pp.is_showing(Verbosity::Info));
        assert!(!pp.is_showing(Verbosity::Verbose));
    }

    // ---- PP::indent ----

    #[test]
    fn indent_increments_indent_level() {
        let pp = PP::new(true, false);
        assert_eq!(pp.indent, 0);
        let child = pp.indent();
        assert_eq!(child.indent, 1);
        let grandchild = child.indent();
        assert_eq!(grandchild.indent, 2);
    }

    #[test]
    fn indent_preserves_verbosity_and_emoji() {
        let pp = PP::new(true, true);
        let child = pp.indent();
        assert_eq!(child.verbosity, pp.verbosity);
        assert_eq!(child.emoji, pp.emoji);
    }

    #[test]
    fn indent_shares_seen_state() {
        let pp = PP::new(false, false);
        let child = pp.indent();

        // Insert via parent's seen set
        pp.seen.lock().unwrap().insert("key1".to_string());

        // Child should observe the same entry
        assert!(child.seen.lock().unwrap().contains("key1"));

        // Insert via child
        child.seen.lock().unwrap().insert("key2".to_string());

        // Parent should observe it too
        assert!(pp.seen.lock().unwrap().contains("key2"));
    }

    // ---- PP::infof, noticef, warningf, errorf - no panic and verbosity gating ----

    #[test]
    fn infof_does_not_panic_when_verbose() {
        let pp = PP::new(false, false);
        pp.infof("", "test info message");
    }

    #[test]
    fn infof_does_not_panic_when_quiet() {
        let pp = PP::new(false, true);
        // Should simply not print, and not panic
        pp.infof("", "test info message");
    }

    #[test]
    fn noticef_does_not_panic_when_verbose() {
        let pp = PP::new(true, false);
        pp.noticef(EMOJI_DETECT, "test notice message");
    }

    #[test]
    fn noticef_does_not_panic_when_quiet() {
        let pp = PP::new(false, true);
        pp.noticef("", "test notice message");
    }

    #[test]
    fn warningf_does_not_panic() {
        let pp = PP::new(true, false);
        pp.warningf(EMOJI_WARNING, "test warning");
    }

    #[test]
    fn warningf_does_not_panic_when_quiet() {
        // warningf always outputs (no verbosity check), just verify no panic
        let pp = PP::new(false, true);
        pp.warningf("", "test warning");
    }

    #[test]
    fn errorf_does_not_panic() {
        let pp = PP::new(true, false);
        pp.errorf(EMOJI_ERROR, "test error");
    }

    #[test]
    fn errorf_does_not_panic_when_quiet() {
        let pp = PP::new(false, true);
        pp.errorf("", "test error");
    }

    // ---- PP::info_once and notice_once ----

    #[test]
    fn info_once_suppresses_duplicates() {
        let pp = PP::new(false, false);
        // First call inserts the key
        pp.info_once("dup_key", "", "first");
        // The key should now be in the seen set
        assert!(pp.seen.lock().unwrap().contains("dup_key"));

        // Calling again with the same key should not insert again (set unchanged)
        let size_before = pp.seen.lock().unwrap().len();
        pp.info_once("dup_key", "", "second");
        let size_after = pp.seen.lock().unwrap().len();
        assert_eq!(size_before, size_after);
    }

    #[test]
    fn info_once_allows_different_keys() {
        let pp = PP::new(false, false);
        pp.info_once("key_a", "", "msg a");
        pp.info_once("key_b", "", "msg b");
        let seen = pp.seen.lock().unwrap();
        assert!(seen.contains("key_a"));
        assert!(seen.contains("key_b"));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn info_once_skipped_when_quiet() {
        let pp = PP::new(false, true);
        pp.info_once("quiet_key", "", "should not register");
        // Because verbosity is Quiet, info_once should not even insert the key
        assert!(!pp.seen.lock().unwrap().contains("quiet_key"));
    }

    #[test]
    fn notice_once_suppresses_duplicates() {
        let pp = PP::new(false, false);
        pp.notice_once("notice_dup", "", "first");
        assert!(pp.seen.lock().unwrap().contains("notice_dup"));

        let size_before = pp.seen.lock().unwrap().len();
        pp.notice_once("notice_dup", "", "second");
        let size_after = pp.seen.lock().unwrap().len();
        assert_eq!(size_before, size_after);
    }

    #[test]
    fn notice_once_skipped_when_quiet() {
        let pp = PP::new(false, true);
        pp.notice_once("quiet_notice", "", "should not register");
        assert!(!pp.seen.lock().unwrap().contains("quiet_notice"));
    }

    #[test]
    fn info_once_shared_via_indent() {
        let pp = PP::new(false, false);
        let child = pp.indent();

        // Mark a key via the parent
        pp.info_once("shared_key", "", "parent");
        assert!(pp.seen.lock().unwrap().contains("shared_key"));

        // Child should see it as already present, so set size stays the same
        let size_before = child.seen.lock().unwrap().len();
        child.info_once("shared_key", "", "child duplicate");
        let size_after = child.seen.lock().unwrap().len();
        assert_eq!(size_before, size_after);

        // Child can add a new key visible to parent
        child.info_once("child_key", "", "child new");
        assert!(pp.seen.lock().unwrap().contains("child_key"));
    }

    // ---- english_join ----

    #[test]
    fn english_join_empty() {
        let items: Vec<String> = vec![];
        assert_eq!(english_join(&items), "");
    }

    #[test]
    fn english_join_single() {
        let items = vec!["alpha".to_string()];
        assert_eq!(english_join(&items), "alpha");
    }

    #[test]
    fn english_join_two() {
        let items = vec!["alpha".to_string(), "beta".to_string()];
        assert_eq!(english_join(&items), "alpha and beta");
    }

    #[test]
    fn english_join_three() {
        let items = vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ];
        assert_eq!(english_join(&items), "alpha, beta, and gamma");
    }

    #[test]
    fn english_join_four() {
        let items = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        assert_eq!(english_join(&items), "a, b, c, and d");
    }

    // ---- default_pp ----

    #[test]
    fn default_pp_is_verbose_no_emoji() {
        let pp = PP::default_pp();
        assert!(!pp.emoji);
        assert_eq!(pp.verbosity, Verbosity::Verbose);
    }
}
