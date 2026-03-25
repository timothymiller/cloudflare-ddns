// Verbosity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Notice,
    Info,
    Verbose,
}

// Emoji constants
pub const EMOJI_WARNING: &str = "\u{26A0}\u{FE0F}";
pub const EMOJI_ERROR: &str = "\u{274C}";
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

const INDENT_PREFIX: &str = "   ";

pub struct PP {
    pub verbosity: Verbosity,
    pub emoji: bool,
    indent: usize,
}

impl PP {
    pub fn new(emoji: bool, quiet: bool) -> Self {
        Self {
            verbosity: if quiet { Verbosity::Quiet } else { Verbosity::Verbose },
            emoji,
            indent: 0,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn infof_does_not_panic_when_verbose() {
        let pp = PP::new(false, false);
        pp.infof("", "test info message");
    }

    #[test]
    fn infof_does_not_panic_when_quiet() {
        let pp = PP::new(false, true);
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

    #[test]
    fn default_pp_is_verbose_no_emoji() {
        let pp = PP::default_pp();
        assert!(!pp.emoji);
        assert_eq!(pp.verbosity, Verbosity::Verbose);
    }
}
