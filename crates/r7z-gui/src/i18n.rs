//! Interface languages. The English text is the key: `tr("Extract here")` gives it in the
//! current language, and `tf!("Extract to {}", name)` also fills in placeholders, as
//! `format!` does. Text with no translation shows in English.
//!
//! Translations live in `res/lang/`, one file per language, so they can be corrected
//! without touching any Rust. See the top of `zh-CN.txt` for the format.

use std::collections::HashMap;
use std::fmt::{Display, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Lang {
    English,
    SimplifiedChinese,
}

/// Settings → Language.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Preference {
    System,
    English,
    SimplifiedChinese,
}

impl Preference {
    pub fn key(self) -> &'static str {
        match self {
            Preference::System => "system",
            Preference::English => "en",
            Preference::SimplifiedChinese => "zh-CN",
        }
    }

    pub fn parse(saved: Option<&str>) -> Preference {
        match saved {
            Some("en") => Preference::English,
            Some("zh-CN") => Preference::SimplifiedChinese,
            _ => Preference::System,
        }
    }

    pub fn lang(self) -> Lang {
        match self {
            Preference::System => system_lang(),
            Preference::English => Lang::English,
            Preference::SimplifiedChinese => Lang::SimplifiedChinese,
        }
    }
}

/// Traditional Chinese readers get English rather than the wrong script.
#[cfg(any(windows, test))]
fn lang_for_windows(id: u16) -> Lang {
    match id {
        0x0804 | 0x1004 | 0x0004 | 0x7804 => Lang::SimplifiedChinese,
        _ => Lang::English,
    }
}

#[cfg(windows)]
fn system_lang() -> Lang {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // SAFETY: takes no arguments and only returns a language ID.
    lang_for_windows(unsafe { GetUserDefaultUILanguage() })
}

#[cfg(not(windows))]
fn system_lang() -> Lang {
    Lang::English
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn current() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        0 => Lang::English,
        _ => Lang::SimplifiedChinese,
    }
}

pub fn set(lang: Lang) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

/// `english` in the current language.
pub fn tr(english: &'static str) -> &'static str {
    translate(current(), english)
}

fn translate(lang: Lang, english: &'static str) -> &'static str {
    match lang {
        Lang::English => english,
        Lang::SimplifiedChinese => zh_cn().get(english).copied().unwrap_or(english),
    }
}

fn zh_cn() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| parse(include_str!("../res/lang/zh-CN.txt")))
}

/// A translation file: an English line, then its translation, with blank lines and `#`
/// comments anywhere between pairs. `\n` stands for a line break.
fn parse(text: &'static str) -> HashMap<&'static str, &'static str> {
    let mut lines = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
    let mut table = HashMap::new();
    while let (Some(english), Some(translated)) = (lines.next(), lines.next()) {
        table.insert(unescape(english), unescape(translated));
    }
    table
}

/// Leaks only the few lines with line breaks; the table lasts as long as the program.
fn unescape(line: &'static str) -> &'static str {
    if line.contains("\\n") {
        Box::leak(line.replace("\\n", "\n").into_boxed_str())
    } else {
        line
    }
}

/// `template` with its placeholders filled in: `{}` takes the next value, `{0}` a value by
/// position (so a translation can reorder them) and `{name}` a value by name. `{{` and
/// `}}` are literal braces, as in `format!`.
pub fn fill(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    let mut next = 0;
    while let Some(at) = rest.find(['{', '}']) {
        out.push_str(&rest[..at]);
        let brace = &rest[at..at + 1];
        let after = &rest[at + 1..];
        if after.starts_with(brace) {
            out.push_str(brace);
            rest = &after[1..];
            continue;
        }
        let close = after.find('}').filter(|_| brace == "{");
        let Some(close) = close else {
            out.push_str(brace);
            rest = after;
            continue;
        };
        let name = &after[..close];
        let value = if name.is_empty() {
            next += 1;
            args.get(next - 1)
        } else if let Ok(position) = name.parse::<usize>() {
            args.get(position)
        } else {
            args.iter().find(|(n, _)| *n == name)
        };
        match value {
            Some((_, value)) => {
                let _ = write!(out, "{value}");
            }
            None => out.push_str(&rest[at..at + close + 2]),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
pub fn translated(english: &str) -> bool {
    zh_cn().contains_key(english)
}

/// `format!` for interface text: `tf!("Extract to {}", name)` or `tf!("Failed: {e}", e = e)`.
/// Values are all positional or all named. Format specs like `{:.1}` aren't supported, so
/// format such a value first.
macro_rules! tf {
    ($key:literal $(,)?) => {
        $crate::i18n::fill($crate::i18n::tr($key), &[])
    };
    ($key:literal, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::fill(
            $crate::i18n::tr($key),
            &[$((stringify!($name), &$value as &dyn std::fmt::Display)),+],
        )
    };
    ($key:literal, $($value:expr),+ $(,)?) => {
        $crate::i18n::fill(
            $crate::i18n::tr($key),
            &[$(("", &$value as &dyn std::fmt::Display)),+],
        )
    };
}
pub(crate) use tf;

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> HashMap<&'static str, &'static str> {
        parse("# a comment\n\nExtract here\n解压到此处\n\nFirst\\nSecond\n第一\\n第二\n")
    }

    #[test]
    fn a_table_is_pairs_of_lines_around_comments_and_blanks() {
        assert_eq!(table().get("Extract here"), Some(&"解压到此处"));
        assert_eq!(table().len(), 2);
    }

    #[test]
    fn a_backslash_n_in_a_table_is_a_line_break() {
        assert_eq!(table().get("First\nSecond"), Some(&"第一\n第二"));
    }

    #[test]
    fn spaces_at_the_ends_of_table_lines_are_kept() {
        let table = parse(", {} left\n，还剩 {} \n");
        assert_eq!(table.get(", {} left"), Some(&"，还剩 {} "));
    }

    #[test]
    fn english_shows_the_key_itself() {
        assert_eq!(translate(Lang::English, "Extract here"), "Extract here");
    }

    #[test]
    fn chinese_shows_the_translation() {
        assert_eq!(translate(Lang::SimplifiedChinese, "Cancel"), "取消");
    }

    #[test]
    fn text_with_no_translation_stays_in_english() {
        let key = "no such text in any language";
        assert_eq!(translate(Lang::SimplifiedChinese, key), key);
    }

    #[test]
    fn placeholders_fill_in_order() {
        let (a, b): (&dyn Display, &dyn Display) = (&"x", &2);
        assert_eq!(fill("{} and {}", &[("", a), ("", b)]), "x and 2");
    }

    #[test]
    fn placeholders_fill_by_name() {
        let e: &dyn Display = &"denied";
        assert_eq!(fill("failed: {e}", &[("e", e)]), "failed: denied");
    }

    #[test]
    fn a_translation_can_reorder_placeholders() {
        let (a, b): (&dyn Display, &dyn Display) = (&"x", &"y");
        assert_eq!(fill("{1} 的 {0}", &[("", a), ("", b)]), "y 的 x");
    }

    #[test]
    fn doubled_braces_are_literal() {
        assert_eq!(fill("{{}} }}{{", &[]), "{} }{");
    }

    #[test]
    fn a_placeholder_with_no_value_stays_visible() {
        assert_eq!(fill("a {missing} b", &[]), "a {missing} b");
    }

    #[test]
    fn tf_takes_positional_named_and_no_arguments() {
        let name = "Backup";
        assert_eq!(tf!("Open {}", name), "Open Backup");
        assert_eq!(tf!("Open {name}", name = name), "Open Backup");
        assert_eq!(tf!("Open"), "Open");
    }

    #[test]
    fn preferences_read_back_as_saved() {
        for p in [
            Preference::System,
            Preference::English,
            Preference::SimplifiedChinese,
        ] {
            assert_eq!(Preference::parse(Some(p.key())), p);
        }
        assert_eq!(Preference::parse(None), Preference::System);
        assert_eq!(Preference::parse(Some("klingon")), Preference::System);
    }

    /// The text of the Rust string literal at the start of `source`.
    fn literal(source: &str) -> String {
        let mut out = String::new();
        let mut chars = source[1..].chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('0') => out.push('\0'),
                    Some('\n') => {
                        while chars.peek().is_some_and(|c| c.is_whitespace()) {
                            chars.next();
                        }
                    }
                    Some(other) => out.push(other),
                    None => break,
                },
                other => out.push(other),
            }
        }
        out
    }

    /// Everything the program passes to `tr` and `tf!` as a literal, read from its sources.
    fn keys_in_source() -> Vec<String> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().is_some_and(|n| n == "i18n.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let code = source.split("#[cfg(test)]\nmod tests").next().unwrap();
            for call in ["tr(", "tf!("] {
                for (at, _) in code.match_indices(call) {
                    let rest = code[at + call.len()..].trim_start();
                    let word_before = code[..at].chars().last();
                    let inside_word = word_before.is_some_and(|c| c.is_alphanumeric() || c == '_');
                    if rest.starts_with('"') && !inside_word {
                        keys.push(literal(rest));
                    }
                }
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }

    #[test]
    fn the_source_scan_finds_interface_text() {
        let keys = keys_in_source();
        assert!(keys.len() > 300, "{}", keys.len());
        assert!(keys.iter().any(|k| k == "Show in Explorer"));
        assert!(keys
            .iter()
            .any(|k| k.starts_with("Open as folder uses Windows")));
    }

    #[test]
    fn all_interface_text_has_a_chinese_translation() {
        let missing: Vec<String> = keys_in_source()
            .into_iter()
            .filter(|k| !zh_cn().contains_key(k.as_str()))
            .map(|k| k.replace('\n', "\\n"))
            .collect();
        assert!(
            missing.is_empty(),
            "{} without a translation:\n{}",
            missing.len(),
            missing.join("\n")
        );
    }

    /// The placeholders of a template, `{}` numbered as a translation would number them.
    fn holes(template: &str) -> Vec<String> {
        let mut next = 0;
        let mut out = Vec::new();
        let text = template.replace("{{", "").replace("}}", "");
        for piece in text.split('{').skip(1) {
            let name = piece.split('}').next().unwrap_or("");
            if name.is_empty() {
                out.push(next.to_string());
                next += 1;
            } else {
                out.push(name.to_string());
            }
        }
        out.sort();
        out
    }

    #[test]
    fn translations_keep_every_placeholder() {
        for (english, chinese) in zh_cn() {
            assert_eq!(holes(english), holes(chinese), "{english}");
        }
    }

    #[test]
    fn translations_contain_chinese_or_are_deliberately_unchanged() {
        for (english, chinese) in zh_cn() {
            assert!(!chinese.is_empty(), "{english}");
            assert!(
                chinese
                    .chars()
                    .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
                    || english == chinese,
                "{english} -> {chinese}"
            );
        }
    }

    #[test]
    fn only_simplified_chinese_windows_asks_for_chinese() {
        for id in [0x0804, 0x1004, 0x0004, 0x7804] {
            assert_eq!(lang_for_windows(id), Lang::SimplifiedChinese, "{id:#x}");
        }
        // English, Traditional Chinese (Taiwan, Hong Kong, Macau), Japanese.
        for id in [0x0409, 0x0404, 0x0C04, 0x1404, 0x0411] {
            assert_eq!(lang_for_windows(id), Lang::English, "{id:#x}");
        }
    }
}
