//! Code pages for archive names, and choosing the one an archive's names were written in.
//!
//! zip (without the UTF-8 flag), LZH, ARJ and old tar headers store names as bytes in
//! whatever code page the writer used: CP437 or another DOS page on Western systems,
//! Shift-JIS in Japan, GBK in China, Big5 in Taiwan and Hong Kong, CP949 in Korea, CP866 or
//! CP1251 in Russia. Nothing in the archive says which. [`detect`] decodes all of an
//! archive's names with each candidate page and scores the result: decoding errors, then
//! how plausible the characters are for that page (letters of its script in sensible case,
//! common CJK characters, kana only for Japanese and Hangul only for Korean). The best
//! score wins, ties go to the earlier candidate, and CP437 is the fallback, so the same
//! bytes always give the same answer.

use std::sync::OnceLock;

use encoding_rs::Encoding;

/// A code page, by its Windows number (`932`, `1251`, `65001` for UTF-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CodePage(u16);

/// How an archive's legacy names were decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameCoding {
    pub page: CodePage,
    /// The page was chosen by [`detect`] rather than given by the caller.
    pub detected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lang {
    Japanese,
    Simplified,
    Traditional,
    Korean,
}

#[derive(Clone, Copy)]
enum Kind {
    Utf8,
    /// A DOS page from the tables below (bytes 0x80-0xFF).
    Table(&'static [char; 128]),
    Single(&'static Encoding),
    Cjk(&'static Encoding, Lang),
}

struct Page {
    number: u16,
    label: &'static str,
    kind: Kind,
    script: Script,
    /// Tried by [`detect`]. The others are used only when asked for.
    detect: bool,
}

macro_rules! page {
    ($n:expr, $label:expr, $kind:expr, $script:ident, $detect:expr) => {
        Page {
            number: $n,
            label: $label,
            kind: $kind,
            script: Script::$script,
            detect: $detect,
        }
    };
}

/// Every supported page. The detected ones come first, in tie-break order.
static PAGES: &[Page] = &[
    page!(65001, "Unicode (UTF-8)", Kind::Utf8, Other, true),
    page!(437, "DOS Latin US", Kind::Table(&CP437), Latin, true),
    page!(
        850,
        "DOS Western European",
        Kind::Table(&CP850),
        Latin,
        true
    ),
    page!(
        1252,
        "Windows Western European",
        Kind::Single(encoding_rs::WINDOWS_1252),
        Latin,
        true
    ),
    page!(
        932,
        "Japanese (Shift-JIS)",
        Kind::Cjk(encoding_rs::SHIFT_JIS, Lang::Japanese),
        Other,
        true
    ),
    page!(
        936,
        "Chinese Simplified (GBK)",
        Kind::Cjk(encoding_rs::GBK, Lang::Simplified),
        Other,
        true
    ),
    page!(
        950,
        "Chinese Traditional (Big5)",
        Kind::Cjk(encoding_rs::BIG5, Lang::Traditional),
        Other,
        true
    ),
    page!(
        949,
        "Korean (UHC)",
        Kind::Cjk(encoding_rs::EUC_KR, Lang::Korean),
        Other,
        true
    ),
    page!(
        866,
        "DOS Cyrillic",
        Kind::Single(encoding_rs::IBM866),
        Cyrillic,
        true
    ),
    page!(
        1251,
        "Windows Cyrillic",
        Kind::Single(encoding_rs::WINDOWS_1251),
        Cyrillic,
        true
    ),
    page!(
        852,
        "DOS Central European",
        Kind::Table(&CP852),
        Latin,
        true
    ),
    page!(
        1250,
        "Windows Central European",
        Kind::Single(encoding_rs::WINDOWS_1250),
        Latin,
        true
    ),
    page!(737, "DOS Greek", Kind::Table(&CP737), Greek, true),
    page!(
        1253,
        "Windows Greek",
        Kind::Single(encoding_rs::WINDOWS_1253),
        Greek,
        true
    ),
    page!(857, "DOS Turkish", Kind::Table(&CP857), Latin, true),
    page!(
        1254,
        "Windows Turkish",
        Kind::Single(encoding_rs::WINDOWS_1254),
        Latin,
        true
    ),
    page!(
        1257,
        "Windows Baltic",
        Kind::Single(encoding_rs::WINDOWS_1257),
        Latin,
        false
    ),
    page!(
        1258,
        "Windows Vietnamese",
        Kind::Single(encoding_rs::WINDOWS_1258),
        Latin,
        false
    ),
    page!(
        874,
        "Thai",
        Kind::Single(encoding_rs::WINDOWS_874),
        Other,
        false
    ),
    page!(
        1255,
        "Windows Hebrew",
        Kind::Single(encoding_rs::WINDOWS_1255),
        Other,
        false
    ),
    page!(
        1256,
        "Windows Arabic",
        Kind::Single(encoding_rs::WINDOWS_1256),
        Other,
        false
    ),
    page!(
        20866,
        "Cyrillic (KOI8-R)",
        Kind::Single(encoding_rs::KOI8_R),
        Cyrillic,
        false
    ),
    page!(
        21866,
        "Cyrillic (KOI8-U)",
        Kind::Single(encoding_rs::KOI8_U),
        Cyrillic,
        false
    ),
    page!(
        28592,
        "ISO 8859-2",
        Kind::Single(encoding_rs::ISO_8859_2),
        Latin,
        false
    ),
    page!(
        28595,
        "ISO 8859-5",
        Kind::Single(encoding_rs::ISO_8859_5),
        Cyrillic,
        false
    ),
    page!(
        28597,
        "ISO 8859-7",
        Kind::Single(encoding_rs::ISO_8859_7),
        Greek,
        false
    ),
    page!(
        28605,
        "ISO 8859-15",
        Kind::Single(encoding_rs::ISO_8859_15),
        Latin,
        false
    ),
    page!(
        10000,
        "Mac Roman",
        Kind::Single(encoding_rs::MACINTOSH),
        Latin,
        false
    ),
    page!(
        20932,
        "Japanese (EUC-JP)",
        Kind::Cjk(encoding_rs::EUC_JP, Lang::Japanese),
        Other,
        false
    ),
    page!(
        54936,
        "Chinese (GB18030)",
        Kind::Cjk(encoding_rs::GB18030, Lang::Simplified),
        Other,
        false
    ),
];

impl CodePage {
    pub const UTF8: CodePage = CodePage(65001);
    pub const CP437: CodePage = CodePage(437);

    /// The page with Windows number `n`, if supported. `51949` (EUC-KR) is CP949.
    pub fn from_number(n: u32) -> Option<CodePage> {
        let n = if n == 51949 { 949 } else { n };
        PAGES
            .iter()
            .find(|p| u32::from(p.number) == n)
            .map(|p| CodePage(p.number))
    }

    /// Parses `932`, `cp932`, `utf-8`, `utf8`.
    pub fn parse(s: &str) -> Option<CodePage> {
        let l = s.trim().to_ascii_lowercase();
        if l == "utf-8" || l == "utf8" {
            return Some(CodePage::UTF8);
        }
        let digits = l.strip_prefix("cp").unwrap_or(&l);
        CodePage::from_number(digits.parse().ok()?)
    }

    pub fn number(self) -> u16 {
        self.0
    }

    /// A description such as `Japanese (Shift-JIS)`.
    pub fn label(self) -> &'static str {
        self.page().label
    }

    /// Every supported page: the ones [`detect`] considers first, then the others.
    pub fn all() -> impl Iterator<Item = CodePage> {
        PAGES.iter().map(|p| CodePage(p.number))
    }

    fn page(self) -> &'static Page {
        PAGES
            .iter()
            .find(|p| p.number == self.0)
            .expect("CodePage values come from PAGES")
    }

    /// Decodes `b`; bytes that do not form a character become U+FFFD.
    pub fn decode(self, b: &[u8]) -> String {
        if b.is_ascii() {
            return String::from_utf8_lossy(b).into_owned();
        }
        match self.page().kind {
            Kind::Utf8 => String::from_utf8_lossy(b).into_owned(),
            Kind::Table(t) => b
                .iter()
                .map(|&c| {
                    if c < 0x80 {
                        c as char
                    } else {
                        t[c as usize - 0x80]
                    }
                })
                .collect(),
            Kind::Single(e) | Kind::Cjk(e, _) => e.decode_without_bom_handling(b).0.into_owned(),
        }
    }
}

impl std::fmt::Display for CodePage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.0, self.label())
    }
}

/// The page to decode an archive's legacy names with: `forced` if given, otherwise the one
/// [`detect`] picks from `texts` (every name and comment that needs a code page).
pub fn choose<'a>(
    forced: Option<CodePage>,
    texts: impl IntoIterator<Item = &'a [u8]>,
) -> NameCoding {
    match forced {
        Some(page) => NameCoding {
            page,
            detected: false,
        },
        None => NameCoding {
            page: detect(texts),
            detected: true,
        },
    }
}

/// Bytes of non-ASCII text scored per archive; enough to decide, and bounded for archives
/// with millions of names.
const SAMPLE: usize = 64 << 10;

/// Picks the code page `texts` were most plausibly written in. ASCII-only input gives CP437.
pub fn detect<'a>(texts: impl IntoIterator<Item = &'a [u8]>) -> CodePage {
    let mut sample: Vec<&[u8]> = Vec::new();
    let mut total = 0;
    for t in texts {
        if t.is_ascii() {
            continue;
        }
        sample.push(t);
        total += t.len();
        if total >= SAMPLE {
            break;
        }
    }
    if sample.is_empty() {
        return CodePage::CP437;
    }
    let mut best = (CodePage::CP437, 0i64);
    for p in PAGES.iter().filter(|p| p.detect) {
        let s: i64 = sample.iter().map(|t| score(p, t)).sum();
        if s > best.1 {
            best = (CodePage(p.number), s);
        }
    }
    best.0
}

// Scores are in half points: a plausible letter of a single-byte page is worth 4, a common
// CJK character (two bytes) 12, a decoding error -20.
const ERROR: i64 = -20;

fn score(p: &Page, t: &[u8]) -> i64 {
    match p.kind {
        Kind::Utf8 => score_utf8(t),
        Kind::Table(_) | Kind::Single(_) => {
            let chars: Vec<char> = CodePage(p.number).decode(t).chars().collect();
            score_single(&chars, p.script)
        }
        Kind::Cjk(e, lang) => score_cjk(t, e, lang),
    }
}

fn score_utf8(t: &[u8]) -> i64 {
    let s = String::from_utf8_lossy(t);
    let mut total = 0;
    for c in s.chars().filter(|c| !c.is_ascii()) {
        if c == '\u{FFFD}' {
            total += ERROR;
            continue;
        }
        // A valid multi-byte sequence is evidence by itself.
        total += 2 * c.len_utf8() as i64;
        total += if is_han(c) {
            han_score(c, Tier::Normal)
        } else if is_kana(c) {
            10
        } else if is_hangul(c) {
            hangul_score(c, Tier::Normal)
        } else {
            symbol_or_letter(c)
        };
    }
    total
}

/// A character outside CJK in a page that allows every script.
fn symbol_or_letter(c: char) -> i64 {
    if is_pua(c) || c.is_control() {
        -10
    } else if is_junk(c) {
        -6
    } else if c.is_alphabetic() {
        4
    } else {
        0
    }
}

fn script_of(c: char) -> Option<Script> {
    if !c.is_alphabetic() || matches!(c, 'ª' | 'º' | 'µ') {
        return None;
    }
    Some(match c as u32 {
        0x00C0..=0x024F | 0x1E00..=0x1EFF => Script::Latin,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        0x0400..=0x052F => Script::Cyrillic,
        _ => Script::Other,
    })
}

/// Symbols that real names almost never contain but wrong decodings produce plenty of:
/// box drawing, blocks, math, technical marks, spacing accents, C1 controls.
fn is_junk(c: char) -> bool {
    matches!(c as u32,
        0x0080..=0x009F | 0x02B0..=0x02FF | 0x2190..=0x23FF | 0x2500..=0x25FF | 0x2017)
        || matches!(
            c,
            '´' | '¸' | '¨' | '¯' | 'ⁿ' | '₧' | 'ƒ' | '¤' | '¦' | '¬' | '\u{AD}'
        )
}

fn is_letter(c: char) -> bool {
    c.is_alphabetic() && !matches!(c, 'ª' | 'º' | 'µ')
}

/// Single-byte pages: one character per byte, judged with its word.
fn score_single(chars: &[char], script: Script) -> i64 {
    let mut total = 0;
    // Words: runs of letters, digits and non-ASCII characters.
    let separator = |c: char| c.is_ascii() && !c.is_ascii_alphanumeric();
    let mut i = 0;
    while i < chars.len() {
        if separator(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && !separator(chars[i]) {
            i += 1;
        }
        total += score_word(&chars[start..i], script);
    }
    total
}

fn score_word(w: &[char], script: Script) -> i64 {
    let non_ascii = w.iter().filter(|c| !c.is_ascii()).count();
    if non_ascii == 0 {
        return 0;
    }
    // Latin words are mostly ASCII; a word made mostly of accented letters is a decoding of
    // something else (Cyrillic or CJK bytes read as Latin).
    let latin_dense = script == Script::Latin && non_ascii >= 3 && non_ascii * 2 > w.len();
    let mut total = 0;
    for (k, &c) in w.iter().enumerate() {
        if c.is_ascii() {
            continue;
        }
        if c == '\u{FFFD}' {
            total += ERROR;
            continue;
        }
        if c.is_control() || is_pua(c) {
            total -= 10;
            continue;
        }
        let prev = k.checked_sub(1).map(|j| w[j]);
        let next = w.get(k + 1).copied();
        match script_of(c) {
            Some(s) if s == script => {
                let mut v = if latin_dense { 0 } else { 4 };
                if script == Script::Cyrillic && !is_core_cyrillic(c) {
                    v = 2;
                }
                // Cyrillic and Greek letters do not share words with ASCII letters.
                if script != Script::Latin
                    && (prev.is_some_and(|p| p.is_ascii_alphabetic())
                        || next.is_some_and(|n| n.is_ascii_alphabetic()))
                {
                    v -= 4;
                }
                total += v;
            }
            Some(_) => total -= 6,
            None if is_junk(c) => total -= 6,
            None => {
                // A symbol between two letters ("Gr”áe").
                if prev.is_some_and(is_letter) && next.is_some_and(is_letter) {
                    total -= 4;
                }
            }
        }
    }
    total + case_penalty(w)
}

/// А-я, Ё, and the Ukrainian and Belarusian letters.
fn is_core_cyrillic(c: char) -> bool {
    matches!(
        c,
        'А'..='я' | 'Ё' | 'ё' | 'І' | 'і' | 'Ї' | 'ї' | 'Є' | 'є' | 'Ґ' | 'ґ' | 'Ў' | 'ў'
    )
}

/// Words are lowercase, Capitalized or UPPERCASE. An uppercase letter after a lowercase
/// one, or a lowercase letter after two uppercase ones, costs points when either letter is
/// non-ASCII (ASCII names like "iPhone" or "PDFs" are left alone).
fn case_penalty(w: &[char]) -> i64 {
    let letters: Vec<char> = w.iter().copied().filter(|&c| is_letter(c)).collect();
    let mut total = 0;
    for k in 1..letters.len() {
        let (a, b) = (letters[k - 1], letters[k]);
        let bad = (a.is_lowercase() && b.is_uppercase())
            || (k >= 2 && letters[k - 2].is_uppercase() && a.is_uppercase() && b.is_lowercase());
        let involves_non_ascii =
            !a.is_ascii() || !b.is_ascii() || (k >= 2 && !letters[k - 2].is_ascii());
        if bad && involves_non_ascii {
            total -= 6;
        }
    }
    total
}

/// How usual a double-byte character's position in its code page is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// The main block (JIS level 1, GB2312 level 1, Big5 frequent, KS X 1001 Hangul).
    Normal,
    /// Secondary blocks (JIS level 2, GB2312 level 2, Big5 less frequent, Hanja, UHC).
    Rare,
    /// Vendor and extension areas.
    Ext,
}

fn tier(lang: Lang, lead: u8, trail: u8) -> Tier {
    let code = (u16::from(lead) << 8) | u16::from(trail);
    match lang {
        Lang::Japanese => match lead {
            0x88..=0x98 => Tier::Normal,
            0x99..=0x9F | 0xE0..=0xEA => Tier::Rare,
            _ => Tier::Ext,
        },
        Lang::Simplified => match (lead, trail) {
            (0xB0..=0xD7, 0xA1..=0xFF) => Tier::Normal,
            (0xD8..=0xF7, 0xA1..=0xFF) => Tier::Rare,
            _ => Tier::Ext,
        },
        Lang::Traditional => match code {
            0xA440..=0xC67E => Tier::Normal,
            0xC940..=0xF9D5 => Tier::Rare,
            _ => Tier::Ext,
        },
        Lang::Korean => match (lead, trail) {
            (0xB0..=0xC8, 0xA1..=0xFF) => Tier::Normal,
            (0xCA..=0xFD, 0xA1..=0xFF) | (0x81..=0xC6, 0x00..=0xA0) => Tier::Rare,
            _ => Tier::Ext,
        },
    }
}

/// Byte length of the character starting at `t[0]`; 1 for a byte that starts none.
fn cjk_len(t: &[u8], lang: Lang) -> usize {
    let (b, n) = (t[0], t.get(1).copied());
    let two = match lang {
        Lang::Japanese => {
            matches!(b, 0x81..=0x9F | 0xE0..=0xFC)
                && n.is_some_and(|n| matches!(n, 0x40..=0x7E | 0x80..=0xFC))
        }
        Lang::Simplified => {
            if matches!(b, 0x81..=0xFE)
                && matches!(n, Some(0x30..=0x39))
                && t.len() >= 4
                && matches!(t[2], 0x81..=0xFE)
                && matches!(t[3], 0x30..=0x39)
            {
                return 4;
            }
            matches!(b, 0x81..=0xFE) && n.is_some_and(|n| matches!(n, 0x40..=0x7E | 0x80..=0xFE))
        }
        Lang::Traditional => {
            matches!(b, 0x81..=0xFE) && n.is_some_and(|n| matches!(n, 0x40..=0x7E | 0xA1..=0xFE))
        }
        Lang::Korean => {
            matches!(b, 0x81..=0xFE)
                && n.is_some_and(|n| matches!(n, 0x41..=0x5A | 0x61..=0x7A | 0x81..=0xFE))
        }
    };
    if two {
        2
    } else {
        1
    }
}

fn score_cjk(t: &[u8], e: &'static Encoding, lang: Lang) -> i64 {
    let mut total = 0;
    let mut i = 0;
    let mut prev = ' ';
    while i < t.len() {
        if t[i] < 0x80 {
            prev = t[i] as char;
            i += 1;
            continue;
        }
        let n = cjk_len(&t[i..], lang);
        let seg = &t[i..i + n];
        let (s, _) = e.decode_without_bom_handling(seg);
        let mut cs = s.chars();
        let c = cs.next().unwrap_or('\u{FFFD}');
        // One character between ASCII letters, its trail byte a letter too ("Zdj?cia"):
        // an accented letter of a Latin word read as a double-byte pair.
        let alpha = |k: Option<&u8>| k.is_some_and(u8::is_ascii_alphabetic);
        let inside_word = n == 2
            && seg[1].is_ascii_alphabetic()
            && alpha(i.checked_sub(1).and_then(|k| t.get(k)))
            && alpha(t.get(i + n));
        i += n;
        if c == '\u{FFFD}' || cs.next().is_some() {
            total += ERROR;
            continue;
        }
        let tr = if n == 2 {
            tier(lang, seg[0], seg[1])
        } else {
            Tier::Ext
        };
        let v = if is_han(c) {
            han_score(c, tr)
        } else if is_kana(c) {
            if lang == Lang::Japanese {
                10
            } else {
                -4
            }
        } else if is_halfwidth_kana(c) {
            // Voicing marks, the long vowel mark and small kana follow a kana in real
            // Japanese; GBK or Big5 bytes read as halfwidth kana rarely line up that way.
            let after_kana = matches!(prev, 'ｦ'..='ﾝ');
            3 + match c {
                'ﾞ' | 'ﾟ' if after_kana => 6,
                'ｰ' | 'ｧ'..='ｯ' if after_kana => 4,
                _ => 0,
            }
        } else if is_hangul(c) {
            hangul_score(c, tr)
        } else if matches!(c as u32, 0x3400..=0x4DBF | 0xF900..=0xFAFF) {
            -2
        } else if matches!(c as u32, 0xFF01..=0xFF5E) {
            4
        } else if matches!(c as u32, 0x3000..=0x303F | 0x2010..=0x2027) {
            2
        } else if is_pua(c) || c.is_control() {
            -10
        } else if c.is_alphabetic() || matches!(c as u32, 0x2500..=0x257F) {
            // Greek, Cyrillic, box drawing: present in CJK pages, rare in names.
            -4
        } else {
            0
        };
        total += if inside_word { v.min(0) } else { v };
        prev = c;
    }
    total
}

fn han_score(c: char, tier: Tier) -> i64 {
    if common_han().binary_search(&c).is_ok() {
        12
    } else {
        match tier {
            Tier::Normal => 8,
            Tier::Rare => 4,
            Tier::Ext => 0,
        }
    }
}

fn hangul_score(c: char, tier: Tier) -> i64 {
    if common_hangul().binary_search(&c).is_ok() {
        12
    } else {
        match tier {
            Tier::Normal => 8,
            _ => 4,
        }
    }
}

fn is_han(c: char) -> bool {
    matches!(c as u32, 0x4E00..=0x9FFF)
}

fn is_kana(c: char) -> bool {
    matches!(c as u32, 0x3041..=0x30FF)
}

fn is_halfwidth_kana(c: char) -> bool {
    matches!(c as u32, 0xFF61..=0xFF9F)
}

fn is_hangul(c: char) -> bool {
    matches!(c as u32, 0xAC00..=0xD7A3)
}

fn is_pua(c: char) -> bool {
    matches!(c as u32, 0xE000..=0xF8FF | 0xF0000..=0x10FFFF)
}

fn sorted(s: &str) -> Vec<char> {
    let mut v: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Frequent characters of Chinese (simplified and traditional) and Japanese text, and
/// words common in file names. Used to tell the CJK pages apart, since most byte pairs
/// decode to some character in each of them.
fn common_han() -> &'static [char] {
    static SET: OnceLock<Vec<char>> = OnceLock::new();
    SET.get_or_init(|| sorted(COMMON_HAN))
}

fn common_hangul() -> &'static [char] {
    static SET: OnceLock<Vec<char>> = OnceLock::new();
    SET.get_or_init(|| sorted(COMMON_HANGUL))
}

const COMMON_HAN: &str = "\
的一是不了人我在有他这中大来上国个到说们为子和你地出道也时年得就那要下以生会自着去之过家
学对可她里后小么心多天而能好都然没日于起还发成事只作当想看文无开手十用主行方又如前所本见
经头面公同三已老从动两长知民样现分将外但身些与高意进把法此实回二理美点月明其种声全工己话
儿者向情部正名定女问力机给等几很业最间新什打便位因重被走电四第门相次东政海口使教西再平真
听世气信北少关并内加化由却代军产入先山五太水万市眼体别处总才场师书比住员九笑性通目华报立
马命张活难神数件安表原车白应路期叫死常提感金何更反合放做系计或司利受光王果亲界及今京务制
解各任至清物台象记边共风战干接它许八特觉望直服毛林题建南度统色字请交爱让认算论百吃义科怎
元社术结六功指思非流每青管夫连远资队跟带花快条院变联言权往展该领传近留红治决周保达办运武
半候七必城父强步完革深区即求品士转量空甚众技轻程告江语英基派满式李息写呢识极令黄德收脸钱
党倒未持取设始版双历越史商千片容研像找友孩站广改议形委早房音火际则首单据导影失拿网香似斯
专石若兵弟谁校读志飞观争究包组造落视济喜离虽坏兴切玩夹档案图照频乐载桌备份复制副建档格划
合同附课练习考试答相册歌曲戏软装序具设置络库项模板素材稿简历证申请登记录统计销售价单号码
客户订购财税务账费预算审核批准通知公告会议纪要培训手册说明规范标准流程管理办法细则
們這個國來說時為會對學過後麼發開動當現實經種樣還進長點機關間問題業電話東車門見與書員給從
頭體區網圖檔資報夾複製增視頻樂載備錄課習試題冊遊戲軟裝設計專兩無應總處師幾兒將變讓認論義術
結華馬張難數達辦運強輕語識極黃錢黨歷濟離雖壞興組觀爭飛讀誰標準價歡聽氣縣風戰覺許統請愛聯權
傳領紅決護邊擇記們廣單據導網鄉陽陰東紀錄買賣廳歲縣區鐵銀醫藥場號碼訂購財帳費預審核準
写画説楽気駅様続読録覧済帰広円売県応対価営総鉄労線検査届確認存削除示類撮影編集個予打積納
契約仕撮旅休夏冬春秋曲歌写真図表";

const COMMON_HANGUL: &str = "\
이다는의에하고가서기지사수리자로를을한대도시인일어나정아그국전상주해것부들게있원회적장제보
비경문동성무우소오구마거내신위미여화공만생개연관세실면각학계조발물요중방선결업금등및와과터
라진명영행감당통니데래후저같민운체식분차법활년안모출산초날점될본반력단바파심말작람건견득습
처표현했었할던까드르러려며므브스크트프피히치토포호효흐새폴더진음악영상료파일고서본탕첨목없
음그림미지운드록설정램게임노래앨범여행족친구의획결과석제업강험답복사백압축해치용버최종수완
료임봄여름가을겨울집방학교회사업무님요일월년";

/// CP437 bytes 0x80-0xFF.
static CP437: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{A0}',
];

const fn table(s: &str) -> [char; 128] {
    let b = s.as_bytes();
    let mut out = ['\u{FFFD}'; 128];
    let (mut i, mut k) = (0, 0);
    while i < b.len() {
        // Decode one UTF-8 sequence.
        let x = b[i] as u32;
        let (len, init) = if x < 0x80 {
            (1, x)
        } else if x >= 0xF0 {
            (4, x & 7)
        } else if x >= 0xE0 {
            (3, x & 0xF)
        } else {
            (2, x & 0x1F)
        };
        let mut c = init;
        let mut j = 1;
        while j < len {
            c = (c << 6) | (b[i + j] as u32 & 0x3F);
            j += 1;
        }
        out[k] = match char::from_u32(c) {
            Some(c) => c,
            None => '\u{FFFD}',
        };
        i += len;
        k += 1;
    }
    assert!(k == 128);
    out
}

// The remaining DOS pages, written out as their 128 upper characters (U+FFFD where the page
// has no character).
static CP737: [char; 128] = table(
    "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀ωάέήϊίόύϋώΆΈΉΊΌΎΏ±≥≤ΪΫ÷≈°∙·√ⁿ²■\u{A0}",
);
static CP850: [char; 128] = table(
    "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´\u{AD}±‗¾¶§÷¸°¨·¹³²■\u{A0}",
);
static CP852: [char; 128] = table(
    "ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁ×čáíóúĄąŽžĘę¬źČş«»░▒▓│┤ÁÂĚŞ╣║╗╝Żż┐└┴┬├─┼Ăă╚╔╩╦╠═╬¤đĐĎËďŇÍÎě┘┌█▄ŢŮ▀ÓßÔŃńňŠšŔÚŕŰýÝţ´\u{AD}˝˛ˇ˘§÷¸°¨˙űŘř■\u{A0}",
);
static CP857: [char; 128] = table(
    "ÇüéâäàåçêëèïîıÄÅÉæÆôöòûùİÖÜø£ØŞşáíóúñÑĞğ¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ºªÊËÈ\u{FFFD}ÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµ\u{FFFD}×ÚÛÙìÿ¯´\u{AD}±\u{FFFD}¾¶§÷¸°¨·¹³²■\u{A0}",
);

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(cp: u16, s: &str) -> Vec<u8> {
        let p = CodePage::from_number(cp.into()).unwrap();
        match p.page().kind {
            Kind::Utf8 => s.as_bytes().to_vec(),
            Kind::Table(t) => s
                .chars()
                .map(|c| {
                    if c.is_ascii() {
                        c as u8
                    } else {
                        0x80 + t.iter().position(|&x| x == c).unwrap() as u8
                    }
                })
                .collect(),
            Kind::Single(e) | Kind::Cjk(e, _) => {
                let (b, _, bad) = e.encode(s);
                assert!(!bad, "{s} in {cp}");
                b.into_owned()
            }
        }
    }

    fn check(cp: u16, names: &[&str]) {
        let raw: Vec<Vec<u8>> = names.iter().map(|n| enc(cp, n)).collect();
        let got = detect(raw.iter().map(|v| v.as_slice()));
        assert_eq!(got.number(), cp, "{names:?} detected as {got}");
        for (n, r) in names.iter().zip(&raw) {
            assert_eq!(got.decode(r), *n);
        }
    }

    #[test]
    fn tables_are_complete() {
        for t in [&CP737, &CP850, &CP852] {
            assert!(!t.contains(&'\u{FFFD}'));
        }
        assert_eq!(CP857.iter().filter(|&&c| c == '\u{FFFD}').count(), 3);
    }

    #[test]
    fn detects_each_page() {
        check(
            932,
            &["資料/会議の議事録.txt", "写真/夏休み.jpg", "表示.txt"],
        );
        check(932, &["ソフト.lzh"]);
        check(932, &["新規フォルダ/説明書.doc"]);
        check(936, &["新建文件夹/报告.doc", "中文名称.txt"]);
        check(936, &["照片.jpg"]);
        check(950, &["新增資料夾/報告.doc", "中文檔案.txt"]);
        check(949, &["새 폴더/보고서.hwp", "사진.jpg"]);
        check(949, &["문서.txt"]);
        check(866, &["Документы/Отчет.txt", "Привет.doc"]);
        check(1251, &["Документы/Отчет.txt", "Привет.doc"]);
        check(737, &["Έγγραφα/αναφορά.txt"]);
        check(1253, &["Έγγραφα/αναφορά.txt"]);
        check(437, &["Größe.txt", "Café/Menü.doc"]);
        check(1252, &["Café.txt", "Größe.doc"]);
        check(852, &["Zdjęcia/Wakacje.jpg", "Mój dokument.doc"]);
        check(1250, &["Książka.txt", "Wróć/Szczęście.doc"]);
        check(65001, &["日本語.txt", "Café.doc"]);
    }

    #[test]
    fn detects_single_short_names() {
        check(932, &["ﾃﾞｰﾀ.txt"]);
        check(932, &["会議.doc"]);
        check(936, &["简历.doc"]);
        check(936, &["毕业论文.docx"]);
        check(936, &["龙虎斗.mp3"]);
        check(950, &["圖片.jpg"]);
        check(950, &["簡報.ppt"]);
        check(949, &["한글.hwp"]);
        check(949, &["가족사진.jpg"]);
        check(949, &["회의록.docx"]);
        check(1251, &["Отчёт.docx"]);
        check(1251, &["Фото.jpg"]);
        check(866, &["Фото.jpg"]);
        check(65001, &["Cafe\u{301}.txt"]);
        check(437, &["Résumé.doc"]);
    }

    /// `R7Z_CP=852 R7Z_NAME=... cargo test --lib codepage::tests::scores -- --ignored
    /// --nocapture` prints every page's score for a name, for tuning.
    #[test]
    #[ignore]
    fn scores() {
        let name = std::env::var("R7Z_NAME").unwrap_or("Zdjęcia/Wakacje.jpg".into());
        let cp: u16 = std::env::var("R7Z_CP").map_or(852, |v| v.parse().unwrap());
        let raw = enc(cp, &name);
        for p in PAGES.iter().filter(|p| p.detect) {
            let s = score(p, &raw);
            println!("{:>6} {s:>5} {}", p.number, CodePage(p.number).decode(&raw));
        }
    }

    #[test]
    fn ascii_and_empty_fall_back() {
        assert_eq!(detect([b"readme.txt".as_slice()]), CodePage::CP437);
        assert_eq!(detect(std::iter::empty()), CodePage::CP437);
    }

    #[test]
    fn parses_numbers() {
        assert_eq!(CodePage::parse("932").unwrap().number(), 932);
        assert_eq!(CodePage::parse("CP1251").unwrap().number(), 1251);
        assert_eq!(CodePage::parse("utf-8"), Some(CodePage::UTF8));
        assert_eq!(CodePage::parse("51949").unwrap().number(), 949);
        assert_eq!(CodePage::parse("12345"), None);
    }

    #[test]
    fn shift_jis_trail_backslash_is_not_a_separator() {
        // 表 is 0x95 0x5C.
        assert_eq!(
            CodePage::from_number(932).unwrap().decode(b"\x95\x5C.txt"),
            "表.txt"
        );
    }
}
