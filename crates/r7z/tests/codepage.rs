//! Legacy code pages in archive names: zip names without the UTF-8 flag, LZH, ARJ and tar
//! names written in Shift-JIS, GBK, Big5, CP949, Cyrillic, Greek and Western pages are
//! detected per archive and decoded; Unicode names are left alone; `-mcp` forces a page.

mod support;

use std::fs;
use std::path::PathBuf;

use r7z::format::{open_bytes, Archive, CodePage, NameCoding, OpenRequest};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};
use support::{write_arj, write_lzh, Member};

struct Quiet;
impl Callbacks for Quiet {}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-cp-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// `s` in code page `cp`.
fn enc(cp: u16, s: &str) -> Vec<u8> {
    let e = match cp {
        65001 => return s.as_bytes().to_vec(),
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        950 => encoding_rs::BIG5,
        949 => encoding_rs::EUC_KR,
        866 => encoding_rs::IBM866,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1252 => encoding_rs::WINDOWS_1252,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        // DOS pages encoding_rs does not have: search r7z's own table.
        _ => {
            let page = CodePage::from_number(cp.into()).unwrap();
            return s
                .chars()
                .map(|c| {
                    if c.is_ascii() {
                        c as u8
                    } else {
                        (0x80..=0xFF)
                            .find(|&b| page.decode(&[b]).starts_with(c))
                            .unwrap_or_else(|| panic!("{c} not in {cp}"))
                    }
                })
                .collect();
        }
    };
    let (b, _, bad) = e.encode(s);
    assert!(!bad, "{s} is not encodable in {cp}");
    b.into_owned()
}

fn sjis(s: &str) -> Vec<u8> {
    enc(932, s)
}
fn cp866(s: &str) -> Vec<u8> {
    enc(866, s)
}

/// One stored zip entry.
struct Z {
    name: Vec<u8>,
    flags: u16,
    extra: Vec<u8>,
    data: Vec<u8>,
    comment: Vec<u8>,
}

impl Z {
    fn new(name: Vec<u8>) -> Z {
        let data = if name.ends_with(b"/") {
            Vec::new()
        } else {
            name.clone()
        };
        Z {
            name,
            flags: 0,
            extra: Vec::new(),
            data,
            comment: Vec::new(),
        }
    }
}

/// A zip of stored entries made on MS-DOS, like old Windows tools write.
fn zip(items: &[Z], comment: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for z in items {
        let off = out.len() as u32;
        let crc = crc32fast::hash(&z.data);
        let n = z.data.len() as u32;
        let common = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes());
            v.extend_from_slice(&z.flags.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&0x5821u16.to_le_bytes());
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(&(z.name.len() as u16).to_le_bytes());
            v.extend_from_slice(&(z.extra.len() as u16).to_le_bytes());
        };
        out.extend_from_slice(b"PK\x03\x04");
        common(&mut out);
        out.extend_from_slice(&z.name);
        out.extend_from_slice(&z.extra);
        out.extend_from_slice(&z.data);
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes());
        common(&mut cd);
        cd.extend_from_slice(&(z.comment.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0; 4]);
        let attr: u32 = if z.name.ends_with(b"/") { 0x10 } else { 0x20 };
        cd.extend_from_slice(&attr.to_le_bytes());
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(&z.name);
        cd.extend_from_slice(&z.extra);
        cd.extend_from_slice(&z.comment);
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(items.len() as u16).to_le_bytes());
    out.extend_from_slice(&(items.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

fn open(bytes: Vec<u8>, name: &str, code_page: Option<CodePage>) -> r7z::format::Opened {
    open_bytes(
        bytes,
        name,
        &OpenRequest {
            code_page,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn names(a: &dyn Archive) -> Vec<String> {
    a.entries().iter().map(|e| e.name.clone()).collect()
}

fn detected(cp: u16) -> Option<NameCoding> {
    Some(NameCoding {
        page: CodePage::from_number(cp.into()).unwrap(),
        detected: true,
    })
}

/// Extracts to a fresh directory and returns it.
fn extract_to(a: &dyn Archive, label: &str) -> PathBuf {
    let dir = tmp(label);
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 2,
        target: Target::Disk {
            dir: dir.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{label}: {:?}", rep.errors);
    dir
}

/// Names that each page writes, as a user of that system would name files.
fn samples() -> Vec<(u16, Vec<&'static str>)> {
    vec![
        (
            932,
            vec![
                "資料/",
                "資料/会議の議事録.txt",
                "写真/夏休み.jpg",
                "表示.txt",
                "ソフト.exe",
            ],
        ),
        (
            936,
            vec![
                "新建文件夹/",
                "新建文件夹/报告.doc",
                "中文名称.txt",
                "照片.jpg",
            ],
        ),
        (
            950,
            vec!["新增資料夾/", "新增資料夾/報告.doc", "中文檔案.txt"],
        ),
        (949, vec!["새 폴더/", "새 폴더/보고서.hwp", "사진.jpg"]),
        (866, vec!["Документы/", "Документы/Отчет.txt", "Привет.doc"]),
        (
            1251,
            vec!["Документы/", "Документы/Отчет.txt", "Привет.doc"],
        ),
        (737, vec!["Έγγραφα/", "Έγγραφα/αναφορά.txt"]),
        (1253, vec!["Έγγραφα/", "Έγγραφα/αναφορά.txt"]),
        (437, vec!["Größe.txt", "Café/", "Café/Menü.doc"]),
        (850, vec!["Søknad/", "Søknad/Brød.txt"]),
        (1252, vec!["Café.txt", "Größe.doc"]),
        (
            852,
            vec!["Zdjęcia/", "Zdjęcia/Wakacje.jpg", "Mój dokument.doc"],
        ),
        (1250, vec!["Książka.txt", "Wróć/", "Wróć/Szczęście.doc"]),
        (
            857,
            vec!["Belgeler/", "Belgeler/Şirket raporu.doc", "Müşteri.xls"],
        ),
        (65001, vec!["日本語/", "日本語/ファイル.txt", "Café.doc"]),
    ]
}

#[test]
fn zip_names_in_each_code_page() {
    for (cp, list) in samples() {
        let items: Vec<Z> = list.iter().map(|n| Z::new(enc(cp, n))).collect();
        let o = open(zip(&items, b""), "legacy.zip", None);
        let a = o.archive();
        let want: Vec<String> = list
            .iter()
            .map(|n| n.trim_end_matches('/').into())
            .collect();
        assert_eq!(names(a), want, "code page {cp}");
        assert_eq!(a.name_coding(), detected(cp), "code page {cp}");
        for (e, n) in a.entries().iter().zip(&list) {
            assert_eq!(e.is_dir, n.ends_with('/'), "{cp}: {n}");
            if !n.is_ascii() {
                assert_eq!(e.raw_name.as_deref(), Some(enc(cp, n).as_slice()));
            }
        }
        let dir = extract_to(a, &format!("zip{cp}"));
        for n in list.iter().filter(|n| !n.ends_with('/')) {
            let got = fs::read(dir.join(n)).unwrap_or_else(|e| panic!("{cp}: {n}: {e}"));
            assert_eq!(got, enc(cp, n), "{cp}: {n}");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn unicode_and_ascii_names_are_left_alone() {
    let mut flagged = Z::new("日本語/説明.txt".as_bytes().to_vec());
    flagged.flags = 0x800;
    let o = open(
        zip(&[flagged, Z::new(b"readme.txt".to_vec())], b"plain comment"),
        "u.zip",
        None,
    );
    let a = o.archive();
    assert_eq!(names(a), ["日本語/説明.txt", "readme.txt"]);
    assert_eq!(a.name_coding(), None);
    assert!(a.entries().iter().all(|e| e.raw_name.is_none()));
    // Forcing a page changes nothing for names that say they are UTF-8.
    let mut flagged = Z::new("日本語.txt".as_bytes().to_vec());
    flagged.flags = 0x800;
    let o = open(zip(&[flagged], b""), "u.zip", CodePage::from_number(932));
    assert_eq!(names(o.archive()), ["日本語.txt"]);
}

fn unicode_path(raw: &[u8], utf8: &str, crc: u32) -> Vec<u8> {
    let mut x = vec![0x75, 0x70];
    x.extend_from_slice(&((5 + utf8.len()) as u16).to_le_bytes());
    x.push(1);
    x.extend_from_slice(&crc.to_le_bytes());
    x.extend_from_slice(utf8.as_bytes());
    let _ = raw;
    x
}

#[test]
fn unicode_path_field_is_used_while_its_crc_matches() {
    let raw = sjis("説明.txt");
    let mut good = Z::new(raw.clone());
    good.extra = unicode_path(&raw, "説明書.txt", crc32fast::hash(&raw));
    let raw2 = sjis("資料.doc");
    let mut stale = Z::new(raw2.clone());
    stale.extra = unicode_path(&raw2, "renamed.doc", 1234);
    let o = open(zip(&[good, stale], b""), "x.zip", None);
    let a = o.archive();
    assert_eq!(names(a), ["説明書.txt", "資料.doc"]);
    assert_eq!(a.entries()[0].raw_name, None);
    assert_eq!(a.name_coding(), detected(932));
}

#[test]
fn forced_code_page_overrides_detection() {
    let list = ["新建文件夹/报告.doc", "中文名称.txt"];
    let items: Vec<Z> = list.iter().map(|n| Z::new(enc(936, n))).collect();
    let bytes = zip(&items, b"");
    let gbk = CodePage::from_number(936).unwrap();
    let o = open(bytes.clone(), "x.zip", Some(gbk));
    assert_eq!(names(o.archive()), list);
    assert_eq!(
        o.archive().name_coding(),
        Some(NameCoding {
            page: gbk,
            detected: false
        })
    );
    // Another page decodes the same bytes differently; the raw bytes stay the same.
    let o = open(bytes, "x.zip", CodePage::from_number(1251));
    let a = o.archive();
    assert_eq!(a.entries()[1].name, "ЦРОДГыіЖ.txt");
    assert_eq!(
        a.entries()[1].raw_name.as_deref(),
        Some(enc(936, list[1]).as_slice())
    );
}

#[test]
fn shift_jis_trail_byte_backslash_is_not_a_separator() {
    // 表 is 0x95 0x5C and 予 is 0x97 0x5C.
    let list = ["表示/", "表示/予定表.txt"];
    let items: Vec<Z> = list.iter().map(|n| Z::new(sjis(n))).collect();
    let o = open(zip(&items, b""), "x.zip", None);
    let a = o.archive();
    assert_eq!(names(a), ["表示", "表示/予定表.txt"]);
    assert!(a.entries()[0].is_dir && !a.entries()[1].is_dir);
    let dir = extract_to(a, "sjis");
    assert_eq!(
        fs::read(dir.join("表示").join("予定表.txt")).unwrap(),
        sjis("表示/予定表.txt")
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn comments_use_the_same_code_page() {
    let mut z = Z::new(sjis("議事録.txt"));
    z.comment = sjis("会議のメモ");
    let o = open(zip(&[z], &sjis("社内資料")), "x.zip", None);
    let a = o.archive();
    assert_eq!(a.entries()[0].comment.as_deref(), Some("会議のメモ"));
    let props = a.properties();
    let comment = props.iter().find(|(k, _)| *k == "Comment").unwrap();
    assert_eq!(comment.1, "社内資料");
}

#[test]
fn lzh_shift_jis_names() {
    let mut members = vec![
        Member::dir("資料"),
        Member::file("資料/会議の議事録.txt", b"minutes".to_vec()),
        Member::file("表示.txt", b"view".to_vec()),
    ];
    for m in &mut members {
        m.encode = sjis;
    }
    for level in 0..=2 {
        let o = open(write_lzh(&members, level, "lh5"), "x.lzh", None);
        let a = o.archive();
        assert_eq!(
            names(a),
            ["資料", "資料/会議の議事録.txt", "表示.txt"],
            "level {level}"
        );
        assert_eq!(a.name_coding(), detected(932), "level {level}");
        let dir = extract_to(a, &format!("lzh{level}"));
        assert_eq!(
            fs::read(dir.join("資料/会議の議事録.txt")).unwrap(),
            b"minutes"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn arj_cyrillic_names() {
    let mut members = vec![
        Member::dir("Документы"),
        Member::file("Документы/Отчет.txt", b"report".to_vec()),
        Member::file("Привет.doc", b"hello".to_vec()),
    ];
    for m in &mut members {
        m.encode = cp866;
    }
    let o = open(write_arj("архив.arj", &members, 1, ""), "x.arj", None);
    let a = o.archive();
    assert_eq!(names(a), ["Документы", "Документы/Отчет.txt", "Привет.doc"]);
    assert_eq!(a.name_coding(), detected(866));
    let dir = extract_to(a, "arj");
    assert_eq!(
        fs::read(dir.join("Документы/Отчет.txt")).unwrap(),
        b"report"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A ustar header block.
fn tar_header(name: &[u8], typ: u8, size: usize, link: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"14000000000\0");
    h[156] = typ;
    h[157..157 + link.len()].copy_from_slice(link);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Name, type flag, data, link target.
type TarItem<'a> = (Vec<u8>, u8, &'a [u8], Vec<u8>);

fn tar(items: &[TarItem]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, typ, data, link) in items {
        out.extend_from_slice(&tar_header(name, *typ, data.len(), link));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

#[test]
fn tar_gbk_names_and_links() {
    let g = |s: &str| enc(936, s);
    let bytes = tar(&[
        (g("新建文件夹/"), b'5', b"", Vec::new()),
        (g("新建文件夹/报告.doc"), b'0', b"report", Vec::new()),
        (
            g("新建文件夹/副本.doc"),
            b'1',
            b"",
            g("新建文件夹/报告.doc"),
        ),
        (g("链接.doc"), b'2', b"", g("新建文件夹/报告.doc")),
        (b"plain.txt".to_vec(), b'0', b"ascii", Vec::new()),
    ]);
    let o = open(bytes, "x.tar", None);
    let a = o.archive();
    assert_eq!(
        names(a),
        [
            "新建文件夹",
            "新建文件夹/报告.doc",
            "新建文件夹/副本.doc",
            "链接.doc",
            "plain.txt"
        ]
    );
    assert_eq!(a.name_coding(), detected(936));
    use r7z::format::Link;
    assert_eq!(
        a.entries()[2].link,
        Some(Link::Hard("新建文件夹/报告.doc".into()))
    );
    assert_eq!(
        a.entries()[3].link,
        Some(Link::Symbolic("新建文件夹/报告.doc".into()))
    );
    assert_eq!(a.entries()[4].raw_name, None);
    let dir = extract_to(a, "tar");
    assert_eq!(
        fs::read(dir.join("新建文件夹/副本.doc")).unwrap(),
        b"report"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tar_utf8_names_are_left_alone() {
    let bytes = tar(&[("日本語.txt".as_bytes().to_vec(), b'0', b"x", Vec::new())]);
    let o = open(bytes, "x.tar", None);
    assert_eq!(names(o.archive()), ["日本語.txt"]);
    assert_eq!(o.archive().name_coding(), None);
}

#[test]
fn cli_mcp_switch() {
    let dir = tmp("cli");
    let arc = dir.join("names.zip");
    let items: Vec<Z> = ["資料/会議.txt", "表示.txt"]
        .iter()
        .map(|n| Z::new(sjis(n)))
        .collect();
    fs::write(&arc, zip(&items, b"")).unwrap();
    let run = |extra: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_r7z"))
            .arg("l")
            .arg("-slt")
            .args(extra)
            .arg(&arc)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let auto = run(&[]);
    assert!(auto.contains("Path = 資料/会議.txt"), "{auto}");
    assert!(
        auto.contains("Code Page = 932 Japanese (Shift-JIS) (detected)"),
        "{auto}"
    );
    let forced = run(&["-mcp=936"]);
    assert!(
        forced.contains("Code Page = 936 Chinese Simplified (GBK) (-mcp)"),
        "{forced}"
    );
    assert!(!forced.contains("会議"), "{forced}");
    let bad = std::process::Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["l", "-mcp=12345"])
        .arg(&arc)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let _ = fs::remove_dir_all(&dir);
}
