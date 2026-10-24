"""Generates crates/r7z/src/format/inno/layouts.rs from Inno Setup's record definitions.

Inno Setup stores its setup data as Delphi records: every String field as a length and
its bytes, then the rest of the record as raw memory. The layout of that memory changes
between releases, so the reader needs, for each format (identified by the "Inno Setup
Setup Data (x.y.z)" string), the size of every record and the offsets of the few fields
it reads. This script computes them from the `Struct.pas` of each release:

    python scripts/inno_layouts.py DIR > crates/r7z/src/format/inno/layouts.rs

DIR holds one `<tag>.pas` per release, fetched from https://github.com/jrsoftware/issrc
(`Projects/Struct.pas` up to 6.3, `Projects/Src/Shared.Struct.pas` after). Records are
packed unless declared as plain `record`; enumerations take one byte, and a set takes
one byte per eight members, with three rounded up to four, as Delphi lays them out.
"""

import os
import re
import sys

BUILTIN = {
    "Integer": 4, "Longint": 4, "LongInt": 4, "Cardinal": 4, "DWORD": 4, "LongWord": 4,
    "UInt32": 4, "Int32": 4, "Int64": 8, "Integer64": 8, "UInt64": 8, "Word": 2,
    "Smallint": 2, "SmallInt": 2, "Byte": 1, "Boolean": 1, "AnsiChar": 1,
    "TFileTime": 8, "TSHA1Digest": 20, "TMD5Digest": 16, "TSHA256Digest": 32,
    "TGUID": 16, "TSIDIdentifierAuthority": 6,
}
STRINGS = {"String", "AnsiString", "WideString"}


def preprocess(text, unicode):
    text = re.sub(r"\(\*.*?\*\)", "", text, flags=re.S)
    out, stack = [], []
    pos = 0
    for m in re.finditer(r"\{(\$?)([^}]*)\}", text):
        if all(stack):
            out.append(text[pos:m.start()])
        pos = m.end()
        if not m.group(1):
            continue
        d = m.group(2).strip().split()
        word = d[0].upper()
        if word in ("IFDEF", "IFNDEF"):
            val = d[1].upper() == "UNICODE" and unicode
            stack.append(val if word == "IFDEF" else not val)
        elif word == "ELSE":
            stack[-1] = not stack[-1]
        elif word == "ENDIF":
            stack.pop()
    if all(stack):
        out.append(text[pos:])
    # Line comments go last: a brace comment can hold a URL's "//".
    return re.sub(r"//[^\n]*", "", "".join(out))


class Types:
    def __init__(self, text, unicode):
        self.unicode = unicode
        self.enums, self.alias, self.records = {}, {}, {}
        body = text
        for m in re.finditer(r"(\w+)\s*=\s*\(([^()]*)\)\s*;", body):
            self.enums[m.group(1)] = self.enum_values(m.group(2))
        for m in re.finditer(r"(\w+)\s*=\s*((?:packed\s+)?set\s+of\s+\w+|array\s*\[[^\]]*\]\s*of\s+\w+)\s*;", body):
            self.alias[m.group(1)] = m.group(2)
        for m in re.finditer(r"(\w+)\s*=\s*(packed\s+)?record\b(.*?)\bend\s*;", body, re.S):
            self.records[m.group(1)] = (bool(m.group(2)), m.group(3))

    @staticmethod
    def enum_values(src):
        vals, n = [], 0
        for part in src.split(","):
            part = part.strip()
            if "=" in part:
                name, v = part.split("=")
                n = int(v.strip())
                part = name.strip()
            vals.append((part, n))
            n += 1
        return vals

    def set_size(self, members):
        hi = max(v for _, v in members)
        b = hi // 8 + 1
        return 4 if b == 3 else b

    def type_info(self, t):
        """(size, alignment, strings, set members or None) of a type expression."""
        t = t.strip()
        if t in STRINGS:
            return 0, 1, 1, None
        if t == "Char":
            return (2, 2, 0, None) if self.unicode else (1, 1, 0, None)
        if t in BUILTIN:
            s = BUILTIN[t]
            return s, min(s, 8) if t not in ("TFileTime", "TSHA1Digest", "TMD5Digest", "TSHA256Digest", "TGUID") else 4, 0, None
        m = re.fullmatch(r"\((.*)\)", t, re.S)
        if m:
            return 1, 1, 0, None
        m = re.fullmatch(r"(?:packed\s+)?set\s+of\s+(.*)", t, re.S)
        if m:
            inner = m.group(1).strip()
            if inner in ("AnsiChar", "Char"):
                return 32, 1, 0, None
            if inner.startswith("("):
                members = self.enum_values(inner[1:-1])
            else:
                members = self.enums[inner]
            s = self.set_size(members)
            return s, 1, 0, members
        m = re.fullmatch(r"array\s*\[\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\]\s*of\s+(\w+)", t, re.S)
        if m:
            n = int(m.group(2)) - int(m.group(1)) + 1
            s, a, _, _ = self.type_info(m.group(3))
            return n * s, a, 0, None
        if t in self.enums:
            return 1, 1, 0, None
        if t in self.alias:
            return self.type_info(self.alias[t])
        if t in self.records:
            r = self.layout(t)
            return r["size"], r["align"], r["strings"], None
        raise KeyError(t)

    def layout(self, name):
        packed, body = self.records[name]
        fields, off, strings, align = {}, 0, 0, 1
        for decl in body.split(";"):
            decl = decl.strip()
            if not decl or ":" not in decl:
                continue
            names, t = decl.split(":", 1)
            for fname in [n.strip() for n in names.split(",")]:
                size, a, s, members = self.type_info(t)
                if s:
                    strings += s
                    if size == 0:
                        fields[fname] = ("str", strings - 1)
                        continue
                if not packed:
                    off = (off + a - 1) // a * a
                    align = max(align, a)
                fields[fname] = (off, size, members)
                off += size
        if not packed:
            off = (off + align - 1) // align * align
        return {"fields": fields, "size": off, "strings": strings, "align": align}


def setup_id(text):
    m = re.search(r"SetupID:\s*TSetupID\s*=\s*'([^']*)'(\s*\+\s*' \(u\)')?", text)
    return m.group(1) + (" (u)" if m.group(2) else "")


def build(path, unicode):
    raw = open(path, encoding="latin-1").read()
    text = preprocess(raw, unicode)
    ty = Types(text, unicode)
    get = ty.layout
    hdr = get("TSetupHeader")
    loc = get("TSetupFileLocationEntry")
    fil = get("TSetupFileEntry")
    lay = {"id": setup_id(text), "unicode": unicode}
    hf = hdr["fields"]
    counts = ["Language", "CustomMessage", "Permission", "Type", "Component", "Task",
              "Dir", "ISSigKey", "File", "FileLocation"]
    lay["counts"] = [hf.get(f"Num{c}Entries", (None,))[0] for c in counts]
    lay["compress"] = hf["CompressMethod"][0]
    assert [n for n, _ in ty.enums["TSetupCompressMethod"]] == ["cmStored", "cmZip", "cmBzip", "cmLZMA", "cmLZMA2"]
    lay["header"] = (hdr["strings"], hdr["size"])
    recs = {"Language": "TSetupLanguageEntry", "CustomMessage": "TSetupCustomMessageEntry",
            "Permission": "TSetupPermissionEntry", "Type": "TSetupTypeEntry",
            "Component": "TSetupComponentEntry", "Task": "TSetupTaskEntry",
            "Dir": "TSetupDirEntry", "ISSigKey": "TSetupISSigKeyEntry"}
    lay["skip"] = []
    for c in counts[:8]:
        if recs[c] in ty.records:
            r = get(recs[c])
            lay["skip"].append((r["strings"], r["size"]))
        else:
            lay["skip"].append((0, 0))
    ff = fil["fields"]
    lay["file"] = (fil["strings"], fil["size"])
    lay["file_location"] = ff["LocationEntry"][0]
    lay["file_attribs"] = ff["Attribs"][0]
    lay["file_type"] = ff["FileType"][0] if "FileType" in ff else None
    lay["file_languages"] = ff["Languages"][1]
    lf = loc["fields"]
    hash_name = next(n for n in ("SHA256Sum", "SHA1Sum") if n in lf)
    flags = lf["Flags"]
    bits = {n: v for n, v in flags[2]}
    def bit(*names):
        for n in names:
            if n in bits:
                return bits[n]
        return None
    lay["loc"] = {
        "size": loc["size"], "first_slice": lf["FirstSlice"][0],
        "start": lf["StartOffset"][0], "start64": lf["StartOffset"][1] == 8,
        "suboffset": lf["ChunkSuboffset"][0], "original": lf["OriginalSize"][0],
        "compressed": lf["ChunkCompressedSize"][0], "hash": lf[hash_name][0],
        "hash_kind": {"SHA256Sum": "Sha256", "SHA1Sum": "Sha1"}[hash_name],
        "time": (lf.get("TimeStamp") or lf["SourceTimeStamp"])[0], "flags": flags[0], "flags_len": flags[1],
        "call": bit("floCallInstructionOptimized", "foCallInstructionOptimized"),
        "encrypted": bit("floChunkEncrypted", "foChunkEncrypted"),
        "chunk_compressed": bit("floChunkCompressed", "foChunkCompressed"),
    }
    enc = get("TSetupEncryptionHeader")["size"] if "TSetupEncryptionHeader" in ty.records else 0
    lay["enc_header"] = enc
    ver = tuple(int(x) for x in re.search(r"\(([\d.]+)\)", lay["id"]).group(1).split("."))
    # Compressed block headers store a 64-bit size from 6.7 on (Compression.Base.pas).
    lay["block64"] = ver >= (6, 7)
    return lay


def rust(lays):
    def opt(v):
        return "None" if v is None else f"Some({v})"
    out = ["// Generated by scripts/inno_layouts.py from Inno Setup's Struct.pas; do not edit.",
           "", "use super::{Hash, Layout, Loc, Rec};", "", "pub(super) const LAYOUTS: &[Layout] = &["]
    for l in lays:
        loc = l["loc"]
        out.append("    Layout {")
        out.append(f"        id: {l['id']!r},".replace("'", '"'))
        out.append(f"        unicode: {str(l['unicode']).lower()},")
        out.append(f"        enc_header: {l['enc_header']},")
        out.append(f"        block64: {str(l['block64']).lower()},")
        out.append(f"        header: Rec {{ strings: {l['header'][0]}, fixed: {l['header'][1]} }},")
        out.append(f"        counts: [{', '.join(opt(c) for c in l['counts'])}],")
        out.append(f"        compress: {l['compress']},")
        out.append("        skip: [" + ", ".join(f"Rec {{ strings: {s}, fixed: {f} }}" for s, f in l["skip"]) + "],")
        out.append(f"        file: Rec {{ strings: {l['file'][0]}, fixed: {l['file'][1]} }},")
        out.append(f"        file_location: {l['file_location']},")
        out.append(f"        file_attribs: {l['file_attribs']},")
        out.append(f"        file_type: {opt(l['file_type'])},")
        out.append(f"        file_languages: {l['file_languages']},")
        out.append("        loc: Loc {")
        for k in ("size", "first_slice", "start"):
            out.append(f"            {k}: {loc[k]},")
        out.append(f"            start64: {str(loc['start64']).lower()},")
        for k in ("suboffset", "original", "compressed", "hash"):
            out.append(f"            {k}: {loc[k]},")
        out.append(f"            hash_kind: Hash::{loc['hash_kind']},")
        for k in ("time", "flags", "flags_len"):
            out.append(f"            {k}: {loc[k]},")
        for k in ("call", "encrypted", "chunk_compressed"):
            out.append(f"            {k}: {opt(loc[k])},")
        out.append("        },")
        out.append("    },")
    out.append("];")
    return "\n".join(out) + "\n"


def main():
    d = sys.argv[1]
    seen, lays = set(), []
    for name in sorted(os.listdir(d)):
        if not name.endswith(".pas"):
            continue
        path = os.path.join(d, name)
        variants = [True] if name >= "is-6" else [True, False]
        for u in variants:
            l = build(path, u)
            if l["id"] in seen:
                continue
            seen.add(l["id"])
            lays.append(l)
    sys.stdout.write(rust(lays))


if __name__ == "__main__":
    main()
