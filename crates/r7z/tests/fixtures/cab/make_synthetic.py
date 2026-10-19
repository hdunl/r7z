"""Writes the CAB fixtures makecab cannot produce: Quantum folders (from a small Quantum
encoder mirroring libmspack's qtmd.c decoder) and a stored cabinet with UTF-8 / ANSI names,
attributes, an invalid DOS date and overlapping files. 7-Zip 25.01 extracts all of them.

Usage: python make_synthetic.py OUTDIR
"""
import os
import random
import struct
import sys

POSITION_BASE = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
                 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
                 65536, 98304, 131072, 196608, 262144, 393216, 524288, 786432, 1048576, 1572864]
EXTRA_BITS = [0, 0, 0, 0] + [i // 2 for i in range(2, 40)]
LENGTH_BASE = [0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110,
               126, 158, 190, 222, 254]
LENGTH_EXTRA = [0] * 6 + [1] * 4 + [2] * 4 + [3] * 4 + [4] * 4 + [5] * 4 + [0]
FRAME = 32768


class Model:
    def __init__(self, start, n):
        self.n, self.shifts = n, 4
        self.sym = [start + i for i in range(n + 1)]
        self.cum = [n - i for i in range(n + 1)]

    def index(self, s):
        return self.sym.index(s, 0, self.n)

    def update(self, j):
        for k in range(j + 1):
            self.cum[k] += 8
        if self.cum[0] <= 3800:
            return
        n = self.n
        self.shifts -= 1
        if self.shifts:
            for i in range(n - 1, -1, -1):
                self.cum[i] >>= 1
                if self.cum[i] <= self.cum[i + 1]:
                    self.cum[i] = self.cum[i + 1] + 1
            return
        self.shifts = 50
        for i in range(n):
            self.cum[i] = (self.cum[i] - self.cum[i + 1] + 1) >> 1
        for i in range(n - 1):
            for j in range(i + 1, n):
                if self.cum[i] < self.cum[j]:
                    self.cum[i], self.cum[j] = self.cum[j], self.cum[i]
                    self.sym[i], self.sym[j] = self.sym[j], self.sym[i]
        for i in range(n - 1, -1, -1):
            self.cum[i] += self.cum[i + 1]


class Frame:
    """Arithmetic-codes one frame; raw bits go where the decoder will read them."""

    def __init__(self):
        self.lo, self.hi, self.pending, self.shifts = 0, 0xFFFF, 0, 0
        self.arith, self.raw = [], []

    def emit(self, b):
        self.arith.append(b)
        self.arith.extend([b ^ 1] * self.pending)
        self.pending = 0

    def code(self, m, s):
        j = m.index(s)
        tot, lo, hi = m.cum[0], m.cum[j + 1], m.cum[j]
        rng = ((self.hi - self.lo) & 0xFFFF) + 1
        self.hi = (self.lo + hi * rng // tot - 1) & 0xFFFF
        self.lo = (self.lo + lo * rng // tot) & 0xFFFF
        m.update(j)
        while True:
            if not (self.lo ^ self.hi) & 0x8000:
                self.emit(self.lo >> 15)
            elif self.lo & 0x4000 and not self.hi & 0x4000:
                self.pending += 1
                self.lo &= 0x3FFF
                self.hi |= 0x4000
            else:
                break
            self.lo = (self.lo << 1) & 0xFFFF
            self.hi = ((self.hi << 1) & 0xFFFF) | 1
            self.shifts += 1

    def bits(self, v, n):
        if n:
            self.raw.append((16 + self.shifts, [(v >> (n - 1 - i)) & 1 for i in range(n)]))

    def finish(self):
        """The decoder reads 16 + shifts coder bits, the raw bits, then 2 more bits, and
        7-Zip requires that to end in the frame's last byte."""
        self.pending += 1
        self.emit(0 if self.lo < 0x4000 else 1)
        need = 16 + self.shifts
        assert len(self.arith) <= need
        self.arith.extend([0] * (need - len(self.arith)))
        out, k = [], 0
        for i in range(len(self.arith) + 1):
            while k < len(self.raw) and self.raw[k][0] == i:
                out.extend(self.raw[k][1])
                k += 1
            if i < len(self.arith):
                out.append(self.arith[i])
        out.extend([0, 0])
        out.extend([0] * (-len(out) % 8))
        return bytes(int(''.join(map(str, out[i:i + 8])), 2) for i in range(0, len(out), 8))


def slot(table, v):
    s = max(i for i, b in enumerate(table) if b <= v)
    return s, v - table[s]


def quantum_folder(data, wbits):
    """Returns the CFDATA payloads (frames) of `data` coded with a 2^wbits window."""
    lits = [Model(64 * i, 64) for i in range(4)]
    n = 2 * wbits
    pos3, pos4, posv = Model(0, min(n, 24)), Model(0, min(n, 36)), Model(0, n)
    lenv, sel = Model(0, 27), Model(0, 7)
    window = 1 << wbits
    heads = {}
    frames = []
    for fs in range(0, len(data), FRAME):
        fe = min(fs + FRAME, len(data))
        f = Frame()
        p = fs
        while p < fe:
            best_len, best_dist = 0, 0
            key = data[p:p + 3]
            for q in reversed(heads.get(key, [])[-48:]):
                d = p - q
                if d > window:
                    break
                ln = 0
                while ln < 259 and p + ln < fe and data[q + ln] == data[p + ln]:
                    ln += 1
                lim = 4096 if ln == 3 else 262144 if ln == 4 else POSITION_BASE[n - 1] + (1 << EXTRA_BITS[n - 1])
                if ln >= 3 and d <= lim and ln > best_len:
                    best_len, best_dist = ln, d
            step = best_len if best_len >= 3 else 1
            if best_len >= 3:
                if best_len == 3:
                    f.code(sel, 4); s, e = slot(POSITION_BASE, best_dist - 1); f.code(pos3, s)
                elif best_len == 4:
                    f.code(sel, 5); s, e = slot(POSITION_BASE, best_dist - 1); f.code(pos4, s)
                else:
                    f.code(sel, 6)
                    ls, le = slot(LENGTH_BASE, best_len - 5)
                    f.code(lenv, ls); f.bits(le, LENGTH_EXTRA[ls])
                    s, e = slot(POSITION_BASE, best_dist - 1); f.code(posv, s)
                f.bits(e, EXTRA_BITS[s])
            else:
                b = data[p]
                f.code(sel, b >> 6); f.code(lits[b >> 6], b)
            for k in range(p, p + step):
                heads.setdefault(data[k:k + 3], []).append(k)
            p += step
        frames.append((f.finish(), fe - fs))
    return frames


def checksum(b, s=0):
    n = len(b) // 4
    for i in range(n):
        s ^= struct.unpack_from('<I', b, 4 * i)[0]
    ul = 0
    for x in b[4 * n:]:
        ul = (ul << 8) | x
    return s ^ ul


def write_cab(path, folders, files, set_id=0x5151):
    """folders: [(ctype, [(payload, uncompressed size)])];
    files: [(name bytes, size, offset, folder, date, time, attrib)]."""
    head = 36
    fold_len = 8 * len(folders)
    file_tab = b''.join(struct.pack('<IIHHHH', s, o, fi, d, t, a) + n + b'\0'
                        for n, s, o, fi, d, t, a in files)
    data_at = head + fold_len + len(file_tab)
    fold_tab, blocks = b'', b''
    for ctype, frames in folders:
        fold_tab += struct.pack('<IHH', data_at + len(blocks), len(frames), ctype)
        for payload, size in frames:
            hdr = struct.pack('<HH', len(payload), size)
            blocks += struct.pack('<I', checksum(hdr, checksum(payload))) + hdr + payload
    total = data_at + len(blocks)
    header = struct.pack('<4sIIIIIBBHHHHH', b'MSCF', 0, total, 0, head + fold_len, 0, 3, 1,
                         len(folders), len(files), 0, set_id, 0)
    with open(path, 'wb') as h:
        h.write(header + fold_tab + file_tab + blocks)


def main(out):
    random.seed(7)
    text = b''.join(b'%d: Quantum compresses cabinets with an arithmetic coder.\n' % (i % 97)
                    for i in range(700))
    noise = bytes(random.getrandbits(8) for _ in range(3000))
    mixed = bytes(random.choice(b'ACGT') for _ in range(9000)) + text[:5000] + bytes(range(256)) * 8
    date, time = (46 << 9) | (10 << 5) | 17, (13 << 11) | (37 << 5) | 21
    for wbits, name in ((10, 'quantum10.cab'), (21, 'quantum21.cab')):
        a = text + noise + mixed
        b = mixed[::-1] + text[:777]
        q = 0x0002 | (4 << 4) | (wbits << 8)
        folders = [(q, quantum_folder(a, wbits)), (q, quantum_folder(b, wbits))]
        files = [(b'text.txt', len(text), 0, 0, date, time, 0x20),
                 (b'noise.bin', len(noise), len(text), 0, date, time, 0x20),
                 (b'dir\\mixed.bin', len(mixed), len(text) + len(noise), 0, date, time, 0x21),
                 (b'rev.bin', len(b), 0, 1, date, time, 0x20)]
        write_cab(os.path.join(out, name), folders, files)

    body = b'0123456789' * 50 + b'UTF8 named\n' + b'cp1252 named\n'
    files = [(b'plain.txt', 500, 0, 0, date, time, 0x20),
             ('dir\\naïve 名.txt'.encode(), 11, 500, 0, date, time, 0x80 | 0x20),
             (b'caf\xe9.txt', 13, 511, 0, date, time, 0x01 | 0x02 | 0x04 | 0x20),
             (b'same.txt', 500, 0, 0, date, time, 0x20),
             (b'baddate.txt', 500, 0, 0, (46 << 9) | 17, time, 0x20)]
    write_cab(os.path.join(out, 'names.cab'), [(0, [(body, len(body))])], files)
    # Partly overlapping files: r7z decodes them; 7-Zip refuses to open the cabinet.
    files = [(b'a.txt', 300, 0, 0, date, time, 0x20), (b'b.txt', 300, 200, 0, date, time, 0x20),
             (b'c.txt', 24, 500, 0, date, time, 0x20), (b'd.txt', 50, 250, 0, date, time, 0x20)]
    write_cab(os.path.join(out, 'overlap.cab'), [(0, [(body, len(body))])], files)


if __name__ == '__main__':
    main(sys.argv[1])
