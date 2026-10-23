"""Writes the ISO 9660 fixtures in this directory with pycdlib
(https://github.com/clalancette/pycdlib, LGPL-2.1, used here only to write test data).

Run: python make_fixtures.py   (pip install pycdlib)
The fixtures are small, and their listings and bytes were checked against 7-Zip 25.01
(`7z l -slt`), which reads the same images. 7-Zip does not write ISO images itself.
"""
import io
import os

import pycdlib

HERE = os.path.dirname(os.path.abspath(__file__))


def fp(data):
    return io.BytesIO(data)


def plain():
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, vol_ident="PLAIN")
    iso.add_fp(fp(b"hello iso\n"), 10, "/HELLO.TXT;1")
    iso.add_directory("/SUB")
    iso.add_fp(fp(b"deep\n"), 5, "/SUB/DEEP.TXT;1")
    iso.add_fp(fp(b""), 0, "/EMPTY.DAT;1")
    iso.write(os.path.join(HERE, "plain.iso"))
    iso.close()


def joliet_rock_ridge():
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="JRR")
    iso.add_fp(fp(b"hello iso\n"), 10, "/HELLO.TXT;1", rr_name="hello.txt", joliet_path="/hello.txt")
    iso.add_directory("/SUB", rr_name="sub", joliet_path="/sub")
    iso.add_fp(fp(b"x" * 1000), 1000, "/SUB/LONG.MD;1",
               rr_name="a file with a long name that goes on.md",
               joliet_path="/sub/a file with a long name that goes on.md")
    iso.add_symlink("/LINK.TXT;1", rr_symlink_name="link.txt", rr_path="/hello.txt",
                    joliet_path="/link.txt")
    iso.write(os.path.join(HERE, "joliet-rock-ridge.iso"))
    iso.close()


def el_torito():
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, vol_ident="BOOT")
    iso.add_fp(fp(b"hello iso\n"), 10, "/HELLO.TXT;1")
    boot = bytes((i * 7) & 0xFF for i in range(4 * 512))
    iso.add_fp(fp(boot), len(boot), "/BOOT.IMG;1")
    iso.add_eltorito("/BOOT.IMG;1", bootcatfile="/BOOT.CAT;1", media_name="noemul")
    iso.write(os.path.join(HERE, "el-torito.iso"))
    iso.close()


if __name__ == "__main__":
    plain()
    joliet_rock_ridge()
    el_torito()
