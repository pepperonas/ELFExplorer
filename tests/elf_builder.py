"""Builds a tiny but valid ELF64 shared object in memory (no compiler needed).

Sections: .text, .dynstr, .dynamic, .strtab, .symtab, .shstrtab.
"""
import struct

EM_X86_64 = 62
# push rbp; mov rbp, rsp; pop rbp; ret
X86_CODE = bytes.fromhex("554889e55dc3")


def _strtab(names):
    blob = b"\0"
    offsets = {}
    for n in names:
        offsets[n] = len(blob)
        blob += n.encode() + b"\0"
    return blob, offsets


def build_elf(symbols, needed=("libc.so.6",), soname="libdemo.so",
              machine=EM_X86_64, code=X86_CODE, extra_rodata=b""):
    """symbols: list of (name, value, size). Returns the ELF file as bytes."""
    text_addr = 0x1000

    dynstr, dyn_off = _strtab(list(needed) + [soname])
    dynamic = b"".join(struct.pack("<qQ", 1, dyn_off[n]) for n in needed)   # DT_NEEDED
    dynamic += struct.pack("<qQ", 14, dyn_off[soname])                        # DT_SONAME
    dynamic += struct.pack("<qQ", 0, 0)                                       # DT_NULL

    strtab, sym_off = _strtab([s[0] for s in symbols])
    symtab = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for name, value, size in symbols:
        symtab += struct.pack("<IBBHQQ", sym_off[name], 0x12, 0, 1, value, size)  # GLOBAL FUNC in .text

    sec_names = [".text", ".rodata", ".dynstr", ".dynamic", ".strtab", ".symtab", ".shstrtab"]
    shstrtab, sh_off = _strtab(sec_names)

    # (name, type, flags, addr, data, link, info, align, entsize)
    sections = [
        (".text", 1, 0x6, text_addr, code, 0, 0, 16, 0),
        (".rodata", 1, 0x2, 0, extra_rodata, 0, 0, 1, 0),
        (".dynstr", 3, 0x2, 0, dynstr, 0, 0, 1, 0),
        (".dynamic", 6, 0x3, 0, dynamic, 3, 0, 8, 16),
        (".strtab", 3, 0, 0, strtab, 0, 0, 1, 0),
        (".symtab", 2, 0, 0, symtab, 5, 1, 8, 24),
        (".shstrtab", 3, 0, 0, shstrtab, 0, 0, 1, 0),
    ]

    body = b""
    offset = 64
    headers = [b"\0" * 64]
    for name, typ, flags, addr, data, link, info, align, entsize in sections:
        headers.append(struct.pack("<IIQQQQIIQQ", sh_off[name], typ, flags, addr,
                                   offset + len(body), len(data), link, info, align, entsize))
        body += data
    pad = (-(64 + len(body))) % 8
    body += b"\0" * pad
    shoff = 64 + len(body)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, text_addr, 0, shoff,
                                 0, 64, 56, 0, 64, len(headers), len(sections))
    return header + body + b"".join(headers)
