#!/usr/bin/env python3
"""profile-synth-vectors — synthetic conformance vectors for the normalized-hash profile.

The OVMF reference exercises only part of the profile. Measured 2026-09-04 across its 122
modules: every one is PE32+ (magic 0x20B), and the only relocation types present are
ABSOLUTE(0) and DIR64(10). So `docs/normalized-module-hash-vectors.json` cannot distinguish
a correct implementation from one that gets the entire 32-bit path wrong -- PE32's ImageBase
lives at a different offset and a different width, and HIGHLOW is a 32-bit subtract.
The same blind spot hides TimeDateStamp/CheckSum, which are already zero on every real module.

These vectors are hand-built, tiny, and shipped as bytes, so a second implementer can run them
without reproducing anyone's firmware build. They cover the paths the real image never reaches
and the failure cases the profile says must emit no value.

  profile-synth-vectors.py --emit -o docs/normalized-module-hash-vectors-runnable.json
  profile-synth-vectors.py --check docs/normalized-module-hash-vectors-runnable.json
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import profile_ref  # noqa: E402  the from-the-document reference implementation

PROFILE = "uefi-pe-rebase0/v1"

FILE_SIZE = 0x600
E_LFANEW = 0x80
TEXT_VA, TEXT_RAW, TEXT_SIZE = 0x1000, 0x200, 0x100
# PointerToRawData values must be multiples of 0x200: pefile rounds every one down to a
# hardcoded 512-byte sector regardless of FileAlignment (a Windows-loader quirk it emulates),
# so a .reloc at 0x300 silently becomes 0x200 and its block header is read out of .text.
RELOC_VA, RELOC_RAW, RELOC_SIZE = 0x2000, 0x400, 0x100
def ptr_rvas(pe_plus):
    """RVAs of the two relocatable pointers. Spacing follows pointer width -- 8 bytes on
    PE32+, 4 on PE32. Hardcoding 8 silently leaves the second PE32 fixup unrelocated."""
    w = 8 if pe_plus else 4
    return (TEXT_VA + 0, TEXT_VA + w)

MAGIC32, MAGIC64 = 0x10B, 0x20B
REL_ABSOLUTE, REL_HIGHLOW, REL_DIR64, REL_HIGH = 0, 3, 10, 1


def build_pe(image_base, pe_plus=True, with_reloc=True, reloc_type=None,
             timestamp=0, checksum=0, truncate_at=None, odd_blocksize=False):
    """A minimal but structurally valid PE whose .text holds two self-referential
    absolute pointers (ImageBase + own RVA), described by a .reloc block -- so
    reversing the fixups is a real operation, not a no-op."""
    if pe_plus:
        magic, size_opt, ib_off, numrva_off, dd_off = MAGIC64, 112 + 16 * 8, 24, 108, 112
        rtype = REL_DIR64 if reloc_type is None else reloc_type
        ptr_fmt, ptr_w = "<Q", 8
    else:
        magic, size_opt, ib_off, numrva_off, dd_off = MAGIC32, 96 + 16 * 8, 28, 92, 96
        rtype = REL_HIGHLOW if reloc_type is None else reloc_type
        ptr_fmt, ptr_w = "<I", 4

    buf = bytearray(FILE_SIZE)
    struct.pack_into("<H", buf, 0, 0x5A4D)                 # MZ
    struct.pack_into("<I", buf, 0x3C, E_LFANEW)
    buf[E_LFANEW:E_LFANEW + 4] = b"PE\x00\x00"
    coff = E_LFANEW + 4
    struct.pack_into("<H", buf, coff + 2, 2)               # NumberOfSections
    struct.pack_into("<I", buf, coff + 4, timestamp)       # TimeDateStamp
    struct.pack_into("<H", buf, coff + 16, size_opt)       # SizeOfOptionalHeader

    opt = coff + 20
    struct.pack_into("<H", buf, opt, magic)
    struct.pack_into(ptr_fmt if pe_plus else "<I", buf, opt + ib_off,
                     image_base if pe_plus else image_base & 0xFFFFFFFF)
    struct.pack_into("<I", buf, opt + 16, TEXT_VA)         # AddressOfEntryPoint -- pefile warns
    struct.pack_into("<I", buf, opt + 64, checksum)        # CheckSum              if it is outside a section
    struct.pack_into("<I", buf, opt + 32, 0x1000)          # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x100)           # FileAlignment -- must divide
                                                       # every PointerToRawData, or pefile
                                                       # silently maps RVAs to the wrong
                                                       # section and reads garbage
    struct.pack_into("<I", buf, opt + 56, 0x3000)          # SizeOfImage -- without this
    struct.pack_into("<I", buf, opt + 60, TEXT_RAW)        # SizeOfHeaders   pefile rejects
    struct.pack_into("<I", buf, opt + numrva_off, 16)      # NumberOfRvaAndSizes  every reloc block

    nreloc = 8 + 2 * 2
    if with_reloc:
        struct.pack_into("<II", buf, opt + dd_off + 5 * 8, RELOC_VA, nreloc)

    sec = opt + size_opt
    for i, (nm, va, raw, sz) in enumerate(
            ((b".text", TEXT_VA, TEXT_RAW, TEXT_SIZE),
             (b".reloc", RELOC_VA, RELOC_RAW, RELOC_SIZE))):
        b = sec + i * 40
        buf[b:b + 8] = nm.ljust(8, b"\x00")
        struct.pack_into("<I", buf, b + 8, sz)             # VirtualSize
        struct.pack_into("<I", buf, b + 12, va)            # VirtualAddress
        struct.pack_into("<I", buf, b + 16, sz)            # SizeOfRawData
        struct.pack_into("<I", buf, b + 20, raw)           # PointerToRawData

    rvas = ptr_rvas(pe_plus)
    for i, rva in enumerate(rvas):                         # the relocatable pointers
        struct.pack_into(ptr_fmt, buf, TEXT_RAW + i * ptr_w,
                         (image_base + rva) & ((1 << (ptr_w * 8)) - 1))

    if with_reloc:                                         # one block, two entries
        struct.pack_into("<II", buf, RELOC_RAW, TEXT_VA, nreloc + (1 if odd_blocksize else 0))
        if odd_blocksize:                                  # directory size must cover the block
            struct.pack_into("<II", buf, opt + dd_off + 5 * 8, RELOC_VA, nreloc + 1)
        for i, rva in enumerate(rvas):
            struct.pack_into("<H", buf, RELOC_RAW + 8 + i * 2,
                             (rtype << 12) | ((rva - TEXT_VA) & 0xFFF))
    if truncate_at == "oh+100":
        return bytes(buf[:opt + 100])
    return bytes(buf)


CASES = [
    # (id, why it exists, builder-kwargs, expect_value)
    ("pe32-highlow-rebased",
     "PE32 (magic 0x10B) with HIGHLOW fixups. NEITHER is present anywhere in the OVMF "
     "reference, so this is the only thing testing the 32-bit ImageBase offset (oh+28, "
     "4 bytes) and the 32-bit subtract.",
     dict(image_base=0x00830000, pe_plus=False), True),
    ("pe32plus-dir64-rebased",
     "PE32+ with DIR64 fixups -- the path the real image does exercise, kept so the two "
     "widths can be compared side by side.",
     dict(image_base=0x0000000140000000, pe_plus=True), True),
    ("pe32-already-base0",
     "PE32 already at ImageBase 0: nothing to reverse, header normalization alone.",
     dict(image_base=0, pe_plus=False), True),
    ("pe32plus-no-reloc-table-rebased",
     "Non-zero ImageBase with NO relocation directory. Profile s4.1 says header "
     "normalization alone canonicalizes it.",
     dict(image_base=0x0000000140000000, pe_plus=True, with_reloc=False), True),
    ("pe32plus-dirty-timestamp-checksum",
     "Non-zero TimeDateStamp and CheckSum. Every real module has these already zeroed by "
     "GenFw, so the reference cannot tell whether an implementation zeroes them.",
     dict(image_base=0, pe_plus=True, timestamp=0x66D1B2C3, checksum=0xDEADBEEF), True),
    ("neg-truncated-data-directory",
     "Rebased PE32+ whose image ends AFTER the optional header's first 68 bytes (so s4.2 "
     "passes) but BEFORE data-directory index 5. s4.1: an unreadable directory with B != 0 "
     "is a failure, not an absence. The reference itself emitted a value here until review.",
     dict(image_base=0x0000000140000000, pe_plus=True, truncate_at="oh+100"), False),
    ("neg-odd-blocksize",
     "Relocation block whose BlockSize is odd. Entries are u16, so the last one straddles the "
     "block end. s4.1: fail. Unspecified until review; the reference emitted a value.",
     dict(image_base=0x0000000140000000, pe_plus=True, odd_blocksize=True), False),
    ("neg-unsupported-reloc-type",
     "HIGH(1) fixup. Profile s4.1: any type other than 0/3/10 MUST emit no value rather "
     "than a partially-normalized image.",
     dict(image_base=0x00830000, pe_plus=True, reloc_type=REL_HIGH), False),
]


def _ptrs(buf, pe_plus):
    """The two self-referential pointers .text carries, as written."""
    fmt, w = ("<Q", 8) if pe_plus else ("<I", 4)
    return [struct.unpack_from(fmt, buf, TEXT_RAW + i * w)[0] for i in range(2)]


def emit():
    out = []
    for cid, why, kw, expect in CASES:
        raw = build_pe(**kw)
        pe_plus = kw.get("pe_plus", True)
        try:
            norm = profile_ref.normalize(raw)
            err = None
        except profile_ref.NotNormalizable as ex:
            norm, err = None, str(ex)

        # SELF-CHECK. A vector that claims to exercise the relocation path must actually
        # exercise it: the two pointers .text carries must come back as bare RVAs. Without
        # this, a vector whose relocations were silently skipped looks identical to a
        # correct one and certifies nothing -- which is exactly how the first attempt at
        # this file produced six worthless vectors.
        if expect and kw.get("with_reloc", True) and kw.get("image_base") \
                and not kw.get("truncate_at") and not kw.get("odd_blocksize"):
            if norm is None:
                sys.exit(f"profile-synth-vectors: '{cid}' expected a value, got none ({err})")
            if _ptrs(norm, pe_plus) != list(ptr_rvas(pe_plus)):
                sys.exit(f"profile-synth-vectors: '{cid}' claims to reverse fixups but the "
                         f".text pointers are {[hex(x) for x in _ptrs(norm, pe_plus)]}, "
                         f"expected {[hex(x) for x in ptr_rvas(pe_plus)]} -- the vector is a no-op")
        if not expect and norm is not None:
            sys.exit(f"profile-synth-vectors: '{cid}' must emit no value but produced one")

        entry = {"id": cid, "rationale": why,
                 "input_b64": base64.b64encode(raw).decode(),
                 "input_sha256": hashlib.sha256(raw).hexdigest(),
                 "expect_value": expect}
        if norm is not None:
            entry["sha256_norm"] = hashlib.sha256(norm).hexdigest()
            entry["output_b64"] = base64.b64encode(norm).decode()
        else:
            entry["sha256_norm"] = None
            entry["reason"] = err
        out.append(entry)
    return {
        "profile": PROFILE,
        "description": "Synthetic conformance vectors covering paths the OVMF reference never "
                       "reaches (PE32, HIGHLOW, non-zero TimeDateStamp/CheckSum) and the cases "
                       "the profile says must emit no value. Expected outputs are produced by "
                       "producers/reconcile/profile_ref.py, an implementation written from the "
                       "profile document alone -- NOT by the implementation under test.",
        "tool": "producers/reconcile/profile-synth-vectors.py",
        "expected_by": "producers/reconcile/profile_ref.py",
        "vectors": out,
    }


def check(path):
    want = json.load(open(path))
    bad = 0
    for v in want["vectors"]:
        raw = base64.b64decode(v["input_b64"])
        try:
            norm = profile_ref.normalize(raw)
        except profile_ref.NotNormalizable:
            norm = None
        got = hashlib.sha256(norm).hexdigest() if norm is not None else None
        ok = got == v["sha256_norm"]
        if v["expect_value"] and norm is None:
            ok = False
        if not v["expect_value"] and norm is not None:
            ok = False
        print(("PASS  " if ok else "FAIL  ") + v["id"] +
              ("" if ok else f"   want={v['sha256_norm']} got={got}"))
        bad += 0 if ok else 1
    print(f"\n{'PASS' if not bad else 'FAIL'}  {len(want['vectors'])} runnable vectors, {bad} failing")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--check", metavar="VECTORS")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    if a.check:
        return check(a.check)
    doc = emit()
    txt = json.dumps(doc, indent=2) + "\n"
    if a.out:
        open(a.out, "w").write(txt)
        sys.stderr.write(f"profile-synth-vectors: {len(doc['vectors'])} vectors -> {a.out}\n")
    else:
        sys.stdout.write(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
