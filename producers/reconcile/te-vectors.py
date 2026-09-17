#!/usr/bin/env python3
"""te-vectors — conformance vectors for `uefi-te-rebase0.v1` (profile s4.4).

These vectors have something the PE32 ones never had: an **independent oracle**.

The PE32 vectors are produced by `profile_ref.py` and checked against `canon_unrebase`.
That catches disagreement between two implementations, but it cannot catch a rule both
of them get wrong -- which happened three times, most recently the section-table pointer
pair (profile s12.1) that only surfaced here.

For TE, edk2's own tooling performs the FORWARD operation:

    GenFw --rebase <addr>  .efi   ->  a PE relocated to <addr>
    GenFw -t               .efi   ->  the TE form

so `normalize_te(TE at <addr>)` MUST reproduce, byte for byte, `GenFw -t` of the same
module at base 0. Nothing of ours participates in producing the expected answer. A
vector that round-trips is evidence about the profile, not about our agreement with
ourselves.

  te-vectors.py --emit  --edk2 <tree> -o docs/normalized-module-hash-te-vectors.json
  te-vectors.py --check docs/normalized-module-hash-te-vectors.json
  te-vectors.py --derive docs/normalized-module-hash-te-vectors.json

--derive rebuilds only the patched vectors (the negatives and the crafted cases), starting from
the oracle output already stored in the file. It needs no edk2 tree, and on an unchanged file it
reproduces the existing entries exactly.
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import profile_ref  # noqa: E402

PROFILE = "uefi-te-rebase0.v1"
TE_HDR = 40

# Smallest of the reference PEIMs, so the inline inputs stay small. Any rebased
# XIP module would do; this one keeps the vectors file readable.
MODULE = "ReportStatusCodeRouterPei"
BASES = ["0x820000", "0xFFE00000"]


def _genfw(edk2):
    p = os.path.join(edk2, "BaseTools", "Source", "C", "bin", "GenFw")
    if not os.path.isfile(p):
        sys.exit("te-vectors: GenFw not found under --edk2 (looked in BaseTools/Source/C/bin)")
    return p


def _run(*args):
    r = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        sys.exit("te-vectors: command failed: %s" % " ".join(args))


def _reloc_dir_offset(b):
    """File offset of the relocation directory inside a TE, via s4.4's mapping."""
    nsec, stripped = b[4], struct.unpack_from("<H", b, 6)[0]
    rva, size = struct.unpack_from("<II", b, 24)
    tso = stripped - TE_HDR
    for i in range(nsec):
        h = TE_HDR + i * 40
        vs, va, rs, pr = struct.unpack_from("<IIII", b, h + 8)
        if pr and rs and va <= rva < va + rs:
            return rva - va + pr - tso, size
    return None, size


def build(edk2, workdir):
    """(id, rationale, bytes) for every vector, all built by edk2's own GenFw."""
    genfw = _genfw(edk2)
    efi = os.path.join(edk2, "Build", "OvmfX64", "DEBUG_GCC", "X64", MODULE + ".efi")
    if not os.path.isfile(efi):
        sys.exit("te-vectors: %s not found -- build OVMF DEBUG_GCC first" % efi)

    base0 = os.path.join(workdir, "base0.te")
    _run(genfw, "-t", "-o", base0, efi)
    out = [("te-real-base0",
            "%s converted to TE at ImageBase 0 by `GenFw -t`. The reference answer: every "
            "rebased vector below must normalize to exactly these bytes." % MODULE,
            open(base0, "rb").read())]

    for base in BASES:
        pe = os.path.join(workdir, "pe_%s.efi" % base)
        te = os.path.join(workdir, "te_%s.te" % base)
        _run(genfw, "--rebase", base, "-o", pe, efi)
        _run(genfw, "-t", "-o", te, pe)
        out.append(("te-real-rebased-%s" % base,
                    "The same module relocated to %s by `GenFw --rebase` and then converted to TE. "
                    "Normalizing it MUST reproduce te-real-base0 byte for byte. edk2 performed the "
                    "forward operation, so this is an oracle rather than self-agreement. Note "
                    "GenFw also writes the load address across PointerToRelocations/"
                    "PointerToLinenumbers of the first non-code section (GenFw.c:966-972); s4.2 "
                    "zeroes that pair, and it is the one byte the profile originally missed."
                    % base,
                    open(te, "rb").read()))

    return out + derived(out[1][2])


# Crafted from oracle output rather than produced by it. The expected value is exact, but an
# implementation may decline these without being non-conformant (profile s6).
MAY_DECLINE = {"te-fixup-rewrites-own-directory"}
DERIVED_FROM = "te-real-rebased-%s" % BASES[0]


def derived(rebased):
    """Every vector patched from the first rebased image, each isolating one rule."""
    rebased = bytearray(rebased)
    out = []
    v = bytearray(rebased)
    struct.pack_into("<II", v, 24, 0, 0)                 # DataDirectory[0] = {0, 0}
    out.append(("neg-te-relocations-stripped",
                "ImageBase != 0 with DataDirectory[0] all zero -- the TE spelling of "
                "IMAGE_FILE_RELOCS_STRIPPED, since a TE header has no Characteristics field. The "
                "fixups were applied and the table discarded, so the placement cannot be reversed: "
                "emit no value.", bytes(v)))

    v = bytearray(rebased)
    rva, _size = struct.unpack_from("<II", v, 24)
    struct.pack_into("<I", v, 28, 0)                     # keep VirtualAddress, Size = 0
    out.append(("te-sentinel-relocatable-no-fixups",
                "ImageBase != 0, DataDirectory[0].Size == 0 but VirtualAddress non-zero (%#x). "
                "GenFw writes exactly this to mean 'relocatable, no fixups to reverse' "
                "(GenFw.c:2700-2712). It is a sentinel, MUST NOT be dereferenced, and unlike the "
                "all-zero case it still normalizes -- ImageBase alone is zeroed." % rva,
                bytes(v)))

    v = bytearray(rebased)
    struct.pack_into("<H", v, 6, TE_HDR)                 # StrippedSize == header size
    out.append(("neg-te-strippedsize-not-greater-than-header",
                "StrippedSize == 40, so TeStrippedOffset would be 0 and the image claims nothing "
                "was stripped -- impossible, since the section table alone sits above it. s4.4 "
                "requires StrippedSize > 40: emit no value.", bytes(v)))

    v = bytearray(rebased)
    off, size = _reloc_dir_offset(v)
    if off is None:
        sys.exit("te-vectors: could not locate the relocation directory to build the odd-block case")
    blk = struct.unpack_from("<I", v, off + 4)[0]
    struct.pack_into("<I", v, off + 4, blk - 1)          # odd BlockSize, SHRUNK by one so the
    out.append(("neg-te-odd-blocksize",                  # block still fits the directory and the
                "First relocation block's BlockSize made odd (%d -> %d). It is shrunk rather than "
                "grown: .reloc is the last section, so widening the block would run past the end of "
                "the file and the directory-bounds check would fire first -- the vector would then "
                "pass while testing a different rule than it names. Entries are uint16, so an odd "
                "block leaves the last one straddling the end. Same rule as s4.1: emit no value."
                % (blk, blk - 1), bytes(v)))

    v = bytearray(rebased)
    off, _size = _reloc_dir_offset(v)
    dir_rva = struct.unpack_from("<I", v, 24)[0]
    struct.pack_into("<I", v, off, dir_rva & ~0xFFF)     # first block now covers the directory's page
    struct.pack_into("<H", v, off + 8, (10 << 12) | ((dir_rva + 8 + 2 * 2) & 0xFFF))
    out.append(("te-fixup-rewrites-own-directory",
                "The first relocation block is pointed at the directory's own page, and its first "
                "entry is a DIR64 fixup onto the block's third entry. So the walk patches entries it "
                "has not read yet. s4: every read in s4.1 comes from the working copy, after the "
                "earlier patches. An implementation that reads entries from the untouched input "
                "sees different entries and differs. Found by differential fuzzing, 2026-09-17.",
                bytes(v)))

    v = bytearray(rebased)
    nsec = v[4]
    out.append(("neg-te-section-table-past-end",
                "Image cut off inside the last section header (NumberOfSections = %d). s4.4 zeroes "
                "the pointer pair in every header, so the table must fit the image whatever "
                "ImageBase is. The reference used to check this only while walking relocations."
                % nsec, bytes(v[:TE_HDR + (nsec - 1) * 40 + 20])))
    return out


def _entry(cid, why, raw):
    entry = {"id": cid, "rationale": why,
             "input_b64": base64.b64encode(raw).decode(),
             "input_sha256": hashlib.sha256(raw).hexdigest(),
             "size": len(raw)}
    try:
        norm = profile_ref.normalize_te(raw)
        entry["expect_value"] = True
        entry["sha256_norm"] = hashlib.sha256(norm).hexdigest()
    except profile_ref.NotNormalizable as ex:
        entry["expect_value"] = False
        entry["sha256_norm"] = None
        entry["reason"] = str(ex)
    if cid in MAY_DECLINE:
        entry["may_decline"] = True
    return entry


def derive(path):
    """Rebuild the patched vectors from the oracle output stored in `path`, in place."""
    doc = json.load(open(path))
    src = next(v for v in doc["vectors"] if v["id"] == DERIVED_FROM)
    fresh = [_entry(*c) for c in derived(base64.b64decode(src["input_b64"]))]
    ids = {e["id"] for e in fresh}
    kept = [v for v in doc["vectors"] if v["id"] not in ids]
    for old in doc["vectors"]:
        new = next((e for e in fresh if e["id"] == old["id"]), None)
        if new is not None and new != old:
            sys.stderr.write("te-vectors: %s changed\n" % old["id"])
    doc["vectors"] = kept + fresh
    open(path, "w").write(json.dumps(doc, indent=2) + "\n")
    sys.stderr.write("te-vectors: %d derived vectors -> %s\n" % (len(fresh), path))
    return 0


def emit(edk2):
    with tempfile.TemporaryDirectory() as wd:
        cases = build(edk2, wd)
    vectors = [_entry(*c) for c in cases]

    # The round trip is the whole point: assert it here rather than trusting the file.
    truth = next(v for v in vectors if v["id"] == "te-real-base0")["sha256_norm"]
    for v in vectors:
        if v["id"].startswith("te-real-rebased-") and v["sha256_norm"] != truth:
            sys.exit("te-vectors: %s does not round-trip to te-real-base0 -- refusing to emit"
                     % v["id"])
    return {
        "profile": PROFILE,
        "description": "Conformance vectors for the TE sibling profile (uefi-te-rebase0.v1, "
                       "profile s4.4). Inputs are shipped inline (base64) and were produced by "
                       "edk2's own GenFw, which performs the forward operation these vectors "
                       "reverse. The rebased entries MUST normalize to the same digest as "
                       "te-real-base0 -- an independent oracle, not agreement between two of our "
                       "implementations.",
        "oracle": "edk2 BaseTools GenFw: `--rebase <addr>` then `-t`",
        "module": MODULE,
        "tool": "producers/reconcile/te-vectors.py",
        "expected_by": "producers/reconcile/profile_ref.py",
        "vectors": vectors,
    }


def check(path):
    doc = json.load(open(path))
    bad = 0
    truth = None
    for v in doc["vectors"]:
        raw = base64.b64decode(v["input_b64"])
        if hashlib.sha256(raw).hexdigest() != v["input_sha256"]:
            print("FAIL  %s: input digest does not match its own bytes" % v["id"]); bad += 1; continue
        try:
            got = hashlib.sha256(profile_ref.normalize_te(raw)).hexdigest()
        except profile_ref.NotNormalizable as ex:
            got, err = None, str(ex)
        if v["expect_value"]:
            if got == v["sha256_norm"]:
                print("PASS  %s" % v["id"])
            else:
                print("FAIL  %s: expected %s got %s" % (v["id"], v["sha256_norm"], got)); bad += 1
            if v["id"] == "te-real-base0":
                truth = got
        else:
            if got is None:
                print("PASS  %s declines (%s)" % (v["id"], err))
            else:
                print("FAIL  %s: expected no value, got %s" % (v["id"], got)); bad += 1

    for v in doc["vectors"]:
        if v["id"].startswith("te-real-rebased-"):
            if truth is not None and v["sha256_norm"] == truth:
                print("PASS  %s round-trips to the base-0 image built by the oracle" % v["id"])
            else:
                print("FAIL  %s does not round-trip to te-real-base0" % v["id"]); bad += 1

    print("\n%s  %d TE vectors, %d failing" % ("PASS" if not bad else "FAIL", len(doc["vectors"]), bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--check", metavar="VECTORS")
    ap.add_argument("--derive", metavar="VECTORS")
    ap.add_argument("--edk2")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    if a.check:
        return check(a.check)
    if a.derive:
        return derive(a.derive)
    if not a.edk2:
        sys.exit("te-vectors: --emit needs --edk2 <tree> (GenFw is the oracle)")
    doc = emit(a.edk2)
    txt = json.dumps(doc, indent=2) + "\n"
    if a.out:
        open(a.out, "w").write(txt)
        sys.stderr.write("te-vectors: %d vectors -> %s\n" % (len(doc["vectors"]), a.out))
    else:
        sys.stdout.write(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
