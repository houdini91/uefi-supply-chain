#!/usr/bin/env python3
"""ffs — shared UEFI firmware-image carving helpers.

Used by both `byte-integrity.py` (does the shipped PE32 match its declared hash?)
and `binary-hardening.py` (what exploit-mitigation posture do those PE32 images
declare?). Keeping the FFS/section walk and the FMMT extraction in one place means
the two producers carve the deployed image identically — a divergence here would
make the two lanes disagree about *which bytes* a module even is.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys

try:
    import pefile  # only needed for XIP/PEI un-rebase canonicalization (byte-integrity phase 3)
except ImportError:
    pefile = None

# XIP / execute-in-place module types: stored rebased to their flash address in the FV, so the
# in-image PE32 differs from the declared (un-rebased) .efi. Naive byte comparison does NOT apply —
# the image bytes are un-rebased first, never reported as tampered. The module's type is read from
# the CARVED FFS (ffs_module_type), i.e. from the shipped image — NOT from the SBOM/coSWID, which
# carries only the declared HASH. Shared by byte-integrity (at-rest) + deploy-reconcile (deploy-time)
# so the two lanes make the identical XIP/direct decision.
XIP_TYPES = {"SEC", "PEI_CORE", "PEIM"}


# EFI_FV_FILETYPE (PI spec, EFI_FFS_FILE_HEADER.Type at offset 0x12) -> the
# module-type label byte-integrity branches on. This is read from the FFS the image
# was CARVED INTO — i.e. from the shipped image itself, not from any declaration in
# the SBOM/coSWID. The SEC/PEI_CORE/PEIM types are XIP (execute-in-place): stored
# rebased to their flash load address, so they must be un-rebased before hashing;
# everything else is compared directly. Deriving the type here (from the image) is
# what makes a declaration-carried type unnecessary — and prevents the class of bug
# where a typeless coSWID makes every module look like a DXE driver.
FFS_FILETYPE = {
    0x03: "SEC",
    0x04: "PEI_CORE",
    0x05: "DXE_CORE",
    0x06: "PEIM",
    0x07: "DXE_DRIVER",
    0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION",
    0x0A: "SMM",
    0x0D: "SMM_CORE",
}


def ffs_module_type(ffs):
    """The module type read from the FFS file header's EFI_FV_FILETYPE byte (offset
    0x12) of the carved image blob — NOT from any SBOM/coSWID declaration. Returns a
    module-type string ('PEIM', 'DXE_DRIVER', ...) or '' if the blob is too short or
    the type byte is unrecognized (treated conservatively as non-XIP -> direct)."""
    if len(ffs) <= 0x12:
        return ""
    return FFS_FILETYPE.get(ffs[0x12], "")


def pe32_from_ffs(ffs):
    """Return the PE32 (section type 0x10) payload bytes from an FFS blob, or None.
    FFS header is 24 bytes (EFI_FFS_FILE_HEADER), or 32 bytes when the
    FFS_ATTRIB_LARGE_FILE bit (0x01) is set (EFI_FFS_FILE_HEADER2 adds an 8-byte
    ExtendedSize). Sections are 4-byte-aligned with a 4-byte common header
    (3-byte size + 1-byte type), or an 8-byte header when size==0xFFFFFF."""
    if len(ffs) < 24:
        return None
    off = 32 if (ffs[0x13] & 0x01) else 24   # ffs[0x13] = Attributes; bit0 = LARGE_FILE
    while off + 4 <= len(ffs):
        size = ffs[off] | (ffs[off + 1] << 8) | (ffs[off + 2] << 16)
        stype = ffs[off + 3]
        shdr = 4
        if size == 0xFFFFFF:
            size = struct.unpack_from("<I", ffs, off + 4)[0]
            shdr = 8
        if size < shdr or off + size > len(ffs):
            break
        if stype == 0x10:  # EFI_SECTION_PE32
            return ffs[off + shdr: off + size]
        off = (off + size + 3) & ~3
    return None


def fmmt_extract(fmmt_py, edk2, image, guid, dst):
    """FMMT -e image guid dst  -> extracted FFS at dst (decompresses FVs)."""
    env = dict(os.environ,
               PYTHONPATH=os.path.join(edk2, "BaseTools", "Source", "Python"),
               PATH=os.path.join(edk2, "BaseTools", "Source", "C", "bin") + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run([sys.executable, fmmt_py, "-e", image, guid, dst],
                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0 and os.path.isfile(dst) and os.path.getsize(dst) > 0


def fmmt_py_path(edk2):
    """Path to FMMT.py under an edk2 tree (or None if absent)."""
    p = os.path.join(edk2, "BaseTools", "Source", "Python", "FMMT", "FMMT.py")
    return p if os.path.isfile(p) else None


def iter_sbom_modules(sbom_path, include_libraries=False):
    """Yield (guid[lower,no-dashes], name, module_type) for every CycloneDX
    component that carries a 32-hex GUID bom-ref. module_type is the edk2:moduleType
    property or "" when absent.

    By default libraries (edk2:isLibrary=True / type=library) are skipped: they are
    linked into their parent module and never ship as a standalone FFS, so carving
    them from the image would just yield 188 phantom "skips". This keeps the examined
    set equal to byte-integrity's real-module population (the 122 modules with a PE32).
    Pass include_libraries=True to yield them anyway."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    for c in sbom.get("components", []):
        ref = (c.get("bom-ref") or "").replace("-", "").lower()
        if len(ref) != 32:
            continue
        props = {p.get("name"): p.get("value") for p in (c.get("properties") or [])}
        is_lib = props.get("edk2:isLibrary") == "True" or c.get("type") == "library"
        if is_lib and not include_libraries:
            continue
        yield ref, c.get("name"), props.get("edk2:moduleType", "")


def ffs_type_label(type_num):
    """Map an EFI_FV_FILETYPE NUMBER (e.g. CHIPSEC's UEFI.json EFI_FILE.Type, a decimal string,
    or a raw int) to the module-type label byte-integrity/deploy-reconcile branch on. Returns ''
    (conservatively non-XIP -> direct) for an unknown / unparseable value. This is the numeric
    twin of ffs_module_type() (which reads the same byte off the carved FFS header)."""
    try:
        n = int(type_num)
    except (TypeError, ValueError):
        return ""
    return FFS_FILETYPE.get(n, "")


def load_sbom_hashes(sbom_path):
    """{guid(lower,no-dashes): (name, declared_sha256)} for components with a GUID bom-ref and a
    declared SHA-256. The module TYPE is deliberately NOT read here — it is derived per-module from
    the carved image (ffs_module_type / ffs_type_label), so a typeless SBOM/coSWID (declaring only
    the hash) cannot force the wrong comparison. Shared by byte-integrity (at-rest) and
    deploy-reconcile (deploy-time) so both reconcile against the IDENTICAL declared set."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    out = {}
    for c in sbom.get("components", []):
        ref = (c.get("bom-ref") or "").replace("-", "").lower()
        if len(ref) != 32:
            continue
        for h in c.get("hashes", []) or []:
            if h.get("alg") == "SHA-256" and h.get("content"):
                digest = h["content"].lower()
                # F6 guard: two components sharing a FILE_GUID collapse in a GUID-keyed map.
                # Harmless when they declare the same hash; if they differ, one would be silently
                # unchecked — warn loudly rather than mask it.
                if ref in out and out[ref][1] != digest:
                    sys.stderr.write("  ⚠ duplicate FILE_GUID %s with differing hashes (%s / %s) — "
                                     "only one instance is byte-checked\n" % (ref, out[ref][1][:12], digest[:12]))
                out[ref] = (c.get("name"), digest)
    return out


def _profile_rva_to_offset(rva, buf, fh, oh):
    """Profile s4.1 RVA -> file offset, read from the RAW section table.

    Deliberately NOT pefile's get_offset_from_rva. pefile widens a section's span to
    max(VirtualSize, SizeOfRawData), substitutes VirtualSize when SizeOfRawData looks
    unrealistic, clamps to the next section, and — when nothing matches at all — returns
    the RVA itself as the offset. Those are sensible heuristics for reading damaged files
    and wrong for computing an identity: this function must be exact or fail. Delegating
    it also meant this file implemented pefile rather than the profile.
    """
    n = struct.unpack_from("<H", buf, fh + 2)[0]
    size_opt = struct.unpack_from("<H", buf, fh + 16)[0]
    base = oh + size_opt
    for i in range(n):
        s = base + i * 40
        if s + 40 > len(buf):
            raise ValueError("section table past end of image")
        vaddr = struct.unpack_from("<I", buf, s + 12)[0]
        rsize = struct.unpack_from("<I", buf, s + 16)[0]
        praw = struct.unpack_from("<I", buf, s + 20)[0]
        if praw == 0 or rsize == 0:
            continue
        if vaddr <= rva < vaddr + rsize:
            return praw + (rva - vaddr)
    raise ValueError("rva %#x maps to no section with raw data" % rva)


def canon_unrebase(pe_bytes):
    """Un-rebase a PE image back to ImageBase 0 (undo the flash relocation) and zero
    ImageBase/TimeDateStamp/CheckSum — so an XIP/PEI module's rebased in-flash bytes can be fairly
    compared to the declared (un-rebased) .efi. The relocation table records exactly which fields
    were shifted, so this is exact and reversible. A module with NO relocation table has nothing to
    reverse — rebasing moved only its ImageBase — so header normalization alone canonicalizes it. A
    real tamper changes code the relocations don't cover, so it still fails. Returns canonical bytes,
    or None if pefile is unavailable.

    Every change is an IN-PLACE byte patch at a computed file offset — the image is never
    parsed-and-re-serialized. That matters because this normal form is the comparison contract
    between a build-time producer and an independent verifier (see
    ``planning/normalized-module-identity.html``): re-serializing would make the output depend on
    a particular PE library's writer, which a second implementation could not be expected to
    reproduce. Byte patching depends only on the input bytes and the documented PE field offsets.
    Verified as a faithful drop-in for the former pefile ``write()`` path: byte-for-byte identical
    output on all 122 modules of the OVMF reference, all matching their declared SBOM hash."""
    if pefile is None:
        return None
    pe = pefile.PE(data=pe_bytes, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
    base = pe.OPTIONAL_HEADER.ImageBase
    buf = bytearray(pe.__data__)
    _e = struct.unpack_from("<I", buf, 0x3C)[0]
    _fh = _e + 4
    _oh = _fh + 20
    # A non-zero ImageBase with NO relocation table means the module has no relocations at all:
    # being rebased to its flash address changed ONLY the ImageBase header field, nothing in
    # code/data. Zeroing ImageBase/TimeDateStamp/CheckSum (below) is therefore the exact, faithful
    # canonicalization. A module whose reloc table was STRIPPED after rebasing would fail to match
    # here — flagged modified, never a false pass. Only when a reloc table is present is there
    # anything to reverse.
    # That reasoning is sound for reconciliation (a mismatch is safe) but not for publishing an
    # IDENTITY: a stripped module's value would claim base 0 while its code still carries the load
    # address. The two cases are distinguishable — IMAGE_FILE_RELOCS_STRIPPED (0x0001) in
    # FileHeader.Characteristics — so absence still emits, removal now fails (profile s4.1, G10).
    # A relocation directory that is DECLARED but that pefile would not parse must fail
    # closed. Without this the loop below is simply skipped and the function returns a
    # header-only normalization — indistinguishable from a module that genuinely has no
    # relocations, and silently wrong for one that does. pefile drops a directory it
    # dislikes (bad FileAlignment, RVA it maps elsewhere, malformed block) without raising,
    # so "no entries" is not evidence of "no relocations". Found by cross-checking against
    # producers/reconcile/profile_ref.py, which parses relocations itself.
    if base:
        # Read the directory bounds from the RAW header, not from pefile's parsed list: when
        # the image is truncated inside the data directory pefile returns a SHORTER list
        # without raising, so `len(_dd) > 5` is False and the truncation looks like absence.
        # Second fail-open of this class, found by the conformance floor (profile s4.1:
        # "an unreadable directory is a failure, not an absence").
        _magic = struct.unpack_from("<H", buf, _oh)[0]
        _numrva_off, _dd_off = ((_oh + 92, _oh + 96) if _magic == 0x10B else (_oh + 108, _oh + 112))
        if _numrva_off + 4 > len(buf):
            raise ValueError("NumberOfRvaAndSizes unreadable with ImageBase != 0")
        if struct.unpack_from("<I", buf, _numrva_off)[0] > 5 and _dd_off + 6 * 8 > len(buf):
            raise ValueError("data directory truncated before the base-relocation entry")
        _dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        _declared = len(_dd) > 5 and _dd[5].VirtualAddress and _dd[5].Size
        if not _declared and (struct.unpack_from("<H", buf, _fh + 18)[0] & 0x0001):
            raise ValueError("relocations stripped with ImageBase != 0; not reversible")
        if _declared and not getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None):
            raise ValueError(
                "relocation directory declared (rva %#x size %d) but no entries were parsed — "
                "refusing to emit a header-only normalization"
                % (_dd[5].VirtualAddress, _dd[5].Size))
    if base and hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        for blk in pe.DIRECTORY_ENTRY_BASERELOC:
            # Entries are u16, so a block whose size is odd cannot be well-formed. pefile
            # floors the entry count and carries on; the profile (s4.1) says fail. Check the
            # raw SizeOfBlock ourselves rather than trust the parsed entry list.
            if (blk.struct.SizeOfBlock - 8) % 2:
                raise ValueError("odd relocation BlockSize %d" % blk.struct.SizeOfBlock)
            for e in blk.entries:
                if e.type == 0:            # IMAGE_REL_BASED_ABSOLUTE — padding, skip
                    continue
                off = _profile_rva_to_offset(e.rva, buf, _fh, _oh)
                if e.type == 3:            # HIGHLOW (32-bit)
                    if off + 4 > len(buf):
                        raise ValueError("HIGHLOW reloc past end of image")
                    v = struct.unpack_from("<I", buf, off)[0]
                    struct.pack_into("<I", buf, off, (v - base) & 0xFFFFFFFF)
                elif e.type == 10:         # DIR64 (64-bit)
                    if off + 8 > len(buf):
                        raise ValueError("DIR64 reloc past end of image")
                    v = struct.unpack_from("<Q", buf, off)[0]
                    struct.pack_into("<Q", buf, off, (v - base) & ((1 << 64) - 1))
                else:
                    # HIGH/LOW/HIGHADJ/ARM/etc. — not handled; fail closed so we never emit a
                    # partially-un-rebased (wrong) image as if it were canonical.
                    raise ValueError("unsupported relocation type %d" % e.type)
    # Header normalization, as byte patches at their documented file offsets. Layout:
    #   e_lfanew @ 0x3C -> "PE\0\0" (4) -> COFF FILE_HEADER (20) -> OPTIONAL_HEADER
    #   FILE_HEADER.TimeDateStamp   @ fh + 4
    #   OPTIONAL_HEADER.CheckSum    @ oh + 64   (same for PE32 and PE32+)
    #   OPTIONAL_HEADER.ImageBase   @ oh + 28 (4 bytes, PE32)  /  oh + 24 (8 bytes, PE32+)
    if len(buf) < 0x40:
        raise ValueError("image too small for a DOS header")
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if e_lfanew + 4 + 20 + 68 > len(buf):
        raise ValueError("e_lfanew %#x leaves no room for the PE headers" % e_lfanew)
    if bytes(buf[e_lfanew:e_lfanew + 4]) != b"PE\0\0":
        raise ValueError("no PE signature at e_lfanew %#x" % e_lfanew)
    fh = e_lfanew + 4
    oh = fh + 20
    magic = struct.unpack_from("<H", buf, oh)[0]
    if magic == 0x20B:          # PE32+ — no BaseOfData, ImageBase is 8 bytes
        ib_off, ib_fmt = oh + 24, "<Q"
    elif magic == 0x10B:        # PE32
        ib_off, ib_fmt = oh + 28, "<I"
    else:
        # Fail closed rather than emit a partially-normalized image.
        raise ValueError("unsupported optional-header magic %#x" % magic)
    struct.pack_into("<I", buf, fh + 4, 0)      # TimeDateStamp
    struct.pack_into("<I", buf, oh + 64, 0)     # CheckSum
    struct.pack_into(ib_fmt, buf, ib_off, 0)    # ImageBase
    return bytes(buf)
