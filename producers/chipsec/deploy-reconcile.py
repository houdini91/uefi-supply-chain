#!/usr/bin/env python3
"""deploy-reconcile — CHIPSEC-fed DEPLOY-TIME byte reconcile against the signed SBOM (Track A).

byte-integrity (producers/reconcile/byte-integrity.py) answers the *admission-time*
question — "do the module bytes in the `.fd` file at rest match the SBOM's declared
hash?" — by carving the image with edk2 FMMT. This producer answers the *deploy-time*
question — "do the module bytes CHIPSEC extracts from the deployed image / live flash
match that same signed, build-born SBOM?" — using CHIPSEC as a **second, independent
carver**. Same SBOM baseline, extended from "at rest" to "on silicon", catching
post-admission / flash-time drift the at-rest gate cannot see (ADR 0001).

It is deliberately a THIN reuse of the proven primitive (A3):
  * REUSES `canon_unrebase`, `load_sbom_hashes`, `XIP_TYPES` from byte-integrity.py,
    UNCHANGED — the normalizer that made CHIPSEC-extracted bytes reproduce the SBOM's
    declared per-module SHA-256 on the OVMF reference (122/122).
  * The module TYPE is read from CHIPSEC's FV filetype directory — the **immediate**
    parent of the `.efi` (the nested-FV trap: an outer compressed DXEFV/PEIFV carries
    its own `.FV_FVIMAGE.dir`, which a whole-path match would wrongly grab and mislabel
    every nested PEI module as non-XIP). It is NEVER read from the SBOM/coSWID, so a
    typeless coSWID cannot force the wrong compare (byte-integrity's BUG-1 hardening).
  * Keyed by **FILE_GUID**, not name — names collide (two CpuMpPei, two CpuDxe with
    distinct GUIDs in OVMF), the GUID does not.

Reconcile is **bidirectional + GUID-bound**:
  * a SBOM GUID with no cleanly-extracted CHIPSEC PE  -> MISSING (tamper / dropped module);
  * a CHIPSEC GUID absent from the SBOM              -> UNEXPECTED (an implant);
  * bytes present but differ from the declared hash  -> MISMATCH (a same-GUID swap).
TE-format sections and anything CHIPSEC cannot cleanly extract to a normalizable PE are
SKIPPED — surfaced honestly, NEVER counted as verified (parity with byte-integrity's skip).

Input is EITHER a directory produced by `chipsec_util uefi decode <image>` (an FV-mirrored
tree of per-module `.efi` bytes), OR an `--image` that this script decodes itself when a
`chipsec_util` is reachable. evidenceGrade = `verified` — reconciled from real extracted bytes.

  deploy-reconcile.py --sbom sbom.cdx.json --decode-dir <img>.fd.dir [--efilist-in efilist.json] [-o verdict.json]
  deploy-reconcile.py --sbom sbom.cdx.json --image OVMF_CODE.fd [--chipsec-util <path>] [-o verdict.json]

A7 (interop): the same CHIPSEC-extracted per-module set can ALSO be emitted as a
CHIPSEC-`scan_image`-compatible `efilist.json` so our tool and CHIPSEC's `scan_image`
cross-check each other (`--emit-efilist <path>`). The base file is byte-schema-identical
to `scan_image`'s own output — keyed by the **as-found** sha256, value `{sha1, guid, name,
type}` in CHIPSEC's field order — so `chipsec_main -i -n -m tools.uefi.scan_image -a
check,<file>,<image>` consumes it unchanged. `--emit-efilist-annotated <path>` writes a
variant that adds a `sha256_norm` value field in the form CHIPSEC's `scan_image ... ,norm`
writes: `uefi-pe-rebase0.v1:sha256:<hex>` or `uefi-te-rebase0.v1:sha256:<hex>`, left out
where the profile gives no value. CHIPSEC's `check` keys on the sha256 and IGNORES the extra
field, so the annotated variant stays check-consumable too.

The verdict JSON carries a stable-namespace, signed-able predicateType
`https://firmware-sbom-supplychain/deploy-reconcile/v1` (wrap.sh wraps it into a
D-anchored in-toto Statement). Exit 0 iff the reconcile is clean (>=1 module matched,
and no mismatch / missing / unexpected / error).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

# --- REUSE the proven carving + normalizer primitives from ffs.py, imported (not reimplemented) ---
# (A3 proved canon_unrebase reproduces the SBOM's declared per-module hash from CHIPSEC-extracted
# bytes.) ffs also provides the numeric EFI_FV_FILETYPE -> label map used against CHIPSEC's UEFI.json.
_RECON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reconcile")
sys.path.insert(0, os.path.abspath(_RECON))
import ffs  # noqa: E402 — module handle so tests can reach ffs.pefile (XIP un-rebase availability)
from ffs import canon_unrebase, load_sbom_hashes, XIP_TYPES, ffs_type_label  # noqa: E402
import profile_ref  # noqa: E402 — dependency-free, so the annotated efilist needs no pefile

PREDICATE_TYPE = "https://firmware-sbom-supplychain/deploy-reconcile/v1"

# CHIPSEC's FV filetype-dir label -> the XIP_TYPES label, so the XIP/direct branch is IDENTICAL to
# byte-integrity's (which reads the EFI_FV_FILETYPE byte off the FFS). Used only by the dir-name
# FALLBACK; the authoritative path derives the label from UEFI.json's EFI_FILE.Type via ffs_type_label.
FV_TO_FILETYPE = {
    "FV_SECURITY_CORE": "SEC", "FV_PEI_CORE": "PEI_CORE", "FV_PEIM": "PEIM",
    "FV_DXE_CORE": "DXE_CORE", "FV_DRIVER": "DXE_DRIVER",
    "FV_APPLICATION": "APPLICATION", "FV_FREEFORM": "FREEFORM",
}
# '<NN>_<file_guid>[.FV_TYPE].dir' — a FILE_GUID-bearing decode dir. The NEAREST such ancestor of a
# module file gives its FILE_GUID (and, when present, its FV type), avoiding the nested-FV trap
# (grabbing an outer wrapper FV's '..FV_FVIMAGE.dir'). Used by the dir-name fallback only.
FV_DIR_RE = re.compile(r"^[0-9]+_([0-9a-fA-F-]{36})(?:\.(FV_[A-Z_]+))?\.dir$")

# Executable-section magics: an MZ image is a (normalizable) PE32; a VZ image is a Terse Executable
# (TE) — surfaced honestly and SKIPPED, never hashed as if it were the PE. Collection keys on these
# MAGIC bytes, NOT the file extension: CHIPSEC names a TE-with-UI-section module '<name>.efi' (VZ
# magic), so an extension filter both mislabels TE as PE32 and misses magic-only modules.
_PE_MAGIC = b"MZ"
_TE_MAGIC = b"VZ"


def _norm_guid(g):
    return (g or "").replace("-", "").lower()


def _mk_mod(raw, guid, filetype, name, path, efilist):
    """Assemble a module dict {guid, name, filetype, fv_type, sec_type, path, raw, asfound, is_pe}.
    is_pe / sec_type are derived from the extracted bytes' MAGIC (MZ->PE32, VZ->TE), never the file
    extension. An OPTIONAL efilist.json (keyed by CHIPSEC's as-found sha256) supplies a NAME hint
    only — it NEVER overrides the authoritative FILE_GUID derived from the FFS-file ancestry; a
    conflicting hint GUID is warned about, not applied (it falls back only when no authoritative
    GUID was derived at all)."""
    asfound = hashlib.sha256(raw).hexdigest()
    meta = efilist.get(asfound, {})
    guid = _norm_guid(guid)
    hint_guid = _norm_guid(meta.get("guid"))
    if guid and hint_guid and hint_guid != guid:
        sys.stderr.write("  ⚠ efilist name-hint GUID %s != authoritative FILE_GUID %s (%s) — keeping "
                         "the authoritative FILE_GUID\n" % (hint_guid[:12], guid[:12], meta.get("name") or name))
    guid = guid or hint_guid  # hint is a fallback ONLY when no authoritative GUID was derived
    is_te = raw[:2] == _TE_MAGIC
    return {
        "guid": guid, "name": meta.get("name") or name,
        "filetype": filetype, "fv_type": filetype,
        # 'type' the efilist records is the SECTION type (S_PE32/S_TE), from MAGIC.
        "sec_type": "S_TE" if is_te else "S_PE32",
        "path": path, "raw": raw, "asfound": asfound,
        # a normalizable PE has the 'MZ' DOS header; TE images ('VZ') and non-PE blobs do not —
        # those are is_pe=False -> UNVERIFIABLE (surfaced, never hashed as if they were the PE).
        "is_pe": raw[:2] == _PE_MAGIC,
    }


def _collect_from_uefi_json(uefi_json_path, base_dir, efilist):
    """AUTHORITATIVE collection: walk CHIPSEC's `<img>.UEFI.json` firmware tree (per-node class /
    Guid / Type / file_path). Every executable section (extracted bytes with MZ/VZ magic) is a
    module whose FILE_GUID + FFS filetype come from its NEAREST ANCESTOR EFI_FILE node — so a module
    nested arbitrarily deep under S_COMPRESSION / S_GUID_DEFINED / nested-FV sections is still
    collected with the right identity (the dir-name layout is irrelevant). Returns a module list, or
    None to signal 'fall back to the dir walk' when the JSON is unreadable."""
    try:
        with open(uefi_json_path) as f:
            tree = json.load(f)
    except (ValueError, OSError):
        return None
    mods, seen = [], set()
    tree_name = os.path.basename(uefi_json_path)[:-len(".UEFI.json")] + ".dir"

    def _resolve(fp):
        if not fp:
            return None
        if os.path.isabs(fp):
            return fp
        path = os.path.join(base_dir, fp)
        if os.path.isfile(path):
            return path
        # CHIPSEC writes file_path relative to the directory it was RUN from, which is only the
        # image's directory if decode was started there. Re-anchor on the decode tree's own name.
        parts = fp.replace("\\", "/").split("/")
        if tree_name in parts:
            i = len(parts) - 1 - parts[::-1].index(tree_name)
            return os.path.join(base_dir, *parts[i:])
        return path

    def rec(node, anc_guid, anc_type):
        if isinstance(node, list):
            for it in node:
                rec(it, anc_guid, anc_type)
            return
        if not isinstance(node, dict):
            return
        cls = node.get("class")
        if cls == "EFI_FILE":
            # An EFI_FILE (FFS file) carries the FILE_GUID + the EFI_FV_FILETYPE the module class is
            # read from. (An EFI_FV's Guid is the VOLUME id, not a module identity — it must NOT
            # become the ancestry, else nested-FV modules would inherit the wrapper's GUID.)
            anc_guid = _norm_guid(node.get("Guid")) or anc_guid
            anc_type = ffs_type_label(node.get("Type"))
        if cls == "EFI_SECTION":
            path = _resolve(node.get("file_path"))
            if path and os.path.isfile(path) and path not in seen:
                with open(path, "rb") as f:
                    raw = f.read()
                if raw[:2] in (_PE_MAGIC, _TE_MAGIC):
                    seen.add(path)
                    name = node.get("ui_string") or os.path.basename(path).rsplit(".", 1)[0]
                    mods.append(_mk_mod(raw, anc_guid, anc_type, name, path, efilist))
        for _k, v in node.items():
            if isinstance(v, (list, dict)):
                rec(v, anc_guid, anc_type)

    rec(tree, "", "")
    return mods


def _collect_from_dirs(decode_dir, efilist):
    """FALLBACK collection (no readable UEFI.json): walk the decode tree and collect every file whose
    MAGIC is MZ/VZ, WHEREVER it nests — the FILE_GUID + FV type come from the NEAREST ANCESTOR
    '<NN>_<guid>[.FV_TYPE].dir'. Magic-based (not extension-based) so a module directly under an
    'NN_S_COMPRESSION.dir' / 'NN_S_GUID_DEFINED.dir' (no '.FV_TYPE.dir' immediate parent) is still
    collected instead of silently dropped into a false MISSING."""
    mods = []
    for root, _dirs, files in os.walk(decode_dir):
        for fn in files:
            path = os.path.join(root, fn)
            try:
                with open(path, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            if raw[:2] not in (_PE_MAGIC, _TE_MAGIC):
                continue
            guid, filetype = "", ""
            for seg in reversed(path.split(os.sep)[:-1]):  # nearest ancestor guid dir wins
                m = FV_DIR_RE.match(seg)
                if m:
                    guid = m.group(1)
                    filetype = FV_TO_FILETYPE.get(m.group(2) or "", "")
                    break
            mods.append(_mk_mod(raw, guid, filetype, fn.rsplit(".", 1)[0], path, efilist))
    return mods


def collect_modules(decode_dir, efilist_path=None):
    """Collect the executable modules from a `chipsec_util uefi decode` tree. Prefers CHIPSEC's
    authoritative `<img>.UEFI.json` (per-node guid/type/file_path, robust to arbitrary
    compression/GUID-defined/nested-FV nesting); falls back to a magic-based dir walk when no
    UEFI.json sits beside the tree. -> list of module dicts (see _mk_mod)."""
    efilist = {}
    if efilist_path and os.path.isfile(efilist_path):
        try:
            with open(efilist_path) as f:
                efilist = json.load(f)
        except (ValueError, OSError):
            efilist = {}
    dd = decode_dir.rstrip(os.sep)
    base_dir = os.path.dirname(os.path.abspath(dd))
    uefi_json = (dd[:-4] if dd.endswith(".dir") else dd) + ".UEFI.json"
    if os.path.isfile(uefi_json):
        mods = _collect_from_uefi_json(uefi_json, base_dir, efilist)
        if mods is not None:
            return mods
    return _collect_from_dirs(decode_dir, efilist)


def normalize(mod):
    """byte-integrity's EXACT decision: XIP -> canon_unrebase(raw), else hash raw directly.
    Returns (normalized_sha256, method). Raises on a malformed/unsupported reloc (fail closed)."""
    raw = mod["raw"]
    if mod["filetype"] in XIP_TYPES:
        canon = canon_unrebase(raw)  # the reused repo normalizer, UNCHANGED
        if canon is None:
            raise RuntimeError("pefile unavailable — cannot un-rebase XIP module %s" % mod["filetype"])
        return hashlib.sha256(canon).hexdigest(), "un-rebase"
    return hashlib.sha256(raw).hexdigest(), "direct"


def _guid_dashed_upper(norm_guid):
    """32-hex-lowercase (our internal key form) -> CHIPSEC's 8-4-4-4-12 UPPERCASE-dashed
    FILE_GUID form (what scan_image writes into efilist.json's `guid` value field)."""
    g = norm_guid
    return ("%s-%s-%s-%s-%s" % (g[0:8], g[8:12], g[12:16], g[16:20], g[20:32])).upper()


def labelled_norm(raw):
    """`<profile>:sha256:<hex>` for a PE32 or TE image, or None where the profile gives no value.

    Always the full profile, via profile_ref -- not normalize()'s "direct" shortcut, which hashes
    a non-XIP module as found without parsing it. That shortcut is right for reconciling against
    the SBOM, but a value labelled with a profile must be what the profile computes.
    """
    if raw[:2] == _PE_MAGIC:
        profile, fn = "uefi-pe-rebase0.v1", profile_ref.normalize
    elif raw[:2] == _TE_MAGIC:
        profile, fn = "uefi-te-rebase0.v1", profile_ref.normalize_te
    else:
        return None
    try:
        return "%s:sha256:%s" % (profile, hashlib.sha256(fn(raw)).hexdigest())
    except profile_ref.NotNormalizable:
        return None


def build_efilist(mods, annotated=False):
    """Assemble a CHIPSEC-`scan_image`-compatible efilist, keyed by the module's **as-found**
    sha256 (== CHIPSEC's `EFI_MODULE.SHA256`, i.e. the key scan_image writes), value dict
    `{sha1, guid, name, type}` in CHIPSEC's exact field ORDER. De-duplicated by sha256 (first
    walk-order occurrence wins) — mirroring scan_image's genlist_callback, which drops a
    later section with an already-seen SHA256 into a duplicate list rather than re-adding it.

    annotated=True appends an additive `sha256_norm` value field, spelled as CHIPSEC's
    `scan_image ... ,norm` spells it: see labelled_norm(). The field is left out when the profile
    gives no value, as CHIPSEC does. CHIPSEC's `check` keys on the sha256 and ignores extra value
    fields, so the annotated file is still `check`-consumable; the base (annotated=False) file is
    byte-schema-identical to scan_image's own output."""
    efilist = {}
    for md in mods:
        key = md["asfound"]
        if key in efilist:   # same-hash section already recorded -> CHIPSEC-style dedupe
            continue
        # 'type' is the SECTION type scan_image records (EFI_SECTION.Name), NOT the FV
        # filetype: an executable section is S_PE32 (PE32/PE32+) or S_TE (terse-executable).
        entry = {
            "sha1": hashlib.sha1(md["raw"]).hexdigest(),
            "guid": _guid_dashed_upper(md["guid"]),
            "name": md["name"],
            # section type from the MAGIC of the extracted bytes (VZ->S_TE, MZ->S_PE32), NOT the file
            # extension — CHIPSEC names a TE-with-UI module '<name>.efi', which an extension test
            # would mislabel S_PE32. sec_type is computed once in _mk_mod.
            "type": md["sec_type"],
        }
        if annotated:
            norm = labelled_norm(md["raw"])
            if norm:
                entry["sha256_norm"] = norm
        efilist[key] = entry
    return efilist


def write_efilist(efilist, path):
    """Serialize EXACTLY as scan_image does — `json.dumps(indent=2, separators=(',', ': '))`,
    NO trailing newline — so the base file is byte-schema-identical to CHIPSEC's efilist.json."""
    with open(path, "w") as f:
        f.write(json.dumps(efilist, indent=2, separators=(",", ": ")))


def reconcile(declared, mods, image_digest=""):
    """Bidirectional, GUID-bound reconcile of CHIPSEC-extracted modules vs the SBOM's declared
    per-module hashes. declared: {guid: (name, sha256)}; mods: collect_modules() output."""
    matched, mismatched, skipped, errored, unexpected = [], [], [], [], []
    seen = set()  # SBOM GUIDs observed with a comparable PE (matched or mismatched)

    for md in sorted(mods, key=lambda m: (m["name"] or "", m["guid"])):
        guid = md["guid"]
        dname, dhash = declared.get(guid, (None, None))
        if dhash is None:
            # CHIPSEC extracted a module the SBOM does not declare -> UNEXPECTED (implant).
            unexpected.append({"name": md["name"], "guid": guid, "fv_type": md["fv_type"]})
            continue
        if not md["is_pe"]:
            # a TE / non-PE section CHIPSEC could not extract as a normalizable PE -> SKIP
            # (surfaced, NEVER counted as verified).
            skipped.append({"name": dname or md["name"], "guid": guid,
                            "reason": "no normalizable PE32 (TE / non-PE section)"})
            continue
        try:
            observed, method = normalize(md)
        except Exception as e:  # noqa: BLE001 — fail closed, record, keep going
            errored.append({"name": dname or md["name"], "guid": guid, "error": str(e)[:200]})
            continue
        seen.add(guid)
        (matched if observed == dhash else mismatched).append(
            {"name": dname or md["name"], "guid": guid, "declared": dhash,
             "observed": observed, "method": method})

    # SBOM-declared GUIDs never observed with a comparable PE in the extract -> MISSING
    # (a declared module dropped / tampered away). A GUID that WAS seen but only as a
    # skip/error is reported under that head, not double-counted as missing.
    accounted = seen | {s["guid"] for s in skipped} | {e["guid"] for e in errored}
    missing = [{"name": name, "guid": guid}
               for guid, (name, _h) in sorted(declared.items(), key=lambda kv: kv[1][0] or "")
               if guid not in accounted]

    reconciled = len(matched) + len(mismatched)  # the comparable set
    declared_count = len(declared)
    # A declared module that came back non-PE (TE), unextractable, or errored is UNVERIFIABLE DRIFT,
    # NOT a benign skip — a same-GUID PE->TE swap lands here, and folding it into a pass would let it
    # through. So `clean` requires FULL coverage of the declared set: every declared module MATCHED,
    # with nothing mismatched / missing / unexpected / skipped / errored. (The gate additionally
    # honors a reviewed data.deploy_reconcile_exempt allowlist for genuinely-unverifiable modules —
    # the producer verdict is unconditionally strict; the exemption is a rego-side policy decision,
    # mirroring byte-integrity, whose producer `clean` is likewise verified==checked.)
    clean = (declared_count > 0
             and len(matched) == declared_count
             and not mismatched and not missing and not unexpected
             and not skipped and not errored)
    return {
        "tool": "deploy-reconcile",
        "predicateType": PREDICATE_TYPE,
        "source": "chipsec-uefi-decode",
        "granularity": "module/PE32-bytes (CHIPSEC-extracted, GUID-bound, bidirectional)",
        "image_digest": image_digest,
        "declared": len(declared),
        "reconciled": reconciled,
        "matched": len(matched),
        "verified_direct": sum(1 for v in matched if v["method"] == "direct"),
        "verified_unrebase": sum(1 for v in matched if v["method"] == "un-rebase"),
        # FULL per-module manifest — enumerated, not just counted, so an auditor sees exactly what
        # reconciled / did not.
        "matched_modules": [{"name": v["name"], "guid": v["guid"], "method": v["method"]} for v in matched],
        "mismatched": mismatched,
        "missing": missing,
        "unexpected": unexpected,
        "skipped": skipped,
        "errored": errored,
        "evidenceGrade": "verified",  # reconciled from real CHIPSEC-extracted bytes
        "clean": clean,
    }


def run_decode(image, chipsec_util, workdir):
    """Run `chipsec_util uefi decode <image>` in workdir; return the decode-dir path (or exit)."""
    tool = chipsec_util or "chipsec_util"
    img_copy = os.path.join(workdir, os.path.basename(image))
    with open(image, "rb") as s, open(img_copy, "wb") as d:
        d.write(s.read())
    try:
        subprocess.run([tool, "uefi", "decode", img_copy], cwd=workdir,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        sys.exit("deploy-reconcile: `chipsec_util uefi decode` failed (%s). Install CHIPSEC and pass "
                 "--chipsec-util <path>, or pre-run decode and pass --decode-dir." % (str(e)[:120]))
    decode_dir = img_copy + ".dir"
    if not os.path.isdir(decode_dir):
        sys.exit("deploy-reconcile: expected decode tree not found at %s" % decode_dir)
    return decode_dir


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--decode-dir", dest="decode_dir",
                    help="a `chipsec_util uefi decode <image>` output tree (per-module .efi bytes)")
    ap.add_argument("--image", help="a firmware image to decode with CHIPSEC ourselves (needs chipsec_util)")
    ap.add_argument("--chipsec-util", dest="chipsec_util", help="path to chipsec_util (default: on PATH)")
    # INPUT name-hints (disambiguated from the --emit-efilist OUTPUTs below): a CHIPSEC efilist.json
    # consulted for module NAMES only; it NEVER overrides the authoritative FILE_GUID. '--efilist' is
    # kept as a deprecated alias.
    ap.add_argument("--efilist-in", "--name-hints", "--efilist", dest="efilist_in", metavar="PATH",
                    help="optional CHIPSEC efilist.json read for module NAME hints only (never overrides "
                         "the authoritative FILE_GUID). Alias: --name-hints (deprecated: --efilist)")
    ap.add_argument("--emit-efilist", dest="emit_efilist", metavar="PATH",
                    help="ALSO write a CHIPSEC-scan_image-compatible efilist.json (keyed by the as-found "
                         "sha256, value {sha1,guid,name,type}) — byte-schema-identical to scan_image's, so "
                         "`chipsec_main -m tools.uefi.scan_image -a check,<PATH>,<image>` consumes it (A7 interop)")
    ap.add_argument("--emit-efilist-annotated", dest="emit_efilist_annotated", metavar="PATH",
                    help="ALSO write an efilist.json with an additive `sha256_norm` value field, in the "
                         "form CHIPSEC `scan_image ... ,norm` writes; CHIPSEC `check` keys on the sha256 "
                         "and ignores it")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if not os.path.isfile(a.sbom):
        sys.exit("deploy-reconcile: --sbom not found: %s" % a.sbom)
    if not a.decode_dir and not a.image:
        sys.exit("deploy-reconcile: supply --decode-dir (a chipsec decode tree) or --image (we decode it)")

    image_digest = ""
    if a.image and os.path.isfile(a.image):
        with open(a.image, "rb") as f:
            image_digest = "sha256:" + hashlib.sha256(f.read()).hexdigest()

    declared = load_sbom_hashes(a.sbom)  # {guid: (name, declared_sha256)} — REUSED loader

    # A pre-decoded --decode-dir needs NO temp dir; only the self-decode (--image) path does.
    td_ctx = tempfile.TemporaryDirectory() if not a.decode_dir else None
    try:
        decode_dir = a.decode_dir or run_decode(a.image, a.chipsec_util, td_ctx.name)
        if not os.path.isdir(decode_dir):
            sys.exit("deploy-reconcile: --decode-dir not a directory: %s" % decode_dir)
        mods = collect_modules(decode_dir, a.efilist_in)
        verdict = reconcile(declared, mods, image_digest)
        # A7 interop: emit a CHIPSEC-scan_image-compatible efilist from the SAME extracted
        # module set (an OUTPUT — does not change the verdict / gate counts).
        if a.emit_efilist:
            el = build_efilist(mods, annotated=False)
            write_efilist(el, a.emit_efilist)
            print("deploy-reconcile: wrote CHIPSEC-compatible efilist (%d entries) -> %s"
                  % (len(el), a.emit_efilist), file=sys.stderr)
        if a.emit_efilist_annotated:
            ela = build_efilist(mods, annotated=True)
            write_efilist(ela, a.emit_efilist_annotated)
            print("deploy-reconcile: wrote sha256_norm-annotated efilist (%d entries) -> %s"
                  % (len(ela), a.emit_efilist_annotated), file=sys.stderr)
    finally:
        if td_ctx is not None:
            td_ctx.cleanup()

    out = json.dumps(verdict, indent=2)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out + "\n")
        print("deploy-reconcile: matched=%d/%d mismatched=%d missing=%d unexpected=%d skipped=%d -> %s"
              % (verdict["matched"], verdict["reconciled"], len(verdict["mismatched"]),
                 len(verdict["missing"]), len(verdict["unexpected"]), len(verdict["skipped"]), a.out))
    else:
        print(out)
    for m in verdict["mismatched"]:
        sys.stderr.write("  ⛔ MISMATCH %s: declared %s != observed %s (on-device byte swap)\n"
                         % (m["name"], m["declared"][:16], m["observed"][:16]))
    for m in verdict["missing"]:
        sys.stderr.write("  ⛔ MISSING %s (%s): declared in SBOM, not extractable by CHIPSEC\n"
                         % (m["name"], m["guid"][:12]))
    for u in verdict["unexpected"]:
        sys.stderr.write("  ⛔ UNEXPECTED %s (%s): extracted by CHIPSEC, not in the SBOM\n"
                         % (u["name"], u["guid"][:12]))
    sys.exit(0 if verdict["clean"] else 1)


if __name__ == "__main__":
    main()
