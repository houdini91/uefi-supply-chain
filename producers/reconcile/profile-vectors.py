#!/usr/bin/env python3
"""profile-vectors — emit and check conformance vectors for the normalized-module-hash profile.

The normal form produced by `canon_unrebase()` is the comparison contract between a build-time
producer (edk2 `-Y SBOM`) and an independent verifier (this repo, and — proposed — CHIPSEC
`scan_image --norm`). A prose description is not enough for a second implementer: they need
(input digest -> output digest) pairs they can reproduce.

These vectors are self-contained without shipping any binaries. Each entry names the module by
FILE_GUID inside a publicly reproducible image (the OVMF reference at anchor digest D), records
the **as-found** PE32 digest (what a naive carve yields) and the **normalized** digest (what the
profile yields), and the method that got there. A second implementation is conformant iff, given
the same as-found bytes, it reproduces every `sha256_norm`.

The 11 entries where `sha256_asfound != sha256_norm` are the load-bearing ones: those are the
XIP/PEI modules that are rebased in flash, and they are the only reason this profile exists.

  profile-vectors.py --emit   --sbom … --image … --edk2 … -o vectors.json
  profile-vectors.py --check  vectors.json --image … --edk2 …      (regression; exit 1 on drift)
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ffs import (  # noqa: E402
    pe32_from_ffs, fmmt_extract, canon_unrebase, load_sbom_hashes, pefile,
)

PROFILE_ID = "uefi-pe-rebase0/v1"   # PLACEHOLDER — naming is a community decision, see
                                    # planning/normalized-module-identity.html


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def collect(sbom, image, edk2):
    """-> (entries, stats). One FMMT extraction pass over every declared module."""
    fmmt = os.path.join(edk2, "BaseTools", "Source", "Python", "FMMT", "FMMT.py")
    if not os.path.isfile(fmmt):
        sys.exit("profile-vectors: FMMT.py not found under --edk2")
    declared = load_sbom_hashes(sbom)
    entries, stats = [], {"declared": len(declared), "extract_fail": 0, "no_pe32": 0, "error": 0}

    with tempfile.TemporaryDirectory() as td:
        for guid, meta in sorted(declared.items()):
            name, want = meta[0], meta[1]
            dst = os.path.join(td, guid + ".ffs")
            if not fmmt_extract(fmmt, edk2, image, guid, dst):
                stats["extract_fail"] += 1
                continue
            with open(dst, "rb") as f:
                pe = pe32_from_ffs(f.read())
            if pe is None:
                stats["no_pe32"] += 1
                continue
            try:
                norm = canon_unrebase(pe)
            except Exception as ex:
                stats["error"] += 1
                entries.append({"name": name, "guid": guid, "error": str(ex)})
                continue
            asfound, normed = _sha(pe), _sha(bytes(norm))
            entries.append({
                "name": name,
                "guid": guid,
                "size": len(pe),
                "sha256_asfound": asfound,
                "sha256_norm": normed,
                # "rebased" == the as-found bytes differ from the normal form, i.e. this module
                # was placed at a load address in flash and the profile had work to do.
                "rebased": asfound != normed,
                "declared_match": normed == want,
            })
    return entries, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--check", metavar="VECTORS")
    ap.add_argument("--sbom")
    ap.add_argument("--image", required=True)
    ap.add_argument("--edk2", required=True)
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if pefile is None:
        sys.exit("profile-vectors: pefile is required (pip install -r requirements.txt)")
    if not (a.emit or a.check):
        sys.exit("profile-vectors: pass --emit or --check")

    sbom = a.sbom
    if a.check and not sbom:
        with open(a.check) as f:
            sbom = json.load(f).get("sbom")
    if not sbom or not os.path.isfile(sbom):
        sys.exit("profile-vectors: need --sbom (or a 'sbom' path recorded in the vectors file)")

    entries, stats = collect(sbom, a.image, a.edk2)
    rebased = sum(1 for e in entries if e.get("rebased"))
    direct = sum(1 for e in entries if e.get("rebased") is False)
    mismatched = [e for e in entries if e.get("declared_match") is False]

    with open(a.image, "rb") as f:
        image_digest = "sha256:" + _sha(f.read())

    doc = {
        "profile": PROFILE_ID,
        "description": "Conformance vectors for the normalized UEFI PE32 module hash. A "
                       "conformant implementation, given the same as-found PE32 bytes, "
                       "reproduces every sha256_norm.",
        "image_digest": image_digest,
        "sbom": sbom,
        "tool": "producers/reconcile/profile-vectors.py",
        "summary": {
            "declared": stats["declared"],
            "vectors": len(entries),
            "direct": direct,
            "rebased_unrebased": rebased,
            "extract_fail": stats["extract_fail"],
            "no_pe32": stats["no_pe32"],
            "error": stats["error"],
        },
        "vectors": entries,
    }

    if a.emit:
        out = a.out or "-"
        txt = json.dumps(doc, indent=2, sort_keys=False) + "\n"
        if out == "-":
            sys.stdout.write(txt)
        else:
            with open(out, "w") as f:
                f.write(txt)
        sys.stderr.write(
            "profile-vectors: %d vectors (%d direct, %d un-rebased), %d declared-mismatch\n"
            % (len(entries), direct, rebased, len(mismatched)))
        return 1 if mismatched or stats["error"] else 0

    # --check : the regression. Any drift in the normal form fails loudly.
    with open(a.check) as f:
        want = json.load(f)
    wv = {e["guid"]: e for e in want.get("vectors", [])}
    gv = {e["guid"]: e for e in entries}
    drift, missing, extra = [], [], []
    for g, w in wv.items():
        if g not in gv:
            missing.append(w.get("name", g))
            continue
        if gv[g].get("sha256_norm") != w.get("sha256_norm"):
            drift.append((w.get("name", g), w.get("sha256_norm", "")[:16],
                          gv[g].get("sha256_norm", "")[:16]))
    for g in gv:
        if g not in wv:
            extra.append(gv[g].get("name", g))

    if want.get("image_digest") != image_digest:
        sys.stderr.write("profile-vectors: NOTE image digest differs from the vectors file\n"
                         "  vectors: %s\n  actual : %s\n"
                         % (want.get("image_digest"), image_digest))
    for n, a_, b_ in drift:
        print("DRIFT    %-28s vectors=%s… actual=%s…" % (n, a_, b_))
    for n in missing:
        print("MISSING  %s" % n)
    for n in extra:
        print("EXTRA    %s" % n)
    ok = not (drift or missing or extra)
    print("%s  %d vectors checked (%d direct, %d un-rebased)"
          % ("PASS " if ok else "FAIL ", len(gv), direct, rebased))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
