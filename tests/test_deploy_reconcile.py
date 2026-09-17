#!/usr/bin/env python3
"""Unit tests for the deploy-reconcile producer (Track A: CHIPSEC-fed deploy-time reconcile).

Two layers, mirroring the byte-integrity test's discipline:
  1) HERMETIC pure-logic tests on a SYNTHESIZED chipsec `uefi decode` tree — no pefile / no
     chipsec / no full OVMF needed. They cover the pieces that make this producer honest:
       * GUID-keying (two modules sharing a NAME but distinct FILE_GUIDs — the OVMF CpuMpPei
         collision — are kept apart);
       * the IMMEDIATE-parent FV-type derivation (the nested-FV trap the A3 prototype fixed:
         a module deep under an outer '.FV_FVIMAGE.dir' still takes its type from its own
         '<NN>_<guid>.FV_PEIM.dir', not the wrapper);
       * TE / non-PE sections are SKIPPED, never counted as verified;
       * BIDIRECTIONAL reconcile: a declared GUID with no extract -> MISSING; an extracted
         GUID absent from the SBOM -> UNEXPECTED; a byte change -> MISMATCH.
     These use DXE_DRIVER (direct-hash) modules so they run WITHOUT pefile.
  2) The 122/122 REFERENCE assertion against the real OVMF CHIPSEC extraction — run ONLY when
     pefile is installed AND the decode tree is reachable (env DEPLOY_RECONCILE_REF, or the A3
     scratch dir). Otherwise it SKIPS loudly (like the coSWID tests), never a silent green.

Run: python3 tests/test_deploy_reconcile.py     # hermetic tests always run
     DEPLOY_RECONCILE_REF=<decode-dir> <python-with-pefile> tests/test_deploy_reconcile.py
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
_spec = importlib.util.spec_from_file_location(
    "deploy_reconcile", os.path.join(ROOT, "producers", "chipsec", "deploy-reconcile.py"))
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)

ok = True
skipped = 0


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


# ---- helpers: synthesize a chipsec `uefi decode` tree + a matching CycloneDX SBOM ----
def _dash(guid32):
    g = guid32
    return "%s-%s-%s-%s-%s" % (g[0:8], g[8:12], g[12:16], g[16:20], g[20:32])


def _write_module(base, fv_type, guid32, fname, payload, idx=0, nested=False):
    """Write a module file into a '<idx>_<guid>.FV_TYPE.dir' (optionally under an outer
    '.FV_FVIMAGE.dir' wrapper, to exercise the immediate-parent derivation)."""
    parent = "%02d_%s.%s.dir" % (idx, _dash(guid32), fv_type)
    if nested:
        d = os.path.join(base, "FV", "00_%s.FV_FVIMAGE.dir" % _dash("a" * 32),
                         "01_S_FV_IMAGE.dir", parent)
    else:
        d = os.path.join(base, "FV", parent)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fname), "wb") as f:
        f.write(payload)


def _sbom(entries):
    """entries: {guid32: (name, sha256hex)} -> a minimal CycloneDX file path."""
    comps = [{"type": "firmware", "name": n, "bom-ref": _dash(g),
              "hashes": [{"alg": "SHA-256", "content": h}]} for g, (n, h) in entries.items()]
    fd, p = tempfile.mkstemp(suffix=".cdx.json")
    with os.fdopen(fd, "w") as f:
        json.dump({"components": comps}, f)
    return p


PE = b"MZ" + b"\x90" * 62  # a 'direct' (DXE) module body — is_pe True, hashed as-is (no pefile)
TE = b"VZ" + b"\x00" * 62  # a TE image — is_pe False -> SKIP
GUID_A = "aa" * 16
GUID_B = "bb" * 16
GUID_TE = "cc" * 16
GUID_X = "dd" * 16          # extracted but NOT in the SBOM -> UNEXPECTED
GUID_MISS = "ee" * 16       # in the SBOM but never extracted -> MISSING
GUID_DUP = "ff" * 16        # second module NAMED like A but distinct GUID (collision guard)


def h(b):
    return hashlib.sha256(b).hexdigest()


# ---- 1) collect_modules: GUID/type derivation, nested-FV trap, TE detection ----
td = tempfile.mkdtemp()
_write_module(td, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
_write_module(td, "FV_PEIM", GUID_B, "CpuMpPei.efi", PE, idx=2, nested=True)  # deep under FV_FVIMAGE
_write_module(td, "FV_PEIM", GUID_DUP, "CpuMpPei.efi", PE, idx=3, nested=True)  # SAME name, other GUID
_write_module(td, "FV_PEIM", GUID_TE, "ModTE.te", TE, idx=4)
mods = dr.collect_modules(td)
by_guid = {m["guid"]: m for m in mods}
check("collect_modules: finds all 4 module files", len(mods) == 4)
check("collect_modules: FV_DRIVER -> DXE_DRIVER (direct)", by_guid[GUID_A]["filetype"] == "DXE_DRIVER")
check("collect_modules: NESTED module takes type from its IMMEDIATE FV_PEIM parent, not the outer FV_FVIMAGE wrapper (nested-FV trap)",
      by_guid[GUID_B]["filetype"] == "PEIM")
check("collect_modules: two CpuMpPei with distinct GUIDs are kept apart (GUID-keyed, names collide)",
      GUID_B in by_guid and GUID_DUP in by_guid and by_guid[GUID_B]["name"] == by_guid[GUID_DUP]["name"] == "CpuMpPei")
check("collect_modules: a TE ('VZ') section is is_pe=False -> will be SKIPPED", by_guid[GUID_TE]["is_pe"] is False)

# ---- 2) reconcile: matched / mismatch / missing / unexpected / skip + clean flag ----
# A dedicated DXE_DRIVER (direct-hash) tree so the whole reconcile runs WITHOUT pefile:
#   GUID_A matches; GUID_MM declared with the WRONG hash -> MISMATCH; GUID_TE is a TE section
#   -> SKIP; GUID_MISS declared but never extracted -> MISSING; GUID_X extracted but NOT declared
#   -> UNEXPECTED.
GUID_MM = "12" * 16
td2 = tempfile.mkdtemp()
_write_module(td2, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
_write_module(td2, "FV_DRIVER", GUID_MM, "ModMM.efi", PE, idx=2)   # bytes = PE, but declared hash differs
_write_module(td2, "FV_DRIVER", GUID_TE, "ModTE.te", TE, idx=3)    # TE -> skip
_write_module(td2, "FV_DRIVER", GUID_X, "ModX.efi", PE, idx=4)     # not declared -> unexpected
mods2 = dr.collect_modules(td2)
declared = dr.load_sbom_hashes(_sbom({
    GUID_A: ("ModA", h(PE)),
    GUID_MM: ("ModMM", h(PE + b"\x01")),  # declared != observed -> mismatch
    GUID_TE: ("ModTE", h(b"whatever")),   # extracted only as TE -> skip
    GUID_MISS: ("Gone", h(PE)),           # never extracted -> missing
}))
v = dr.reconcile(declared, mods2)
check("reconcile: GUID_A matches (direct hash, no pefile needed)",
      v["matched"] == 1 and v["matched_modules"][0]["guid"] == GUID_A)
check("reconcile: wrong-hash module -> 1 MISMATCH", len(v["mismatched"]) == 1 and v["mismatched"][0]["guid"] == GUID_MM)
check("reconcile: TE section -> 1 SKIP (never counted as matched)", len(v["skipped"]) == 1 and v["skipped"][0]["guid"] == GUID_TE)
check("reconcile: declared-but-unextracted -> 1 MISSING (tamper/dropped)", len(v["missing"]) == 1 and v["missing"][0]["guid"] == GUID_MISS)
check("reconcile: extracted-but-undeclared -> 1 UNEXPECTED (implant)", len(v["unexpected"]) == 1 and v["unexpected"][0]["guid"] == GUID_X)
check("reconcile: reconciled == matched + mismatched (the comparable set)", v["reconciled"] == 2)
check("reconcile: NOT clean while any mismatch/missing/unexpected stands", v["clean"] is False)
check("reconcile: predicateType is the stable-namespace deploy-reconcile v1",
      v["predicateType"] == "https://firmware-sbom-supplychain/deploy-reconcile/v1")
check("reconcile: evidenceGrade is 'verified' (reconciled from real extracted bytes)", v["evidenceGrade"] == "verified")

# an all-matching run is clean
v2 = dr.reconcile(dr.load_sbom_hashes(_sbom({GUID_A: ("ModA", h(PE))})),
                  [m for m in mods2 if m["guid"] == GUID_A])
check("reconcile: an all-matching extract (1/1) is clean -> exit-0 shape", v2["clean"] is True and v2["matched"] == 1)

# ---- 2b) SECURITY — coverage floor: a declared module that comes back UNVERIFIABLE (a same-GUID
# PE->TE swap, or any non-PE/error) is DRIFT, never a benign skip. `clean` requires matched ==
# declared, so a partial pass (1-of-N, or one module swapped to TE) is NOT clean. (Repro of the
# skip/coverage bypass three reviewers flagged: pre-fix `clean` needed only matched>0.) ----
# (i) same-GUID PE->TE swap: GUID_A stays a real PE (matches); GUID_B is DECLARED as a PE but the
#     device now carries a TE under the SAME GUID -> B is unverifiable, the run is NOT clean.
td_swap = tempfile.mkdtemp()
_write_module(td_swap, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
_write_module(td_swap, "FV_PEIM", GUID_B, "ModB.te", TE, idx=2)  # B swapped PE->TE (same GUID)
v_swap = dr.reconcile(dr.load_sbom_hashes(_sbom({GUID_A: ("ModA", h(PE)), GUID_B: ("ModB", h(PE))})),
                      dr.collect_modules(td_swap))
check("SECURITY: a same-GUID PE->TE swap is UNVERIFIABLE drift, NOT clean (matched=1 != declared=2)",
      v_swap["clean"] is False and v_swap["matched"] == 1 and v_swap["declared"] == 2)
check("SECURITY: the swapped module is surfaced in `skipped` (so the gate can name + exemption-check it), NOT silently missing",
      len(v_swap["missing"]) == 0 and any(s["guid"] == GUID_B for s in v_swap["skipped"]))
# (ii) 1-of-N: only 1 of 4 declared modules matched (rest TE-skipped) -> NOT clean (coverage floor).
td_1ofn = tempfile.mkdtemp()
_write_module(td_1ofn, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
for _i, _g in enumerate(("11" * 16, "22" * 16, "33" * 16)):
    _write_module(td_1ofn, "FV_DRIVER", _g, "M%d.te" % _i, TE, idx=_i + 2)
v_1ofn = dr.reconcile(dr.load_sbom_hashes(_sbom({
    GUID_A: ("ModA", h(PE)), "11" * 16: ("M0", h(b"x")),
    "22" * 16: ("M1", h(b"y")), "33" * 16: ("M2", h(b"z"))})), dr.collect_modules(td_1ofn))
check("SECURITY: matched=1 / rest-skipped of 4 declared is NOT clean (coverage floor, not matched>0)",
      v_1ofn["clean"] is False and v_1ofn["matched"] == 1 and v_1ofn["declared"] == 4)

# ---- 2c) COLLECTION (finding #3) — a module nested under a compression / GUID-defined section (no
# '<NN>_<guid>.FV_TYPE.dir' immediate parent, as on real Dell/Lenovo Insyde firmware) is COLLECTED by
# MAGIC wherever it nests, not silently dropped into a false MISSING. Two paths, both asserted:
#   (a) the AUTHORITATIVE path: a synthesized CHIPSEC `<img>.UEFI.json` whose PE32 section sits deep
#       under an S_GUID_DEFINED/S_FV_IMAGE nest; FILE_GUID comes from the nearest ancestor EFI_FILE.
#   (b) the magic-based dir FALLBACK: the '.efi' lives directly under an 'NN_S_COMPRESSION.dir'. ----
GUID_NEST = "9b" * 16
# (a) authoritative UEFI.json walk
uj_root = tempfile.mkdtemp()
_pe_path = os.path.join(uj_root, "OVMF.fd.dir", "FV", "00_fv.dir", "sec.dir", "ModNest.efi")
os.makedirs(os.path.dirname(_pe_path), exist_ok=True)
with open(_pe_path, "wb") as _f:
    _f.write(PE)
_uefi_json = [{"class": "EFI_FV", "Guid": _dash("f" * 32), "children": [
    {"class": "EFI_FILE", "Guid": _dash(GUID_NEST), "Type": "7", "children": [   # Type 7 = DXE_DRIVER
        {"class": "EFI_SECTION", "Name": "S_GUID_DEFINED", "Type": "2", "children": [
            {"class": "EFI_SECTION", "Name": "S_PE32", "Type": "16",
             "file_path": "OVMF.fd.dir/FV/00_fv.dir/sec.dir/ModNest.efi"}]}]}]}]
with open(os.path.join(uj_root, "OVMF.fd.UEFI.json"), "w") as _f:
    json.dump(_uefi_json, _f)
mods_nest = dr.collect_modules(os.path.join(uj_root, "OVMF.fd.dir"))
check("collect_modules(#3): a PE32 nested under S_GUID_DEFINED is COLLECTED via the authoritative UEFI.json (not MISSING)",
      len(mods_nest) == 1 and mods_nest[0]["guid"] == GUID_NEST)
check("collect_modules(#3): its FILE_GUID + filetype come from the nearest ancestor EFI_FILE (Type 7 -> DXE_DRIVER)",
      mods_nest[0]["filetype"] == "DXE_DRIVER")
v_nest = dr.reconcile(dr.load_sbom_hashes(_sbom({GUID_NEST: ("ModNest", h(PE))})), mods_nest)
check("collect_modules(#3): the nested module reconciles clean (1/1) instead of a false MISSING/DENY",
      v_nest["clean"] is True and len(v_nest["missing"]) == 0)
# CHIPSEC writes file_path relative to the directory decode was RUN from, e.g. "../../x/OVMF.fd.dir/..."
# when started elsewhere. Such a path does not resolve against the image's directory; it must be
# re-anchored on the tree's own name rather than yield an empty module list.
_uefi_json[0]["children"][0]["children"][0]["children"][0]["file_path"] = \
    "../../elsewhere/OVMF.fd.dir/FV/00_fv.dir/sec.dir/ModNest.efi"
with open(os.path.join(uj_root, "OVMF.fd.UEFI.json"), "w") as _f:
    json.dump(_uefi_json, _f)
mods_moved = dr.collect_modules(os.path.join(uj_root, "OVMF.fd.dir"))
check("collect_modules: a UEFI.json written from another working directory still resolves its modules",
      len(mods_moved) == 1 and mods_moved[0]["guid"] == GUID_NEST)
# (b) magic-based dir fallback (no UEFI.json): '.efi' directly under an 'NN_S_COMPRESSION.dir'
fb_root = tempfile.mkdtemp()
_comp = os.path.join(fb_root, "FV", "00_%s.dir" % _dash("aa" * 16), "01_S_COMPRESSION.dir")
os.makedirs(_comp)
with open(os.path.join(_comp, "ModC.efi"), "wb") as _f:
    _f.write(PE)
mods_fb = dr.collect_modules(fb_root)
check("collect_modules(#3): the magic-based dir FALLBACK collects a module under an 'NN_S_COMPRESSION.dir' (no FV_TYPE.dir parent)",
      len(mods_fb) == 1 and mods_fb[0]["is_pe"] is True)

# ---- 2d) TYPE FROM MAGIC (finding #4) — CHIPSEC names a TE-with-UI module '<name>.efi' (VZ magic).
# The efilist `type` + is_pe must come from the MAGIC, not the '.efi' extension. ----
td_te = tempfile.mkdtemp()
_write_module(td_te, "FV_PEIM", GUID_TE, "TeNamedEfi.efi", TE, idx=1)  # TE bytes, '.efi' name
mods_te = dr.collect_modules(td_te)
check("collect_modules(#4): a TE-magic ('VZ') file NAMED '.efi' is is_pe=False (magic, not extension)",
      mods_te[0]["is_pe"] is False)
check("build_efilist(#4): a TE-magic '.efi' is typed 'S_TE' (from magic), not 'S_PE32' (from extension)",
      list(dr.build_efilist(mods_te).values())[0]["type"] == "S_TE")

# ---- 3) REFERENCE: the real OVMF CHIPSEC extraction reconciles 122/122 (needs pefile + tree) ----
# The decode tree is supplied ONLY via env DEPLOY_RECONCILE_REF (a `chipsec_util uefi decode
# <OVMF>.fd.dir`) — no committed session-specific scratch path; absent -> SKIP LOUDLY below.
ref = os.environ.get("DEPLOY_RECONCILE_REF")
ref_sbom = os.path.join(ROOT, "inputs", "sbom.cdx.json")
if dr.ffs.pefile is None:
    skipped += 1
    print("SKIP  122/122 OVMF reference reconcile (pefile not installed — the XIP un-rebase path "
          "cannot run; install pefile / run with the pefile venv). Hermetic tests above still ran.")
elif not (ref and os.path.isdir(ref) and os.path.isfile(ref_sbom)):
    skipped += 1
    print("SKIP  122/122 OVMF reference reconcile (decode tree not reachable — set DEPLOY_RECONCILE_REF "
          "to a `chipsec_util uefi decode <OVMF>.fd.dir`). Hermetic tests above still ran.")
else:
    efilist = os.path.join(os.path.dirname(ref), "efilist.json")
    rmods = dr.collect_modules(ref, efilist if os.path.isfile(efilist) else None)
    rv = dr.reconcile(dr.load_sbom_hashes(ref_sbom), rmods)
    check("reference: CHIPSEC-extracted OVMF reconciles 122/122 against the signed SBOM (A3 parity)",
          rv["matched"] == 122 and rv["reconciled"] == 122)
    check("reference: no mismatch / missing / unexpected on the clean reference image",
          not rv["mismatched"] and not rv["missing"] and not rv["unexpected"] and rv["clean"] is True)
    check("reference: 11 XIP modules took the un-rebase path, 111 the direct path (A3 split)",
          rv["verified_unrebase"] == 11 and rv["verified_direct"] == 111)
    check("reference: the verdict's declared count == the 122 hashable SBOM modules (coverage denominator)",
          rv["declared"] == 122)
    # XIP un-rebase is a REAL transform: an XIP module's normalized (rebase-0) hash must DIFFER from
    # its as-found (in-flash, rebased) hash — else the un-rebase did nothing and we'd be comparing the
    # wrong bytes. (Direct modules have norm == as-found; TE has norm null — both already tested.)
    ela = dr.build_efilist(rmods, annotated=True)
    xip_norm_differs = any(
        e["sha256_norm"] is not None and e["sha256_norm"] != k
        for k, e in ela.items()
        for md in [next((m for m in rmods if m["asfound"] == k), None)]
        if md and md["filetype"] in dr.XIP_TYPES)
    check("reference: an XIP module's sha256_norm (rebase-0) DIFFERS from its as-found hash (un-rebase is a real transform, not a no-op)",
          xip_norm_differs)

print("----")
if skipped:
    print("⚠  %d REFERENCE TEST GROUP(S) SKIPPED — the 122/122 OVMF reconcile did NOT run here "
          "(pefile and/or the CHIPSEC decode tree unavailable). The hermetic logic tests ran." % skipped)
print(("ALL PASS%s" % (" (with %d SKIPPED — see warning)" % skipped if skipped else "")) if ok else "FAILURES")
sys.exit(0 if ok else 1)
