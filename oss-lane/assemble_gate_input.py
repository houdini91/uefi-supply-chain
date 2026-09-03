#!/usr/bin/env python3
"""Build the OPA gate input from VERIFIED evidence — the single source of truth.

Ported from assemble-gate-input.sh (kept as a thin shim). Same env-var contract,
same output, so the local runner and the CI workflow can never drift. Every field
is derived from evidence, never asserted:

  - attestation.file_subject (H) + attestation.firmware_subject (D) + reconcile predicate:
    decoded from the VERIFIED multi-subject DSSE bundle — the "firmware-image" subject is the
    firmware anchor D (evidence-graph binding); the bound SBOM-file subject is H (tamper-after-
    signing binding)
  - sbom.hash: the SBOM file's actual SHA-256 H (the policy binds it to attestation.file_subject)
  - provenance.builder_id: the signer identity (cert SAN URI) extracted from the bundle
  - cve.findings: the grype scan
  - firmware.*: the firmware-image anchor legs (build SBOM digest / reconcile re-hash / deployed)

Env in:  SBOM BUNDLE SIG(true|false) OUT  [BUILDER_ID SOURCE_REPO GRYPE_JSON
         CHIPSEC_JSON BUILD_TOOLS_JSON BUILD_TOOLS_SIG SLSA_VERIFIED PROVENANCE_SUBJECT
         FW_IMAGE  DEV_ASSUME_{IDENTITY,SLSA,BUILDTOOLS,CHAIN,FWIMAGE}]
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys


def env(name, default=""):
    return os.environ.get(name, default)


def require(name):
    v = os.environ.get(name)
    if not v:
        sys.exit("assemble_gate_input: %s is required" % name)
    return v


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path):
    with open(path) as f:
        return json.load(f)


def dflt(d, key, default):
    """jq `.key // default` — absent OR null falls through to default."""
    v = d.get(key)
    return default if v is None else v


def decode_dsse(bundle_path):
    """Decode the in-toto Statement from a legacy cosign bundle (.base64Signature).
    Fails closed with a clear message on an unexpected format."""
    try:
        bundle = load_json(bundle_path)
        env_json = json.loads(base64.b64decode(bundle["base64Signature"]))
        stmt = json.loads(base64.b64decode(env_json["payload"]))
        if not isinstance(stmt, dict):
            raise ValueError("payload is not an object")
        return stmt, bundle
    except Exception:
        sys.exit("error: could not decode a DSSE in-toto payload from %s — unexpected cosign "
                 "bundle format (expected legacy .base64Signature). Pin cosign or refresh the bundle."
                 % bundle_path)


def signer_san(bundle):
    """Extract the signer identity (cert SAN URI) from the bundle cert — do NOT
    trust an env string. Shells out to openssl for the one field (no new dep)."""
    cert = bundle.get("cert") or ""
    if not cert:
        return ""
    if "BEGIN" not in cert or "CERTIFICATE" not in cert:
        try:
            cert = base64.b64decode(cert).decode("utf-8", "replace")
        except Exception:
            return ""
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"],
                             input=cert, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True).stdout
    except Exception:
        return ""
    for tok in out.replace(",", " ").split():
        if tok.startswith("URI:"):
            return tok[len("URI:"):]
    return ""


def build_tools_derive(comps, sig_verified):
    """Pure: components list -> build-tools posture. A component is unpinned if it
    has neither a concrete version (absent or 'latest') nor a hash."""
    unpinned = [c.get("name") for c in comps
                if ((not c.get("version")) or c.get("version") == "latest") and not c.get("hashes")]
    return {"present": len(comps) > 0, "unpinned": unpinned,
            "all_pinned": len(unpinned) == 0, "signature_verified": sig_verified}


def build_tools(path, sig_verified):
    if path and os.path.isfile(path):
        return build_tools_derive(load_json(path).get("components", []) or [], sig_verified)
    # missing file: explicitly not-present and not-pinned (distinct from an empty list)
    return {"present": False, "unpinned": [], "all_pinned": False, "signature_verified": sig_verified}


# DXE-class module types the image-protection policy governs — NX-compat is required
# for these (mirrors producers/reconcile/binary-hardening.py DXE_CLASS). Used as the
# SBOM-derived coverage denominator for binary-hardening, so a cherry-picked verdict
# cannot fake its own coverage.
DXE_CLASS = {"DXE_DRIVER", "DXE_RUNTIME_DRIVER", "DXE_SAL_DRIVER", "UEFI_DRIVER",
             "UEFI_APPLICATION", "DXE_CORE", "SMM_CORE", "DXE_SMM_DRIVER", "MM_STANDALONE"}


def _module_type(c):
    for p in (c.get("properties") or []):
        if p.get("name") == "edk2:moduleType":
            return p.get("value")
    return None


def _hash_profile(c):
    """The canonicalization profile a component's declared hash was computed under
    (edk2:hashCanonicalForm), or None when the SBOM does not say. See
    docs/normalized-module-hash-profile.md — the generator emits 'genfw-rebase-0' for a
    normalized base-0 digest and 'raw-pe32' for the degraded, un-normalized fallback."""
    for p in (c.get("properties") or []):
        if p.get("name") == "edk2:hashCanonicalForm":
            return p.get("value")
    return None


def integrity(sbom):
    mods = [c for c in (sbom.get("components") or []) if isinstance(c, dict) and c.get("type") != "library"]
    def hashed(c):
        h = c.get("hashes")
        return isinstance(h, list) and len(h) > 0
    hashed_mods = [c for c in mods if hashed(c)]
    # The distinct canonicalization profiles the SBOM's declared hashes were computed under.
    # A verifier can only compare a declared hash to a re-derived one when it IMPLEMENTS that
    # profile: 'genfw-rebase-0' and 'raw-pe32' are not comparable to each other, and an
    # unrecognized profile is not comparable to anything. The gate refuses rather than
    # silently comparing digests whose preimages were built differently.
    profiles = sorted({p for p in (_hash_profile(c) for c in hashed_mods) if p})
    return {"hashable_total": len(mods),
            "hashed": len(hashed_mods),
            "unhashed": [c.get("name") for c in mods if not hashed(c)],
            "hash_profiles": profiles,
            "hashed_without_profile": sum(1 for c in hashed_mods if _hash_profile(c) is None),
            "dxe_class_total": sum(1 for c in mods if _module_type(c) in DXE_CLASS)}


def generation(sbom):
    """CISA 2026 Minimum Elements — Generation Tool + Generation Context, surfaced
    from the SBOM the same way integrity()/thirdparty() surface their facts. HONESTY:
    this reports what the SBOM DECLARES (a tool with name+version; a lifecycle phase),
    not that the declared tool produced these bytes — the gate rule reflects that ceiling.
      - tool_present: metadata.tools carries at least one entry with a name AND version.
        CycloneDX 1.4 tools is a list; 1.5+ is an object {components:[...],services:[...]}.
      - context_present: metadata.lifecycles[] carries at least one entry with a phase."""
    md = sbom.get("metadata", {}) or {}
    tools = md.get("tools")
    if isinstance(tools, dict):
        tool_list = (tools.get("components") or []) + (tools.get("services") or [])
    elif isinstance(tools, list):
        tool_list = tools
    else:
        tool_list = []
    tool_present = any(t.get("name") and t.get("version") for t in tool_list if isinstance(t, dict))
    lifecycles = md.get("lifecycles") or []
    context_present = any(lc.get("phase") for lc in lifecycles if isinstance(lc, dict))
    return {"tool_present": tool_present, "context_present": context_present}


_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _source_revision(sbom):
    """The build-wide source revision (git commit) the image was built from — the
    -Y SBOM generator records it on the document-root component as edk2:sourceRevision
    ('git:<sha>'). This is the SLSA-provenance-style coarse source anchor, surfaced into
    the gate input's provenance so the evidence records WHICH source produced the image,
    complementing the per-module edk2:sourceHash. Empty (not fabricated) if absent."""
    mc = (sbom.get("metadata", {}) or {}).get("component", {}) or {}
    for p in (mc.get("properties") or []):
        if p.get("name") == "edk2:sourceRevision" and p.get("value"):
            return p.get("value")
    return ""


def _source_hash_present(c):
    """OSF M-srchash: a real source-file hash rides in coSWID colloquial-version. In the
    CycloneDX manifest that carrier is an explicit edk2:sourceHash property — the -Y SBOM
    generator now emits one per module (a SHA-256 over the module's INF [Sources] set). A
    module with no readable source honestly carries none."""
    for p in (c.get("properties") or []):
        if p.get("name") == "edk2:sourceHash" and p.get("value"):
            return True
    return False


def osf_conformance(sbom):
    """OSF Firmware Embedded SBOM structural conformance, surfaced from the CycloneDX
    manifest the gate already holds — a manifest-level proxy for the embedded coSWID
    shape, NOT a parse of the coSWID extracted from the shipped PE (that deeper check
    stays roadmapped; see CONFORMANCE.md). Two MUSTs are separable here:
      - GUID identity (MET): every firmware module's tag-id is its FILE_GUID. In the
        CDX manifest the module's bom-ref carries the FILE_GUID, so guid_tag_id counts
        modules whose bom-ref is GUID-form.
      - Source-file hash / M-srchash (UNMET by default): source_hash_present counts
        modules carrying an edk2:sourceHash. 0 unless --source-hashes was supplied."""
    mods = [c for c in (sbom.get("components") or []) if isinstance(c, dict) and c.get("type") != "library"]
    guid_tag_id = sum(1 for c in mods if _GUID_RE.match(str(c.get("bom-ref", ""))))
    return {"evaluated": True,
            "modules_total": len(mods),
            "guid_tag_id": guid_tag_id,
            "source_hash_present": sum(1 for c in mods if _source_hash_present(c))}


_PURL_RE = re.compile(r"^pkg:[a-zA-Z][a-zA-Z0-9.+-]*/[^@?#]+")
# SPDX short-form license-id CHARSET/shape (letters/digits/.+-). HONESTY: this is a well-formedness
# check, NOT SPDX-license-list membership — a syntactically-valid-but-fictitious id like
# "NOT-A-LICENSE" or "totally-made-up" PASSES the shape (it is charset-legal). What it DOES catch:
# empty ids, and ids containing spaces/underscores/parens/slashes/other illegal chars. Full
# SPDX-list membership (which would reject a fake-but-shaped id) is a documented refinement.
_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def data_quality(sbom):
    """NTIA 'SBOM data quality' — the identifiers that ARE present must be well-formed, not merely
    non-empty. thirdparty()/cisa-license-id check presence; this checks well-formedness:
      - purl_invalid:    declared component.purl strings that don't parse as a package URL
      - license_invalid: declared component.licenses[] entries that are neither a charset-legal
        SPDX-shaped `license.id`/`expression` nor a non-empty `name` (so an EMPTY license object,
        or an id with illegal characters, is flagged).
    HONESTY: a fictitious-but-charset-legal id (e.g. "NOT-A-LICENSE") is NOT flagged — that needs
    full SPDX-license-list membership (a documented refinement). A component with no purl/license
    is not counted here (presence is a separate control)."""
    comps = sbom.get("components") or []
    purl_checked = purl_invalid = 0
    bad_purls, bad_lics = [], []
    lic_checked = lic_invalid = 0
    for c in comps:
        if not isinstance(c, dict):
            continue
        purl = c.get("purl")
        if purl:
            purl_checked += 1
            if not _PURL_RE.match(str(purl)):
                purl_invalid += 1
                if len(bad_purls) < 10:
                    bad_purls.append("%s: %s" % (c.get("name"), purl))
        for lic in (c.get("licenses") or []):
            if not isinstance(lic, dict):
                continue
            lic_checked += 1
            lid = (lic.get("license") or lic).get("id") if isinstance(lic.get("license"), dict) else lic.get("id")
            expr = lic.get("expression")
            name = (lic.get("license") or {}).get("name") if isinstance(lic.get("license"), dict) else lic.get("name")
            ok = (lid and _SPDX_ID_RE.match(str(lid))) or (expr and str(expr).strip()) or (name and str(name).strip())
            if not ok:
                lic_invalid += 1
                if len(bad_lics) < 10:
                    bad_lics.append(c.get("name"))
    return {"purl_checked": purl_checked, "purl_invalid": purl_invalid, "bad_purls": bad_purls,
            "license_checked": lic_checked, "license_invalid": lic_invalid, "bad_licenses": bad_lics}


def dependency_facts(sbom):
    """CISA 2026 / NTIA REQUIRED 'Dependency Relationship' element. The -Y SBOM generator emits a
    CycloneDX dependencies[] graph (module -> library dependsOn edges), but the gate never read it.
    Surface structural facts so a gated report can assert the graph is present, non-trivial, and
    well-formed (no dangling dependsOn ref pointing at a non-existent component). This is presence +
    referential integrity of the declared graph — NOT a claim of dependency COMPLETENESS (that needs
    a compositions[].aggregate declaration from the generator; tracked separately)."""
    deps = sbom.get("dependencies") or []
    refs = {c.get("bom-ref") for c in (sbom.get("components") or []) if isinstance(c, dict) and c.get("bom-ref")}
    md_ref = ((sbom.get("metadata", {}) or {}).get("component", {}) or {}).get("bom-ref")
    if md_ref:
        refs.add(md_ref)
    edges = 0
    dangling = set()
    for d in deps:
        if not isinstance(d, dict):
            continue
        if d.get("ref") and d["ref"] not in refs:
            dangling.add(d["ref"])
        for t in (d.get("dependsOn") or []):
            edges += 1
            if t not in refs:
                dangling.add(t)
    has_composition = bool(sbom.get("compositions"))
    return {"present": len(deps) > 0, "edges": edges,
            "dangling_count": len(dangling), "dangling": sorted(dangling)[:10],
            "has_composition": has_composition}


_URN_UUID_RE = re.compile(
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def sbom_identity(sbom):
    """CISA 2026 'SBOM Version' unique-id element: a serialNumber (urn:uuid) + integer version, and
    a completeness/known-unknowns declaration (compositions[].aggregate). Both are surfaced for
    gating; the -Y SBOM generator now emits both."""
    serial = str(sbom.get("serialNumber") or "")
    comps = sbom.get("compositions") or []
    aggregate = next((c.get("aggregate") for c in comps if isinstance(c, dict) and c.get("aggregate")), "")
    return {"serial_present": bool(_URN_UUID_RE.match(serial)),
            "completeness_declared": bool(aggregate), "aggregate": aggregate}


def component_supplier(sbom):
    """CISA 2026 'Component Producer' (per-component supplier), applied to every enumerated component
    — distinct from the document-level supplier. Every component must carry a non-empty supplier.name
    (or author.name as a fallback)."""
    comps = [c for c in (sbom.get("components") or []) if isinstance(c, dict)]
    def has_supplier(c):
        s = c.get("supplier") or {}
        a = c.get("author")
        return bool((isinstance(s, dict) and s.get("name")) or a)
    missing = [c.get("name") for c in comps if not has_supplier(c)]
    return {"total": len(comps), "missing": missing[:10], "missing_count": len(missing)}


def baseline_metadata(sbom):
    """CISA 2026 / NTIA baseline REQUIRED elements that live in metadata but were never gated:
      - author_present:    metadata.authors[] carries a name (the SBOM Author element)
      - timestamp_present: metadata.timestamp is a non-empty ISO-8601 UTC string (the Timestamp element)
      - supplier_present:  metadata.supplier.name is set (the Software Producer/Supplier element)
    These are surfaced the same way integrity()/generation() surface theirs, so a new gated report
    can assert the baseline. Presence-not-validity (a data-quality control checks the values)."""
    md = sbom.get("metadata", {}) or {}
    authors = md.get("authors") or []
    ts = md.get("timestamp") or ""
    supplier = md.get("supplier") or {}
    author_present = any(a.get("name") for a in authors if isinstance(a, dict))
    timestamp_present = bool(re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", str(ts)))
    supplier_present = bool(isinstance(supplier, dict) and supplier.get("name"))
    return {"author_present": author_present,
            "timestamp_present": timestamp_present,
            "supplier_present": supplier_present}


def thirdparty(sbom):
    def vendored(c):
        return any(p.get("name") == "edk2:vendored" and p.get("value") == "true"
                   for p in (c.get("properties") or []))
    tp = [c for c in (sbom.get("components") or []) if isinstance(c, dict) and vendored(c)]
    def missing(c):
        return (not c.get("purl")) or c.get("purl") == "" \
            or (not c.get("licenses")) or len(c.get("licenses")) == 0
    return {"total": len(tp), "missing": [c.get("name") for c in tp if missing(c)]}


def cve_findings(path):
    if not (path and os.path.isfile(path) and os.path.getsize(path) > 0):
        return []
    try:
        doc = load_json(path)
    except ValueError:
        return []
    seen, out = set(), []
    for m in doc.get("matches", []) or []:
        v = {"id": m.get("vulnerability", {}).get("id"),
             "component": m.get("artifact", {}).get("name"),
             "severity": (m.get("vulnerability", {}).get("severity") or "").upper()}
        key = json.dumps(v, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return sorted(out, key=lambda x: json.dumps(x, sort_keys=True))


def cve_fact(path):
    """CVE evidence with a NON-VACUITY 'scanned' flag (parity with byte_integrity.ran).
    scanned=False when no grype scan was supplied — distinct from 'scanned, found nothing'.
    Without this flag an empty findings list read as 'no critical CVEs / no KEV / all VEX-
    adjudicated' on a firmware that was never scanned (a foreign SBOM, or a missing scan) —
    absence-of-evidence reported as evidence-of-absence. The gate now treats not-scanned as
    NOT-satisfied (fail-closed), never a silent pass."""
    scanned = bool(path and os.path.isfile(path) and os.path.getsize(path) > 0)
    return {"scanned": scanned, "findings": cve_findings(path)}


def signed_predicate(bundle_path, anchor_d):
    """Return a signed evidence bundle's `.predicate` ONLY IF its subject #1
    (name=="firmware-image") digest.sha256 == the firmware anchor D. Returns None
    — FAIL CLOSED, treated by the callers as not-ran — when the firmware-image subject
    is absent or != D, so a bundle re-pointed at another image (subject D != the image),
    or one carrying no firmware anchor, cannot feed the gate. decode_dsse() itself
    fail-closes (sys.exit) on an undecodable bundle, so a tampered/garbled bundle aborts.

    The signature + keyless identity of this bundle are verified upstream (cosign
    verify-blob-attestation in run.sh / the CI VERIFY loop) — the same division of
    labor as the reconcile bundle: crypto is checked by cosign, the D-binding here."""
    stmt, _bundle = decode_dsse(bundle_path)
    anchor = (anchor_d or "").replace("sha256:", "")
    fw = ""
    for s in (stmt.get("subject", []) or []):
        if s.get("name") == "firmware-image":
            fw = dflt(s.get("digest", {}) or {}, "sha256", "")
            break
    if not anchor or not fw or fw != anchor:
        return None
    pred = stmt.get("predicate")
    return pred if isinstance(pred, dict) else None


def _byte_integrity_derive(d):
    # NAMES of modules that could not be byte-verified (skipped OR errored) — surfaced so
    # the gate can name exactly what did not pass and check each against a reviewed
    # exemption list (data.byte_integrity_exempt); an unexpected one denies.
    unverifiable = [x.get("name") for x in (d.get("skipped", []) or [])] \
        + [x.get("name") for x in (d.get("errored", []) or [])]
    unverifiable = sorted(n for n in unverifiable if n)
    modified_names = sorted(n for n in (m.get("name") for m in (d.get("modified", []) or [])) if n)
    return {"ran": True, "checked": d.get("checked", 0),
            "verified": d.get("byte_verified", 0),
            "modified_count": len(d.get("modified", []) or []),
            "modified": modified_names,  # NAMES of MODIFIED modules, so the gate can name what tampered
            "unverifiable": unverifiable,
            "skipped_count": len(unverifiable)}


def byte_integrity_fact(path, bundle_path=None, anchor_d=""):
    """R4: fold the byte-integrity producer's verdict into a gate fact. ran=False
    when no image+edk2 was available to the producer (distinct from a clean run).
    Surfaces skipped_count so the gate can refuse a vacuous pass (all modules
    skipped / nothing verified) — a skip is NOT a pass.

    When BYTE_INTEGRITY_BUNDLE is set, the verdict MUST come from the SIGNED,
    firmware-D-anchored bundle (subject #1 firmware-image == D): the loose file is
    IGNORED, closing the forge where an attacker with inputs/ write access but no
    signing key rewrites byte-integrity.json to modified:0. A bundle whose firmware
    subject != D fails closed to not-ran (absent)."""
    absent = {"ran": False, "checked": 0, "verified": 0, "modified_count": 0,
              "skipped_count": 0, "unverifiable": []}
    if bundle_path:
        d = signed_predicate(bundle_path, anchor_d)
        if d is None:
            return absent  # unbound/mismatched signed verdict is NOT a pass (fail closed)
        return _byte_integrity_derive(d)
    if not (path and os.path.isfile(path)):
        return absent
    try:
        d = load_json(path)
    except ValueError:
        return absent
    return _byte_integrity_derive(d)


def deploy_reconcile_fact(path, bundle_path=None, anchor_d=""):
    """Track A: fold the deploy-reconcile producer's verdict (CHIPSEC-fed on-device/image byte
    reconcile vs the signed SBOM) into a gate fact. ran=False (ABSENT) when no deploy-reconcile
    evidence was supplied — the leg is CONDITIONAL, so on the offline/CI demo (no device) it is
    absent and the SP 800-193 §4.3.1 control stays advisory-MISSING WITHOUT flipping `allow`.
    Surfaces matched/reconciled + mismatch/missing/unexpected counts (and names) so the gate can
    both refuse a vacuous pass (nothing reconciled) and name exactly what drifted on the device.
    A skip (a TE/non-extractable section) is NOT a pass — reconciled counts only the comparable set.

    When DEPLOY_RECONCILE_BUNDLE is set, the verdict MUST come from the SIGNED, firmware-D-anchored
    bundle (subject #1 firmware-image == D), IGNORING the loose file — same forge-close as
    byte_integrity_fact/binary_hardening_fact. A bundle whose firmware subject != D fails closed.

    A LOOSE (unsigned) verdict carries no signed subject to anchor D, so it must D-anchor ITSELF: its
    predicate `image_digest` MUST equal the firmware anchor D. A loose verdict pointed at another/empty
    image is untrustworthy and fails closed to ABSENT (advisory) — never a PASS. (No verdict at all
    stays advisory-absent; the REQUIRE_SIGNED_EVIDENCE=1 abort for a PRESENT loose verdict is enforced
    by the caller, mirroring byte-integrity's _evidence_bundle.)"""
    if bundle_path:
        d = signed_predicate(bundle_path, anchor_d)
        if d is None:
            return _DR_ABSENT  # unbound/mismatched signed verdict is NOT a pass (fail closed)
        return _deploy_reconcile_derive(d)
    if not (path and os.path.isfile(path)):
        return _DR_ABSENT
    try:
        d = load_json(path)
    except ValueError:
        return _DR_ABSENT
    anchor = (anchor_d or "").replace("sha256:", "")
    img = (d.get("image_digest") or "").replace("sha256:", "")
    if not anchor or not img or img != anchor:
        return _DR_ABSENT  # loose verdict not self-anchored to D -> advisory-absent, no PASS
    return _deploy_reconcile_derive(d)


_DR_ABSENT = {"ran": False, "declared": 0, "reconciled": 0, "matched": 0, "mismatch_count": 0,
              "missing_count": 0, "unexpected_count": 0, "skipped_count": 0,
              "mismatched": [], "missing": [], "unexpected": [], "unverifiable": []}


def _deploy_reconcile_derive(d):
    mismatched = sorted(n for n in (m.get("name") for m in (d.get("mismatched", []) or [])) if n)
    missing = sorted(n for n in (m.get("name") for m in (d.get("missing", []) or [])) if n)
    unexpected = sorted(n for n in (u.get("name") for u in (d.get("unexpected", []) or [])) if n)
    # NAMES of declared modules that came back UNVERIFIABLE (a non-PE/TE skip or an extraction error) —
    # NOT a benign pass. The gate checks each against data.deploy_reconcile_exempt; an un-exempted one
    # denies (parity with byte-integrity's `unverifiable`). A same-GUID PE->TE swap surfaces here.
    unverifiable = sorted(n for n in
                          ([x.get("name") for x in (d.get("skipped", []) or [])]
                           + [x.get("name") for x in (d.get("errored", []) or [])]) if n)
    return {"ran": True,
            "declared": d.get("declared", 0),
            "reconciled": d.get("reconciled", 0),
            "matched": d.get("matched", 0),
            "mismatch_count": len(d.get("mismatched", []) or []),
            "missing_count": len(d.get("missing", []) or []),
            "unexpected_count": len(d.get("unexpected", []) or []),
            "skipped_count": len(d.get("skipped", []) or []),
            "mismatched": mismatched, "missing": missing, "unexpected": unexpected,
            "unverifiable": unverifiable}


def _binary_hardening_derive(d):
    # NAMES of DXE-class modules that could not be scanned (skipped OR errored). Only
    # DXE-class matters for the NX expectation, so non-DXE skips (PEI/SEC/TE) are not
    # "unverifiable" here. Each is checked against data.binary_hardening_exempt; an
    # unexpected one denies. (skipped/errored entries carry their module `type`.)
    unverifiable = [x.get("name") for x in (d.get("skipped", []) or [])
                    if x.get("type") in DXE_CLASS] \
        + [x.get("name") for x in (d.get("errored", []) or [])
           if x.get("type") in DXE_CLASS]
    unverifiable = sorted(n for n in unverifiable if n)
    missing_nx_names = sorted(n for n in (m.get("name") for m in (d.get("dxe_missing_nx", []) or [])) if n)
    return {"ran": True,
            "dxe_class_checked": d.get("dxe_class_checked", 0),
            "dxe_nx_compat": d.get("dxe_nx_compat", 0),
            "missing_nx_count": len(d.get("dxe_missing_nx", []) or []),
            "missing_nx": missing_nx_names,  # NAMES of missing-NX DXE modules, so the gate can name them
            "errored_count": len(d.get("errored", []) or []),
            "unverifiable": unverifiable}


def binary_hardening_fact(path, bundle_path=None, anchor_d=""):
    """R8: fold the binary-hardening producer's verdict into a gate fact. ran=False
    when no image+edk2 was available (distinct from a clean run). Surfaces the
    DXE-class NX-compat coverage AND the DXE-class modules that could not be scanned
    (unverifiable) so the gate can refuse a vacuous/under-covered pass and name exactly
    what did not pass — an unexamined image is NOT a hardened one.

    When BINARY_HARDENING_BUNDLE is set, the verdict MUST come from the SIGNED,
    firmware-D-anchored bundle (subject #1 firmware-image == D): the loose file is
    IGNORED, closing the same inputs/-write forge as byte_integrity_fact. A bundle
    whose firmware subject != D fails closed to not-ran (absent)."""
    absent = {"ran": False, "dxe_class_checked": 0, "dxe_nx_compat": 0,
              "missing_nx_count": 0, "errored_count": 0, "unverifiable": []}
    if bundle_path:
        d = signed_predicate(bundle_path, anchor_d)
        if d is None:
            return absent  # unbound/mismatched signed verdict is NOT a pass (fail closed)
        return _binary_hardening_derive(d)
    if not (path and os.path.isfile(path)):
        return absent
    try:
        d = load_json(path)
    except ValueError:
        return absent
    return _binary_hardening_derive(d)


# CHIPSEC sub-result module names the platform-posture reports read directly (mirrors how
# chipsec-posture already consumes chipsec.json). Surfaced as {fact: PASSED|FAILED|NOTAPPLICABLE},
# defaulting to "ABSENT" when the module did not appear (so the gate can tell absent from failed).
CHIPSEC_FACTS = {"secure_boot": "common.secureboot.variables", "smm": "common.smm",
                 "bios_wp": "common.bios_wp", "bios_ts": "common.bios_ts", "smrr": "common.smrr"}


def chipsec_subresults(doc):
    by = {}
    for r in (doc.get("results", []) or []):
        if r.get("module"):
            by[r["module"]] = (r.get("result") or "").upper()
    return {fact: by.get(mod, "ABSENT") for fact, mod in CHIPSEC_FACTS.items()}


def main():
    sbom_path = require("SBOM"); bundle_path = require("BUNDLE")
    sig = require("SIG"); out_path = require("OUT")
    builder = env("BUILDER_ID"); repo = env("SOURCE_REPO")
    warnings = []
    # Report names whose evidence was ASSUMED this run via a DEV_ASSUME_* opt-in (offline demo).
    # Emitted into the gate input as assumed_reports so the rego downgrades their evidenceGrade from
    # "verified" to "assumed" — the machine-readable grade then matches the loud warnings, instead of
    # over-claiming "verified" on evidence we did not actually verify this run. Empty in CI (real
    # signature + provenance) and for the all-facts-true fixtures.
    assumed_reports = []

    # SLSA L2 floor
    slsa_verified = env("SLSA_VERIFIED", "false")
    if slsa_verified != "true" and env("DEV_ASSUME_SLSA") == "1":
        slsa_verified = "true"; assumed_reports += ["slsa-provenance", "slsa-level-floor"]; warnings.append(
            "DEV_ASSUME_SLSA=1 — SLSA L2 provenance ASSUMED for local demo, not platform-verified "
            "(CI verifies it via gh attestation verify)")
    slsa_level = 2 if slsa_verified == "true" else 0

    # CHIPSEC posture
    chipsec_json = env("CHIPSEC_JSON")
    if chipsec_json and os.path.isfile(chipsec_json):
        _chipsec_doc = load_json(chipsec_json)
        chipsec_passed = bool(dflt(_chipsec_doc, "critical_passed", False))
        chipsec_subs = chipsec_subresults(_chipsec_doc)
    else:
        chipsec_passed = env("CHIPSEC_PASSED") == "true"
        chipsec_subs = {fact: "ABSENT" for fact in CHIPSEC_FACTS}

    # Build-tools posture
    bt_sig = env("BUILD_TOOLS_SIG", "false")
    if bt_sig != "true" and env("DEV_ASSUME_BUILDTOOLS") == "1":
        bt_sig = "true"; assumed_reports += ["build-tools-signed"]; warnings.append(
            "DEV_ASSUME_BUILDTOOLS=1 — build-tools signature ASSUMED for local demo, not verified "
            "(CI verifies it via cosign verify-blob of the build-tools bundle)")
    bt = build_tools(env("BUILD_TOOLS_JSON"), bt_sig == "true")

    # DSSE decode (from the VERIFIED bundle) + cert-SAN signer identity.
    # The reconcile attestation is a MULTI-SUBJECT in-toto Statement: subject "firmware-image"
    # is the firmware anchor D, and a second subject (the bound SBOM file) carries H. We surface
    # both separately — D drives the firmware/evidence-graph binding, H drives the SBOM-file
    # (tamper-after-signing) binding. A legacy single-subject bundle degrades to file_subject=that
    # subject, firmware_subject="".
    if sig == "true":
        stmt, bundle = decode_dsse(bundle_path)
        subjects = stmt.get("subject", []) or []
        att_firmware = ""
        att_file = ""
        for s in subjects:
            h = dflt(s.get("digest", {}) or {}, "sha256", "")
            if s.get("name") == "firmware-image":
                att_firmware = h
            elif not att_file:
                att_file = h
        if not att_file and subjects:  # legacy single-subject: the lone subject is the file digest H
            att_file = dflt(subjects[0].get("digest", {}) or {}, "sha256", "")
        pred = stmt.get("predicate", {}) or {}
        signer_id = signer_san(bundle)
    else:
        att_firmware, att_file, pred, signer_id = "", "", {}, ""

    # EFFECTIVE_BUILDER: the extracted identity, else assumed, else unverifiable
    if signer_id:
        effective_builder = signer_id
    elif env("DEV_ASSUME_IDENTITY") == "1":
        effective_builder = builder
        assumed_reports += ["provenance-identity", "signer-identity-pinned"]
        warnings.append("DEV_ASSUME_IDENTITY=1 — builder identity ASSUMED, not cryptographically "
                        "verified (CI keyless verifies it for real)")
    else:
        effective_builder = "unverified:no-cert-identity"

    sbom = load_json(sbom_path)
    sbom_hash = sha256_file(sbom_path)
    summary = pred.get("summary", {}) or {}
    clean = (dflt(summary, "missing", 1) == 0 and dflt(summary, "modified", 1) == 0
             and dflt(summary, "added_suspicious", 1) == 0)

    # firmware-image anchor D: the SBOM's own metadata.component SHA-256 — the digest
    # of the firmware bytes the build says it shipped. The evidence graph is rooted at D
    # (see _evidence_chain_bound), so the provenance subject binds to D, not to the SBOM
    # file digest H.
    fw_sbom = ""
    for h in (sbom.get("metadata", {}).get("component", {}).get("hashes") or []):
        if h.get("alg") == "SHA-256":
            fw_sbom = "sha256:" + h.get("content", "")
            break

    # provenance subjects. E2 SLSA provenance is platform-generated (GitHub attest-build-
    # provenance over the SBOM file), so its real subject is the SBOM-file digest H — that is
    # the FILE subject, consumed by the H-consistency leg of evidence-chain-bound. Its FIRMWARE
    # binding to D cannot be extracted (single-subject H), so it is a DEV_ASSUME-class mapping to
    # the firmware anchor D (informational — the rego's firmware binding is checked on the WE-built
    # reconcile attestation, not on E2).
    prov_file_sub = env("PROVENANCE_SUBJECT")
    if not prov_file_sub and env("DEV_ASSUME_CHAIN") == "1":
        prov_file_sub = "sha256:" + sbom_hash
        assumed_reports += ["evidence-chain-bound"]
        warnings.append("DEV_ASSUME_CHAIN=1 — provenance FILE subject ASSUMED = SBOM file digest H for "
                        "local demo (CI extracts it from the verified attestation)")
    prov_firmware_sub = fw_sbom  # DEV_ASSUME-class: E2 is single-subject H; D is the anchor mapping

    # firmware-image anchor legs
    fw_reconcile = dflt(pred, "image_digest", "")
    # freshly_measured distinguishes a GENUINE flash-time measurement (a real FW_IMAGE hashed
    # here at leg-3) from DEV_ASSUME_FWIMAGE mode (leg-3 copied from the build self-claim). Only
    # the former discharges SP 800-193 §4.3.1 (admission-time detection); the gate emits the
    # firmware-freshly-measured report ONLY when this is true, so offline/CI never claims §4.3.1.
    fw_image = env("FW_IMAGE")
    if fw_image and os.path.isfile(fw_image):
        fw_deployed = "sha256:" + sha256_file(fw_image)
        fw_freshly_measured = True
    elif env("DEV_ASSUME_FWIMAGE") == "1":
        fw_deployed = fw_sbom
        fw_freshly_measured = False
        warnings.append("DEV_ASSUME_FWIMAGE=1 — deployed .fd digest ASSUMED = SBOM image digest for local "
                        "demo (CI/flash sets FW_IMAGE to hash the real deployed image); §4.3.1 NOT claimed")
    else:
        fw_deployed = ""
        fw_freshly_measured = False

    # Signed-evidence enforcement for the two image-derived keystones (byte-integrity,
    # binary-hardening). REQUIRE_SIGNED_EVIDENCE=1 (set by run.sh + CI) makes the *_BUNDLE
    # MANDATORY: a missing/empty one aborts fail-closed, so a dropped env can never silently
    # downgrade to the unsigned loose file (the forge P0.1 closed). Off (ad-hoc/local dev),
    # the loose fallback is allowed but ALWAYS warns — the downgrade is never silent.
    require_signed = env("REQUIRE_SIGNED_EVIDENCE") == "1"

    def _evidence_bundle(name):
        b = env(name) or None
        if not b:
            if require_signed:
                sys.exit("assemble_gate_input: %s is required when REQUIRE_SIGNED_EVIDENCE=1 — "
                         "refusing to fall back to the loose inputs/*.json (this is the byte-integrity "
                         "forge P0.1 closed). This is a bundle-PRESENCE requirement; the bundle's "
                         "signature is verified out-of-band by cosign verify-blob-attestation in "
                         "run.sh/CI. Produce + pass the D-anchored bundle." % name)
            warnings.append("%s unset — verdict read from an UNSIGNED loose inputs/*.json "
                            "(local-dev fallback, NOT production; set REQUIRE_SIGNED_EVIDENCE=1 "
                            "to enforce the signed, D-anchored bundle)." % name)
        return b

    bi_bundle = _evidence_bundle("BYTE_INTEGRITY_BUNDLE")
    bh_bundle = _evidence_bundle("BINARY_HARDENING_BUNDLE")
    # Deploy-reconcile is a CONDITIONAL deploy-time leg: absent unless a device/image was scanned.
    # Its signed bundle is OPTIONAL even under REQUIRE_SIGNED_EVIDENCE (unlike byte-integrity/
    # binary-hardening, which are admission-time keystones) — so an offline/CI run with no device
    # simply omits it and the leg stays advisory-absent. A loose fallback still warns.
    dr_bundle = env("DEPLOY_RECONCILE_BUNDLE") or None
    if not dr_bundle and env("DEPLOY_RECONCILE_JSON"):
        # Deploy-reconcile is a CONDITIONAL leg (absent with no device), so no verdict at all never
        # aborts. But a PRESENT loose verdict under REQUIRE_SIGNED_EVIDENCE=1 must come from the
        # signed, D-anchored bundle — refuse the unsigned loose forge (parity with the byte-integrity/
        # binary-hardening _evidence_bundle abort). A dropped bundle env can no longer feed a forged
        # loose deploy-reconcile pass.
        if require_signed:
            sys.exit("assemble_gate_input: DEPLOY_RECONCILE_BUNDLE is required when "
                     "REQUIRE_SIGNED_EVIDENCE=1 and a deploy-reconcile verdict is present "
                     "(DEPLOY_RECONCILE_JSON set) — refusing the UNSIGNED loose file (deploy-reconcile "
                     "forge closed). Produce + pass the D-anchored signed bundle, or supply no verdict "
                     "(the leg stays advisory-absent).")
        warnings.append("DEPLOY_RECONCILE_BUNDLE unset — deploy-reconcile verdict read from an "
                        "UNSIGNED loose file (local-dev; set DEPLOY_RECONCILE_BUNDLE for the signed, "
                        "D-anchored bundle).")

    gate_input = {
        "sbom": {"present": len(sbom.get("components", [])) > 0, "hash": "sha256:" + sbom_hash,
                 "integrity": integrity(sbom), "thirdparty": thirdparty(sbom),
                 "generation": generation(sbom), "osf": osf_conformance(sbom),
                 "baseline": baseline_metadata(sbom), "dependencies": dependency_facts(sbom),
                 "data_quality": data_quality(sbom), "identity": sbom_identity(sbom),
                 "component_supplier": component_supplier(sbom)},
        "attestation": {"file_subject": ("" if att_file == "" else "sha256:" + att_file),
                        "firmware_subject": ("" if att_firmware == "" else "sha256:" + att_firmware)},
        "signature": {"verified": sig == "true", "identity": effective_builder},
        "provenance": {"builder_id": effective_builder, "source_repo": repo,
                       "source_commit": _source_revision(sbom),
                       "slsa_verified": slsa_verified == "true", "slsa_level": slsa_level,
                       "file_subject": prov_file_sub, "firmware_subject": prov_firmware_sub},
        "reconcile": {"clean": clean, "missing": dflt(pred, "missing", []),
                      "added": dflt(pred, "added", []), "modified": dflt(pred, "modified", []),
                      "declared": dflt(summary, "declared_modules", 0),
                      "matched": dflt(summary, "validated", 0),
                      "missing_count": dflt(summary, "missing", 0),
                      "undeclared_observed": dflt(summary, "added_suspicious", 0),
                      # shadow-duplicate GUIDs: FFS files sharing one FILE_GUID (a trojan hiding
                      # behind a legit module's identity). Names surfaced so the gate can name them.
                      "duplicate_guids": [d.get("guid") for d in dflt(pred, "duplicate_guids", [])],
                      "duplicate_count": dflt(summary, "duplicate_guids", 0)},
        "firmware": {"sbom_digest": fw_sbom, "reconcile_digest": fw_reconcile, "deployed_digest": fw_deployed,
                     "freshly_measured": fw_freshly_measured},
        "cve": cve_fact(env("GRYPE_JSON")),
        "chipsec": {"critical_passed": chipsec_passed, **chipsec_subs},
        # byte-integrity / binary-hardening: when a BUNDLE env is set, the verdict is read
        # from the SIGNED, firmware-D-anchored attestation (subject #1 firmware-image == the
        # anchor D = fw_sbom), NOT the loose inputs/*.json. This closes the last unsigned
        # image-derived verdict: an attacker with inputs/ write but no signing key can no
        # longer forge modified:0. anchor_d = fw_sbom (the SBOM metadata.component D the graph
        # roots at). The loose *_JSON path is a no-bundle fallback — but it silently re-opens
        # the forge, so REQUIRE_SIGNED_EVIDENCE=1 (set by run.sh + CI) makes the bundle
        # MANDATORY (fail-closed, mirroring the require("BUNDLE") reconcile precedent) and a
        # loose fallback ALWAYS warns, so a dropped env can never quietly downgrade the keystone.
        "byte_integrity": byte_integrity_fact(env("BYTE_INTEGRITY_JSON"), bi_bundle, fw_sbom),
        "binary_hardening": binary_hardening_fact(env("BINARY_HARDENING_JSON"), bh_bundle, fw_sbom),
        # Track A deploy-time reconcile — CONDITIONAL (ran=False/absent unless a device/image was
        # CHIPSEC-scanned). Present + failing DENYs (on-device byte swap); present + clean is a
        # `verified` leg for SP 800-193 §4.3.1; absent leaves §4.3.1 advisory without flipping allow.
        "deploy_reconcile": deploy_reconcile_fact(env("DEPLOY_RECONCILE_JSON"), dr_bundle, fw_sbom),
        "build_tools": {"present": bt["present"], "signature_verified": bt["signature_verified"],
                        "all_pinned": bt["all_pinned"], "unpinned": bt["unpinned"]},
        # Machine-readable honesty carry-through (previously stderr-only): the DEV_ASSUME_* /
        # loose-fallback caveats travel INTO the artifact, so a consumer of the gate input / VSA
        # sees them without the ephemeral stdout. assumed_reports drives the evidenceGrade
        # downgrade in firmware.rego (verified -> assumed for any report assumed this run).
        "warnings": warnings,
        "assumed_reports": sorted(set(assumed_reports)),
    }

    with open(out_path, "w") as f:
        json.dump(gate_input, f, indent=2)
        f.write("\n")

    sys.stderr.write("   builder_id=%s\n" % effective_builder)
    for w in warnings:
        sys.stderr.write("   ⚠ %s\n" % w)


if __name__ == "__main__":
    main()
