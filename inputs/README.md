# `inputs/` — the evidence artifacts

The real evidence the pipeline operates on for the OVMF/edk2 demo target. Two kinds:

**Source-of-record (committed)** — the demo's evidence, checked in so the gate and tests are reproducible
without a full firmware build:

| File | What | Produced by |
|---|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 SBOM (311 components; firmware digest in `metadata.component`) | edk2 `-Y SBOM` (fork, commit `eb53e5a` — see the provenance note below) |
| `sbom.spdx.json` | SPDX 2.3 view — **native** `-Y SPDX` output (supplier + BSD-2-Clause-Patent license + primaryPackagePurpose on every package; DEPENDS_ON relationships) | edk2 `-Y SPDX` (fork) |
| `sbom.uswid` | coSWID view + embed carrier | `producers/interop/to-coswid.sh` (uSWID) |
| `reconcile-verdict.json` | declared-vs-observed **membership** verdict (+ `image_digest`, anchor leg 2) | `producers/reconcile/carve.sh` |
| `byte-integrity.json` | **byte-integrity** verdict — each module's shipped PE32 bytes vs the SBOM hash (R4, 122 of 123). Carries a **full per-module manifest** (every module + method); any module that can't be byte-verified must be a reviewed entry in `data.byte_integrity_exempt` (with a documented reason) or the gate **denies and names it**. | `producers/reconcile/byte-integrity.py` |
| `chipsec.json` | CHIPSEC platform-posture predicate — **real** offline read of the demo OVMF's Secure Boot variables (`secureboot.variables=NOTAPPLICABLE`: SB not provisioned); HW-rooted checks NOTAPPLICABLE (no QEMU backing). Not a live `chipsec_main` driver run. | `producers/chipsec/secureboot-from-varstore.py` → `to-predicate.py` |
| `vex.openvex.json` / `vex.csaf.json` | CVE triage (**OpenVEX** — the signed evidence, in-toto `openvex.dev/ns`, subjects = firmware `D` + the OpenVEX file `H`) + BSI **CSAF** view (**collapsed into a reference inside the OpenVEX attestation**, not a second VEX attestation) | authored / `producers/interop/to-csaf.py` |

> **How these are trusted.** `reconcile-verdict.json`, `byte-integrity.json`, `chipsec.json`, and `binary-hardening.json` are produced
> **offline against the real deployed `.fd`** (they need an edk2 tree + a built OVMF image) and committed here;
> the gate — locally and in CI — **consumes them as evidence, it does not regenerate them** (CI has no built
> firmware). A consumer verifying their *own* firmware re-runs the producers against their image. To
> regenerate the byte-integrity verdict: `make byte-integrity EDK2=<edk2 tree> IMG=<OVMF.fd>` (needs `pefile`
> + edk2 FMMT; ~6 min — one FMMT extraction per module).

**Generated at run time (gitignored)** — recreated by `make demo` / the gate; safe to `make clean`:
`grype.json` (CVE scan), `gate-input.json` (assembled facts), `build-tools.cdx.json` (CI toolchain inventory),
and the keyless DSSE attestation bundles. Each WE-built attestation carries **two subjects** — #1
`firmware-image` = `D` (the evidence-graph anchor) and #2 the artifact's own digest `H` (tamper-after-signing):
`sbom.att.bundle` (reconcile, legacy-format so the assembler can decode both subjects; file subject = the SBOM),
`sbom.cdx.att.bundle` (E1 SBOM), `vex.att.bundle` (E4 OpenVEX, CSAF referenced), `chipsec.att.bundle` (E10),
`build-tools.att.bundle` (E7), `vsa.att.bundle` (E6 VSA, `inputAttestations` = the evidence graph). **E2 SLSA
provenance is single-subject `H`** (platform-generated over the SBOM file); its firmware binding to `D` is a
`DEV_ASSUME`-class mapping. The DSSE signature + signer identity (the former "E5") is the **signing envelope**
over these bundles, not a standalone artifact.

> Not to be confused with `oss-lane/fixtures/` — those are hand-authored **test vectors** (one per gate
> failure mode), not real evidence.

## Provenance of the reference SBOM — which generator revision produced it (2026-09-03)

The committed reference is **self-attributing**: `metadata.component.properties` carries
`edk2:sourceRevision = git:eb53e5a75ebb3f153f64646e04bc69ffd499d463`, the edk2-fork commit the
image and SBOM were built from. The assembler surfaces it into the gate input as
`provenance.source_commit`, so the signed evidence records which source produced these bytes.

**It is not the fork's current tip.** `eb53e5a` is an ancestor of the fork's `master` but roughly
25 commits behind it — the reference predates the generator hardening that added the
`raw-pe32` canonicalization fallback. Two consequences worth stating rather than discovering later:

- The reference SBOM's declared hashes are all `edk2:hashCanonicalForm = genfw-rebase-0`. The
  `raw-pe32` profile is *defined* (see [`docs/normalized-module-hash-profile.md`](../docs/normalized-module-hash-profile.md)
  and `data.supported_hash_profiles`) but **not exercised** by this reference.
- Re-deriving from the fork's current `master` changes the anchor `D`, which forces every negative
  fixture to be re-cut. That is the documented reference-consistency freeze
  (`planning/REVIEW-ROUND-2-FINDINGS.md` P1.1), and it belongs with the CI-builds-real-firmware
  work (`planning/CI-REAL-EVIDENCE.md`) — which rebuilds anyway — not as a standalone step that
  would pay the re-cut cost twice.

## Note on `sbom.cdx.json` hardening annotations (2026-08-07)

The `edk2:hashCanonicalForm` (per hashed module) and `edk2:thirdPartyEnumeration`
(metadata.component) properties were **annotated** onto this captured sample to reflect
the hardened `-Y SBOM` generator (edk2 fork commit `3053c6e`), whose code — but not the
hash *values* — post-dates this capture.

**Rebuild-confirmed (2026-08-07):** a genuine `build -a X64 -t GCC -p OvmfPkg/OvmfPkgX64.dsc
-b DEBUG -Y SBOM` on the fork's `feat/build-y-sbom-generator` branch (edk2-stable202411) was
run and its output inspected: **311 components, all 122 hashed modules `genfw-rebase-0` (zero
`raw-pe32`), `thirdPartyEnumeration=git-submodules`** — i.e. the annotations above match a real
build exactly. The genuine build's *hash values* differ (different compiler bytes), so its SBOM
is NOT swapped in here: the checked-in snapshot's per-module hashes must stay consistent with
`byte-integrity.json`, `reconcile-verdict.json`, and the firmware digest `D` referenced across
26 hand-crafted gate fixtures. To adopt a fresh capture end-to-end, regenerate the *whole*
evidence set (SBOM + reconcile + byte-integrity + `D`) from one build — see
`scripts/regen-reference-sbom.sh` for the SBOM step.

## Source hashes — real values, added 2026-08-08

Every module now carries a real **`edk2:sourceHash`** (123/123 non-library modules; 310/311
components) and the document root carries **`edk2:sourceRevision = git:eb53e5a…`**
(edk2-stable202605-473). Unlike the *code-post-dating* hardening annotations above, these are
**real hash values**: they were produced by the enhanced `-Y SBOM` generator on a genuine
OvmfPkgX64 build and are a deterministic SHA-256 over each module's INF `[Sources]` file set —
a function of the **source**, independent of the compiler. They are valid for this checked-in
snapshot because every module GUID here matches that build 123/123 and the source revision is
the same; the `AcpiTableDxe` value was re-derived independently and matched to the byte. They
satisfy the OSF **M-srchash** MUST (gate control `osf-source-hash`, now GREEN) without touching
the shipped-byte hashes or `D`. The generator change lives in the fork's `BuildReport.py`
(per-module `edk2:sourceHash` + document `edk2:sourceRevision`).

## Shape enrichment — added 2026-08-08 (Increment E)

The reference (and the generator) now also carry: a document **`serialNumber`** (urn:uuid, CISA
SBOM-Version), **per-component `licenses`** (edk2 first-party = `BSD-2-Clause-Patent`; vendored OSS
keeps its own — 123/123 modules), **platform `metadata.component` `cpe`/`purl`/`licenses`**
(`cpe:2.3:a:tianocore:edk2:edk2-stable202605`), a **`compositions[].aggregate: incomplete`**
completeness declaration (CISA known-unknowns), and the restored **`edk2:hashCanonicalForm`**
property. These are deterministic (license/cpe/compositions) or a valid urn:uuid (serialNumber),
annotated onto the reference from the enhanced generator's real build WITHOUT touching the
shipped-byte hashes or `D`. New gated controls: cisa-sbom-version, cisa-completeness,
cisa-component-producer (all GREEN on the reference).

## SPDX — native generator, not protobom (2026-08-08, Increment F)

`sbom.spdx.json` is now the **native** `-Y SPDX` output, replacing a lossy `protobom` round-trip
that dropped per-package `supplier` (an NTIA-required field: 310->0) and `copyrightText`, and
downgraded real `DEPENDS_ON` edges to `CONTAINS`. The native output carries **supplier +
BSD-2-Clause-Patent license + primaryPackagePurpose on 310/310 packages** and true `DEPENDS_ON`
relationships. It is a **view** (the gate reads the CDX, which stays the canonical byte reference);
full **SPDX 3.0.1** (which BSI TR-03183-2 now expects, alongside the CDX 1.6 we already meet) is a
larger format migration tracked as future work.
