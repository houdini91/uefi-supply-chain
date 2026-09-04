# coSWID / OSF conformance — honest status

This document states plainly what the coSWID our `producers/interop/coswid-emit.py`
emits **does** and **does not** conform to, against the [OSF Firmware Embedded SBOM
spec](https://github.com/open-source-firmware/sbom) (v0.10, 2024-FEB-21) and
[RFC 9393 (coSWID)](https://www.rfc-editor.org/rfc/rfc9393).

> **On the `M-…` / `E-…` labels used below.** These are **this repo's own shorthand**, not
> identifiers from the OSF specification. Checked 2026-09-04: the spec's `source/*.rst` files
> contain no requirement IDs at all — every requirement is an unlabelled bullet, and the document
> is still v0.10 ("Initial prerelease version. Imported text from LVFS."). The labels are a
> convenience for cross-referencing *within this repo* and must not be used when corresponding with
> the OSF project, where they will not resolve.

**Framing.** This repo is a **verification layer** that is *complementary to*
hughsie/python-uswid + fwupd's embedded-SBOM model, not a competing SBOM producer
and **not** a claim of repo-level "OSF conformance." Our emit is a thin wrapper on
python-uswid's **native** CycloneDX loader; our contribution is the downstream
**shipped-byte reconcile + signed VSA**, not the coSWID format itself. Do not read
anything here as "OSF-conformant firmware." (See `DESIGN.md` — "fit the existing
embedded-SBOM plan, not compete with it.")

---

## MET (the scaffolding is real)

> **Scope of "MET": these describe what the *emitter* (`producers/interop/coswid-emit.py`)
> produces.** The enforcing OPA gate consumes the *CycloneDX* SBOM (`inputs/sbom.cdx.json`)
> and reconciles shipped bytes.
>
> **What the gate now DOES check (Tier-2, added):** a gated `osf-identity-shape` report
> asserts the OSF **GUID-identity MUST** — every firmware module carries a GUID-form tag-id
> (== FILE_GUID) — evaluated against the CycloneDX manifest the gate holds (each module's
> `bom-ref` carries the FILE_GUID). A conditional+advisory `osf-source-provenance` report
> represents the **M-srchash MUST**; the `-Y SBOM` generator now emits a real per-module
> `edk2:sourceHash` (123/123 on OvmfPkgX64), so on the reference this report **fires GREEN**
> and the `osf-source-hash` control is MET (it stays non-gating: a build without source
> hashes leaves it absent, never a DENY). Both map to the `osf-embedded-sbom` framework
> (`frameworks.yaml`).
>
> **What the gate still does NOT check (deeper roadmap):** the `osf-identity-shape` check is a
> **manifest-level structural proxy** — it reasons about the CycloneDX manifest, **not** the
> coSWID **parsed from the shipped PE / `.sbom` COFF section**. It does not yet verify the
> serialized coSWID's CBOR shape, tag-creator, or the `.sbom` section in the deployed image. A
> firmware whose *embedded* coSWID diverged from its CycloneDX manifest could still pass. The
> deeper check — extract the coSWID from the shipped image via uswid → `uswid --validate` clean
> → assert it matches the manifest — remains the roadmap item in `planning/COMPLIANCE-ROADMAP.md`.
>
> Also note: the OSF spec (`embedding.rst:20`) says the SBOM "does not need to be verified
> against a binary" — so our shipped-byte reconcile is an **extension beyond** OSF, not an OSF
> requirement.

- **coSWID / CBOR format** — serialized entirely by python-uswid (`uSwidFormatCoswid`
  / `uSwidFormatUswid`); no hand-rolled CBOR. (OSF `embedding.rst:64`)
- **uSWID magic header** for non-PE embedding — the `.uswid` container carries the
  25-byte header. (`embedding.rst:118-121`)
- **GUID identity (UEFI)** — the coSWID `tag-id` is the module `FILE_GUID`, carried
  through natively from the CycloneDX `bom-ref`. (`metadata.rst:46,69`)
- **Entity with tag-creator** — exactly one entity, `Oats Solutions`
  (regid `oatssolutions.tech`), role **`tag-creator` only**. (`metadata.rst:49-52`,
  RFC 9393 §2.5 tag-creator MUST)
- **Name + version** — `software-name` and `software-version` (fallback `"0"`).
- **M-srchash (MUST) — now MET.** The `-Y SBOM` generator emits a real per-module
  **`edk2:sourceHash`** — a SHA-256 over the module's INF `[Sources]` file set (each source
  file hashed, keyed by workspace-relative path, sorted, then hashed; deterministic and
  reproducible) — for every built module (**123/123** on OvmfPkgX64, verified by independent
  recompute). The CycloneDX carrier is the `edk2:sourceHash` property; the coSWID carrier is
  `colloquial-version`. The build's **source revision** (git commit) is additionally recorded
  as `edk2:sourceRevision` on the document root and surfaced into the gate's provenance as
  `source_commit`. Nothing is fabricated — a module with no readable source honestly carries
  none (0 such modules on OvmfPkgX64). The gate's `osf-source-hash` control is now GREEN.
  (`metadata.rst:56,62`)

## NOT-YET (unmet MUSTs — do not claim these)

- **M-lic (MUST):** OSS license links (SPDX URL + `license` rel) for OSS modules.
  The emitter adds no `link` entries. (`metadata.rst:115-117`)
- **M-swid (MUST):** `swid:`-prefixed generated GUIDs for **non-UEFI** parts
  (compilers, libraries, build tools). We skip components without a FILE_GUID + hash
  entirely, so no `swid:` identity is generated for them. (`metadata.rst:70`)

## Conditional

- **E-all:** *if* an artifact is labeled "the firmware SBOM" it MUST contain **all**
  component SBOMs. Our container is a **per-module subset** (only GUID + SHA-256
  modules). It is therefore safe **only** as per-module interop — do **not** brand it
  as *the* firmware SBOM. (`embedding.rst:170-174`)

## Our extension (labeled, not an OSF requirement)

- The **normalized shipped-byte SHA-256** — the hash a verifier recomputes from a
  dumped `.fd` to catch a same-GUID swap — is carried as the coSWID **payload hash**
  (its native home; it is the CycloneDX component hash rode through by the native
  loader). This is the substance of the reconcile + VSA, i.e. the repo's real
  contribution, but it is **our extension**, not an OSF/RFC-9393 requirement.
- **The dual-hash "device-measured evidence" idea is a PROPOSAL, not a shipped
  format.** RFC 9393's semantic home for a device-measured hash is the `evidence`
  branch — but python-uswid's `uSwidEvidence` has **no hash field** (only
  `{date, device_id}`), so it cannot be expressed with the reference tooling.
  We therefore do **not** ship a private `.src`/`.efi` payload-suffix convention;
  the shipped-byte hash uses the native payload, and the device-measured-evidence
  extension is left as the Hughes/USBT verification-profile proposal to pursue
  upstream (e.g. an evidence-hash field). `tests/test_coswid.py` asserts this gap.

---

## Related compliance notes (what the SBOM does/doesn't claim)

- **CRA Annex I Part II(1) / BSI TR-03183-2** — machine-readable SBOM obligation:
  **met** (we produce CycloneDX + SPDX).
- **CISA 2026 minimum elements** (finalized July 2026, superseding the NTIA 2021 baseline) —
  component **hash** + **license/IDs** are additions we cover; the **firmware image-digest
  binding is our extension**, not a CISA minimum element (already labeled as such in
  `oss-lane/`). The 2026 document also adds **tool name** and **generation context**, which are
  provenance-side — our SBOM records the generating tool in `metadata.tools` — and are not
  separately gated here; confirm the exact element text against the primary CISA source before citing.
- **EO 14028 / publishing an SPDX/CycloneDX export** — a SHOULD we satisfy; note we
  bind on the firmware digest `H` rather than the SBOM's own SHA-256 as the collection
  ID — a deliberate, documented choice.
