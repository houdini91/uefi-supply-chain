# Normalized UEFI module hash — a comparison profile

**Version 1 · draft for discussion.** Defines one thing: how to compute a digest of a UEFI PE32
module that is **independent of where the module was placed in flash**, so a hash declared at build
time and a hash re-derived from a shipped firmware image can be compared.

This document exists so that the normalization does **not** have to be defined by any SBOM
specification, and does not have to be inferred from any one implementation's source. It is
deliberately small, versioned, and owned by nobody's format.

> **Naming is not settled.** The identifier `uefi-pe-rebase0/v1` used below is a **placeholder**.
> Whether the scheme is named for the transformation, carries a version segment, or follows
> `gitoid:blob:sha256:…` versus `swh:1:cnt:…` style is a community decision. What is settled is that
> the value must be expressible as a URI, because SPDX 3.0's `contentIdentifierValue` is an
> `anyURI`.

---

## 1. Why a profile is needed

A UEFI module is built once and may be placed at different addresses in different images. Placement
is not a modification of the code, but it *is* a modification of the bytes: the loader-visible
`ImageBase` changes, and every field named by the module's base-relocation table is fixed up by the
same delta.

So a naive digest of the bytes found in flash answers "is this the same *placement* of this module",
not "is this the same *module*". On the OVMF reference, **11 of 122** modules are affected — every
XIP/PEI-phase module. For those, an as-found digest and a build-time digest **necessarily** differ
even when the code is byte-for-byte the same.

That is the entire problem this profile solves. It is not a security mechanism on its own; it is the
precondition that makes a build-declared hash and a deployment-observed hash *comparable*.

## 2. Scope

**In scope.** `EFI_SECTION_PE32` sections carrying a PE32 or PE32+ image.

**Out of scope — emit no value.** TE-format sections (`EFI_SECTION_TE`), non-PE blobs
(e.g. `ResetVector`), sections that cannot be cleanly parsed, and any image whose relocations this
profile does not define. An implementation **MUST NOT** emit a value it could not compute exactly.
A missing value is a correct answer; a guessed one is not.

**Not defined here.** How to carve modules out of a firmware image, what to do with the resulting
digest, and what any mismatch means. Those belong to the consuming tool or specification.

## 3. Preimage

The preimage is the **section payload with the common section header removed** — that is, the PE
image itself, and nothing else.

`EFI_COMMON_SECTION_HEADER` is **4 bytes** (3-byte size + 1-byte type), or **8 bytes** when the
3-byte size field reads `0xFFFFFF`, in which case a 4-byte `ExtendedSize` follows.

> **This is the clause most likely to be got wrong, and it is worth stating explicitly.** Two
> independent implementations already agree here — this repo's `pe32_from_ffs()` and CHIPSEC's
> `EFI_MODULE.calc_hashes()`, which hashes `Image[HeaderSize:]` — but that agreement is currently
> a coincidence of two careful implementations, not a contract. The extended (8-byte) header form is
> **not exercised by the OVMF reference**, because it requires a section larger than 16 MB. It is
> pinned here so it does not diverge silently later.

## 4. Normalization

Applied to a mutable copy of the preimage, **in order**. Every step is an in-place byte patch at a
computed file offset. The image is **never parsed and re-serialized** — re-serialization would make
the result depend on a particular PE library's writer, which a second implementation cannot be
expected to reproduce.

### 4.1 Reverse the relocation fixups

Let `B` = `OPTIONAL_HEADER.ImageBase`.

If `B != 0` **and** a base-relocation directory is present, then for each relocation entry, at the
file offset corresponding to its RVA:

| Type | Name | Action |
|---:|---|---|
| `0` | `IMAGE_REL_BASED_ABSOLUTE` | skip — padding, carries no fixup |
| `3` | `IMAGE_REL_BASED_HIGHLOW` | read LE `uint32` *v*, write `(v − B) mod 2³²` |
| `10` | `IMAGE_REL_BASED_DIR64` | read LE `uint64` *v*, write `(v − B) mod 2⁶⁴` |
| any other | — | **fail — emit no value** |

If `B != 0` and there is **no** relocation directory, there is nothing to reverse: being placed at a
load address changed only the `ImageBase` header field, and §4.2 alone canonicalizes the image.

> A module whose relocation table was *stripped after* rebasing will not reproduce its declared
> digest. That is the intended behaviour — it is reported as a mismatch, never silently accepted.

### 4.2 Zero the placement-dependent header fields

Offsets, all little-endian. `e_lfanew` is the `uint32` at file offset `0x3C`; the PE signature
`"PE\0\0"` is 4 bytes at `e_lfanew`; the COFF `FILE_HEADER` follows at `fh = e_lfanew + 4` and is 20
bytes; the `OPTIONAL_HEADER` follows at `oh = fh + 20`.

| Field | Offset | Size |
|---|---|---|
| `FILE_HEADER.TimeDateStamp` | `fh + 4` | 4 |
| `OPTIONAL_HEADER.CheckSum` | `oh + 64` | 4 — same for PE32 and PE32+ |
| `OPTIONAL_HEADER.ImageBase` | `oh + 28` (PE32, magic `0x10B`)<br>`oh + 24` (PE32+, magic `0x20B`) | 4<br>8 |

Any other `OPTIONAL_HEADER` magic: **fail — emit no value.**

`TimeDateStamp` and `CheckSum` are zeroed because edk2's `GenFw` already zeroes them when producing
the build-side `.efi`; normalizing both sides to the same state is what makes the comparison fair.

### 4.3 Digest

`SHA-256` over the resulting bytes. Lowercase hex.

## 5. Profile values

A producer declaring a digest **MUST** state which profile produced it. Two values are defined:

| Value | Meaning |
|---|---|
| `genfw-rebase-0` | The full profile above. The declared digest is over a GenFw-normalized, base-0 image; a verifier reproduces it by applying §4 to the shipped bytes. |
| `raw-pe32` | **Degraded.** The digest is over the PE32 payload with **no** normalization. Emitted when a producer cannot obtain a base-0 form. It is *not* comparable to a `genfw-rebase-0` digest. |

> A consumer **MUST NOT** compare digests across differing profile values, and **MUST NOT** treat
> such a comparison as a match or a mismatch — it is *not comparable*, which is a third outcome.
>
> This is a real case, not a hypothetical one: the `-Y SBOM` generator on the edk2 fork's `master`
> emits `raw-pe32` when GenFw rebase-0 is unavailable.
>
> **The committed reference predates that.** It was built from fork commit `eb53e5a` (recorded in
> the SBOM as `edk2:sourceRevision`), which is an ancestor of `fork/master` but ~25 commits behind
> it — before the hardening that added the fallback. So `hash_profiles` on the reference is a single
> value, and the `raw-pe32` path is defined here but not exercised by it. Re-deriving is a
> deliberate step, not a side effect: it changes the anchor `D` and forces the negative fixtures to
> be re-cut, so it belongs with the CI-builds-real-firmware work
> (`planning/CI-REAL-EVIDENCE.md`), which rebuilds regardless.

## 6. Conformance vectors

[`normalized-module-hash-vectors.json`](normalized-module-hash-vectors.json) carries one entry per
module of the OVMF reference image, each with the **as-found** digest and the **normalized** digest.
An implementation is conformant if, given the same as-found bytes, it reproduces every
`sha256_norm`.

The entries where `rebased: true` are the load-bearing ones — those are the modules where the two
digests differ, and therefore the only ones that test the normalization at all. A implementation
that passes only the `rebased: false` entries has demonstrated nothing.

Regenerate or re-check:

```bash
python3 producers/reconcile/profile-vectors.py --check docs/normalized-module-hash-vectors.json \
        --sbom inputs/sbom.cdx.json --image <OVMF_CODE.fd> --edk2 <edk2 tree>
```

Vectors are reproducible without shipping binaries: the inputs are the modules of a publicly
buildable image, identified by `FILE_GUID`, and the vectors file records the image digest they were
taken from.

## 7. Reference implementations

| | Where | Notes |
|---|---|---|
| Verifier | `producers/reconcile/ffs.py` → `canon_unrebase()` | Python + `pefile`. Byte-patching per §4; verified byte-for-byte identical to the previous parse-and-re-serialize implementation across all 122 reference modules. |
| Producer | edk2 fork, `BaseTools/.../BuildReport.py` (`-Y SBOM`) | Declares the digest and the profile value. |
| — | CHIPSEC `scan_image` | A normalized-hash field has been *raised* as an idea in [chipsec/chipsec#2843](https://github.com/chipsec/chipsec/issues/2843) (open). CHIPSEC has **not** been asked to adopt this profile and has agreed to nothing; listed only so the idea's origin is traceable. |

## 8. Why not just declare the as-placed hash?

Fair question, and it would remove the need for this profile entirely: have the build record each
module's hash as it sits in the finished image, then a verifier carves and hashes and compares. Nothing
to normalize. CHIPSEC would work against it unchanged, since an as-found hash is already what it
computes.

The catch is where the work lands. To declare an as-placed hash, the generator has to carve its own
finished firmware image, including decompressing the volumes inside it. The intermediate `.Fv` build
artifacts are not a shortcut — **8 of 117** modules in them differ from what actually ships (measured
2026-09-03), because the volumes are re-packed during image assembly.

That would turn the generator into a firmware parser. Today it hashes the `.efi` files the build
already produced: no FV knowledge, no dependencies. That simplicity is the main argument for it being
maintainable upstream (see `planning/UPSTREAM-RISKS.md` R3).

So the choice is deliberate — keep the generator simple, put the work in the verifier, which carves
the image anyway. Layout-independence is a bonus rather than the goal: the same hash identifies a
module whichever image it lands in, which is also what makes it useful for allow-lists.

## 9. Non-goals

This profile does **not** define where the digest is carried, how it is signed, what a mismatch
implies, or any policy. It is one comparison contract. Carriage is discussed separately in
[`planning/normalized-module-identity.html`](../planning/normalized-module-identity.html).

## 10. Status

Draft. Nothing here has been proposed to any standards body. It is written to be pointed at, so that
a normalization can be *referenced* rather than *re-specified* — which is precisely the objection
raised in [open-source-firmware/sbom#3](https://github.com/open-source-firmware/sbom/issues/3):
that a particular PE transformation should not become frozen API inside a specification.
