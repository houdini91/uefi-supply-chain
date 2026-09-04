# Normalized UEFI module hash — a comparison profile

**Version 1 · draft for discussion.** Defines one thing: how to compute a digest of a UEFI PE32
module that is **independent of where the module was placed in flash**, so a hash declared at build
time and a hash re-derived from a shipped firmware image can be compared.

This document exists so that the normalization does **not** have to be defined by any SBOM
specification, and does not have to be inferred from any one implementation's source. It is
deliberately small, versioned, and owned by nobody's format.

> **The identifier is settled here, not in the ecosystem.** Within this document the profile is
> `uefi-pe-rebase0/v1`, and §5 fixes exactly which strings a consumer accepts. Whether the wider
> ecosystem adopts that spelling — and whether it prefers a `gitoid:blob:sha256:…` or
> `swh:1:cnt:…` style — is a community decision this document does not pre-empt. The one hard
> constraint is that the value be expressible as a URI, because SPDX 3.0's
> `contentIdentifierValue` is an `anyURI`.

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

Let `B` = `OPTIONAL_HEADER.ImageBase`. If `B == 0` there is nothing to reverse; go to §4.2.

**Locating the section table.** `NumberOfSections` is the `uint16` at `fh + 2` and
`SizeOfOptionalHeader` the `uint16` at `fh + 16`. The table begins at `oh + SizeOfOptionalHeader`
and each entry is 40 bytes, with `VirtualSize` at `+8`, `VirtualAddress` at `+12`, `SizeOfRawData`
at `+16` and `PointerToRawData` at `+20`.

**Mapping an RVA to a file offset.** Find the first section for which
`VirtualAddress ≤ rva < VirtualAddress + max(VirtualSize, SizeOfRawData)`; the offset is
`PointerToRawData + (rva − VirtualAddress)`. An RVA matching no section is a failure (below).
Where sections overlap, the first match in table order wins.

> This mapping is the single most likely source of divergence between two implementations, and PE
> parsers differ on it in practice. It is pinned here rather than left to "the file offset
> corresponding to its RVA".

**Locating the relocation directory.** `NumberOfRvaAndSizes` is the `uint32` at `oh + 92` (PE32) or
`oh + 108` (PE32+); the data directory array begins at `oh + 96` / `oh + 112`. The base-relocation
directory is index **5**, an 8-byte pair `{VirtualAddress: uint32, Size: uint32}`.

The directory is **absent** — meaning there is genuinely nothing to reverse — if and only if
`NumberOfRvaAndSizes ≤ 5`, or its `VirtualAddress` is `0`, or its `Size` is `0`. In that case
§4.2 alone canonicalizes the image: being placed at a load address changed only the `ImageBase`
header field.

**Walking the directory.** From the directory's first byte for exactly `Size` bytes, a sequence of
blocks:

```
block  = { PageRVA: uint32, BlockSize: uint32, entries… }
entry  = uint16 ; type = entry >> 12 , offset = entry & 0x0FFF
target = PageRVA + offset          ; entry count = (BlockSize − 8) / 2
```

A `BlockSize` of `0` ends the walk. Then for each entry, at the file offset its target RVA maps to:

| Type | Name | Action |
|---:|---|---|
| `0` | `IMAGE_REL_BASED_ABSOLUTE` | skip — padding, carries no fixup, **including when its offset is non-zero** |
| `3` | `IMAGE_REL_BASED_HIGHLOW` | read LE `uint32` *v*, write `(v − B) mod 2³²` |
| `10` | `IMAGE_REL_BASED_DIR64` | read LE `uint64` *v*, write `(v − B) mod 2⁶⁴` |
| any other | — | **fail — emit no value** |

**Failure cases — all emit no value, never a partially-normalized image.** With `B ≠ 0`: an image
that ends before `NumberOfRvaAndSizes` or before data-directory index 5 can be read (an
**unreadable** directory is a failure, not an absence — see the callout below). An unsupported
relocation type; a `BlockSize` below 8, **odd**, or extending past the directory; a directory
extending past the end of the image; an RVA (of the directory or of any fixup target) that maps to no
section; a fixup target whose 4 or 8 bytes would run past the end of the image; a section table
extending past the end of the image.

> **A declared or unreadable directory is a failure, not an absence.** Two implementations in this
> repo each had a version of this fault. The pefile-based one delegated parsing to a library that
> discards a relocation directory it dislikes without raising, so the loop was skipped. The
> dependency-free one let a *truncated* data directory fall through to "absent". In both cases the
> result was a header-only normalization — indistinguishable from a module with genuinely no
> relocations, and silently wrong for one that has them. The two agreed on all 122 reference modules
> while both carried the fault, because no reference module triggers it. Agreement between
> implementations is not evidence about paths neither exercises; that is what the negative vectors
> in §7 are for.

> A module whose relocation table was *stripped after* rebasing will not reproduce its declared
> digest. That is the intended behaviour — it is reported as a mismatch, never silently accepted.

### 4.2 Zero the placement-dependent header fields

Offsets, all little-endian. `e_lfanew` is the `uint32` at file offset `0x3C`; the PE signature
`"PE\0\0"` is 4 bytes at `e_lfanew`; the COFF `FILE_HEADER` follows at `fh = e_lfanew + 4` and is 20
bytes; the `OPTIONAL_HEADER` follows at `oh = fh + 20`.

**Fail — emit no value** if the image is shorter than `0x40` bytes, if `e_lfanew` leaves no room for
the signature and COFF header, if there is no `"PE\0\0"` at `e_lfanew`, or if the optional header
does not reach `oh + 68` (the last byte this section reads).

| Field | Offset | Size |
|---|---|---|
| `FILE_HEADER.TimeDateStamp` | `fh + 4` | 4 |
| `OPTIONAL_HEADER.CheckSum` | `oh + 64` | 4 — same for PE32 and PE32+ |
| `OPTIONAL_HEADER.ImageBase` | `oh + 28` (PE32, magic `0x10B`)<br>`oh + 24` (PE32+, magic `0x20B`) | 4<br>8 |

Any other `OPTIONAL_HEADER` magic: **fail — emit no value.**

`TimeDateStamp` and `CheckSum` are zeroed because edk2's `GenFw` already zeroes them when producing
the build-side `.efi`; normalizing both sides to the same state is what makes the comparison fair.

> **These two are a no-op on the OVMF reference, and they are still required.** Measured
> 2026-09-03: across all 122 modules, `TimeDateStamp` and `CheckSum` are already `0`, while
> `ImageBase` is non-zero on exactly the 11 rebased ones. So an implementation that skips these two
> fields still reproduces every vector here — and is still non-conformant.
>
> The reason is the point of the whole profile. `TimeDateStamp` is build-incidental: leave it in the
> preimage and rebuilding identical source at a different time yields a different digest, which
> destroys the layout-independent identity this exists to provide. It happens not to bite on edk2
> because GenFw already zeroes it. It would bite on a producer that doesn't.
>
> This is exactly the kind of divergence a conformance suite misses, since the vectors cannot
> distinguish the two implementations. Stated here so it is caught by reading rather than by a
> mismatch two years from now.

### 4.3 Digest

`SHA-256` over the resulting bytes. Lowercase hex.

## 5. Profile values

A producer declaring a digest **MUST** state which profile produced it.

| Identifier | Status | Meaning |
|---|---|---|
| **`uefi-pe-rebase0/v1`** | **canonical** | The full profile above. A verifier reproduces the digest by applying §4 to the shipped bytes. |
| `genfw-rebase-0` | **alias** | What the edk2 `-Y SBOM` generator emits today, in `edk2:hashCanonicalForm`, for this same profile. Accept as equivalent to `uefi-pe-rebase0/v1`. Retained because it is already present in shipped SBOMs; new producers should emit the canonical form. |
| `raw-pe32` | degraded | The digest is over the PE32 payload with **no** normalization. Emitted when a producer cannot obtain a base-0 form. **Not** comparable to either of the above. |

**Scope.** An identifier attached to a *component* (CycloneDX `properties[]`, coSWID `file-entry`)
applies to **every** hash on that component. The reference SBOM carries one `edk2:hashCanonicalForm`
per module beside both a SHA-256 and a SHA-512; both digests are over the same normalized bytes. An
identifier embedded in a self-describing value (`uefi-pe-rebase0/v1:sha256:…`) applies to that value
only. A component **MUST NOT** carry hashes under more than one profile without a per-hash form.

**Versioning.** The version is part of the identifier; there is no unversioned form. A consumer
**MUST** match identifiers exactly and **MUST NOT** treat `uefi-pe-rebase0` as equal to, or a prefix
of, `uefi-pe-rebase0/v1`. A change to §3 or §4 that alters any digest requires a new version.

**Absence.** A hash carrying **no** profile identifier **MUST** be read as the digest of the bytes
**as found**, with no transformation applied — i.e. as `raw-pe32`. It **MUST NOT** be read as
"unknown, not comparable".

> This is not a stylistic choice. Every SBOM published before this profile existed carries hashes
> with no identifier, and they are all plain digests of the bytes. Reading absence as "unknown"
> would retroactively invalidate all of them. The obligation therefore falls on the producer: a
> producer that applies **any** transformation before hashing **MUST** record the identifier.
> That version is also testable, which "a consumer MUST NOT compare" is not.

**Unknown identifier.** A consumer that meets an identifier it does not implement **MUST NOT**
compare the digest against anything it computes; the outcome is *not comparable*, and a verification
tool **SHOULD** report it as such rather than as a mismatch. Silently ignoring the identifier and
comparing anyway is the failure this profile exists to prevent.

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

## 6. Conformance

An implementation is conformant if, **whenever it emits a value, that value is correct**.

Emitting **no value** is permitted on any input the implementation cannot parse to its own
satisfaction — parsers differ in strictness, and a stricter one is not less conformant. What is never
permitted is emitting a value that *differs* from the reference for the same input.

Declining is not free, though: an implementation that emits no value for **any** vector marked
`expect_value: true` in the runnable set is **not conformant**. Those vectors are the floor. Without
one, an implementation that declines everything would satisfy "never differs" vacuously.

> This matters because it is already the observed situation. This repo's `canon_unrebase` (built on
> `pefile`) and `profile_ref.py` (a dependency-free parser) both reproduce all 122 modules of the
> OVMF reference and agree on every one — but on deliberately awkward synthetic inputs, `pefile`
> declines where the hand parser proceeds. Under this model both are conformant, and the distinction
> the model forbids — two different values for one input — has not been observed.

Two implementations, neither derived from the other, are the practical test of whether §3 and §4 say
enough. `profile_ref.py` was written from this document alone for exactly that purpose; the places
the document did not initially say enough are recorded in its `GUESSES` list and have since been
folded into §4.

## 7. Conformance vectors

Two files, and both are needed.

[`normalized-module-hash-vectors.json`](normalized-module-hash-vectors.json) — one entry per module
of the OVMF reference image, with the **as-found** and **normalized** digest of each. Real firmware,
but it does not ship the input bytes: reproducing them means reproducing the build.

[`normalized-module-hash-vectors-runnable.json`](normalized-module-hash-vectors-runnable.json) —
small hand-built images carrying their inputs inline, runnable by anyone. These exist because the
OVMF reference **cannot exercise half of §4**: every one of its 122 modules is PE32+ with only
`ABSOLUTE` and `DIR64` fixups, so the PE32 `ImageBase` offset and width, the `HIGHLOW` subtract, a
non-zero `TimeDateStamp`/`CheckSum`, and every failure case had never executed. An implementation can
get the entire 32-bit path wrong and still reproduce all 122 real modules.

Expected values in the runnable file are produced by `profile_ref.py`, **not** by the implementation
under test — vectors generated by the code they check prove only that it agrees with itself.

**What the vectors cannot test.** They feed PE bytes directly, so §3 (the section-header strip,
including the 8-byte extended form) is never exercised by them; that clause is checked only by
reading. And they cover the failure cases individually rather than exhaustively — a passing run is
evidence, not proof.

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

## 8. Reference implementations

| | Where | Notes |
|---|---|---|
| Verifier | `producers/reconcile/ffs.py` → `canon_unrebase()` | Python + `pefile`. Byte-patching per §4. Delegates PE parsing to `pefile` and therefore declines some inputs the reference accepts; fails closed on a declared-but-unparsed relocation directory. |
| **Reference** | `producers/reconcile/profile_ref.py` | Dependency-free (`hashlib` + `struct` only). Written from §3–§4 of this document without consulting `canon_unrebase`; it is what the runnable vectors' expected values come from. Agrees with `canon_unrebase` on all 122 reference modules. Its `GUESSES` list records every place this document initially fell short. |
| Producer | edk2 fork, `BaseTools/.../BuildReport.py` (`-Y SBOM`) | Declares the digest and the profile value. |
| — | CHIPSEC `scan_image` | A normalized-hash field has been *raised* as an idea in [chipsec/chipsec#2843](https://github.com/chipsec/chipsec/issues/2843) (open). CHIPSEC has **not** been asked to adopt this profile and has agreed to nothing; listed only so the idea's origin is traceable. |

## 9. Why not just declare the as-placed hash?

Fair question, and it would remove the need for this profile entirely: have the build record each
module's hash as it sits in the finished image, then a verifier carves and hashes and compares. Nothing
to normalize. CHIPSEC would work against it unchanged, since an as-found hash is already what it
computes.

The catch is where the work lands. To declare an as-placed hash, the generator has to carve its own
finished firmware image, including decompressing the volumes inside it. The intermediate `.Fv` build
artifacts are not a shortcut — of the 122 reference modules, 117 could be located in them at all and
**8 of those 117** differ from what actually ships (measured 2026-09-03), because the volumes are
re-packed during image assembly.

That would turn the generator into a firmware parser. Today it hashes the `.efi` files the build
already produced: no FV knowledge, no dependencies. That simplicity is the main argument for it being
maintainable upstream (see `planning/UPSTREAM-RISKS.md` R3).

So the choice is deliberate — keep the generator simple, put the work in the verifier, which carves
the image anyway. Layout-independence is a bonus rather than the goal: the same hash identifies a
module whichever image it lands in, which is also what makes it useful for allow-lists.

## 10. Relationship to TCG Component RIM

IANA's CoSWID Items registry already assigns indices 58–74 to the *TCG Component RIM Binding for
SWID/CoSWID*, and index **70**, `spdm-dmtf-spec-measurement-value-type`, is a discriminator saying
what kind of measurement a digest is. That is close enough to this profile's purpose that anyone
reviewing a coSWID extension will raise it, and it deserves an answer rather than silence.

The distinction: index 70 discriminates **what was measured** within an SPDM measurement block —
it selects among DMTF-defined measurement value types for a device reporting its own state over
SPDM. This profile discriminates **how a digest was computed** from a firmware file at rest: which
byte transformation was applied before hashing. The two are orthogonal, and a producer could in
principle need both.

Honest caveats: this has not been raised with TCG, the fit has been assessed from the registry and
the specification's scope rather than from implementation experience, and if a TCG mechanism can
carry a preimage-transformation identifier then reusing it is plainly better than minting a new
one. That question should be asked before any registration is sought.

## 11. Non-goals

This profile does **not** define where the digest is carried, how it is signed, what a mismatch
implies, or any policy. It is one comparison contract. Carriage is discussed separately in
[`planning/normalized-module-identity.html`](../planning/normalized-module-identity.html).

## 12. Status

Draft. Nothing here has been proposed to any standards body. It is written to be pointed at, so that
a normalization can be *referenced* rather than *re-specified* — which is precisely the objection
raised in [open-source-firmware/sbom#3](https://github.com/open-source-firmware/sbom/issues/3):
that a particular PE transformation should not become frozen API inside a specification.
