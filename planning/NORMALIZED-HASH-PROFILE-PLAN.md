# The normalized-module-hash profile — how CHIPSEC #2843, OSF #3, and this demo fit together

> **Status: PLAN (2026-09-03).** Written after re-reading both live upstream threads. Nothing here is
> filed or sent. Companion to [`CHIPSEC-INTEGRATION.md`](CHIPSEC-INTEGRATION.md) (Track B) and the
> drafts in `planning/engagement/`.
>
> Live state at time of writing: **CHIPSEC #2842 MERGED** (2026-08-22) · **CHIPSEC #2843 OPEN**, with
> `npmitche` on 2026-08-24 saying *"I like the idea of simply adding a `sha256_norm` field"* and routing
> it to `@BrentHoltsclaw` · **OSF `open-source-firmware/sbom` #3 OPEN**, 7 comments, last word Hughes
> 2026-08-21. We owe #3 a concrete proposal (~2026-09-10, per our own "about 3 weeks").

---

## 1. The relation: one mechanism, three legs

Both upstream offers are halves of a single check this repo already performs end to end.

| Leg | Question | Who owns it upstream | Where it lives today |
|---|---|---|---|
| **Declared** | what hash did the build say this module has? | **OSF #3** — an optional measurement slot in the embedded SBOM | edk2 `-Y SBOM` → `components[].hashes[]` (fork PR #6) |
| **Profile** | *how* was that hash computed, so a verifier can reproduce it? | **nobody — the gap** | `edk2:hashCanonicalForm = genfw-rebase-0`, CDX only |
| **Observed** | what hash does the shipped image actually yield? | **CHIPSEC #2843** — `sha256_norm` on `efilist.json` | `canon_unrebase()` in `producers/reconcile/ffs.py` |

```
   build ──> SBOM component hash ─────┐
                                      ├──> compare ──> same-GUID swap caught
   image ──> extract ──> normalize ───┘
                          ▲
                  both sides must run the SAME normalization
                  ── that shared definition is the whole product ──
```

The reconcile is only meaningful if the declared side and the observed side compute the **same normal
form**. Neither issue contains that definition. That is the actual deliverable, and it is what makes the
two threads one piece of work rather than two.

### Why the two asks are asymmetric (this drives the sequencing)

- **CHIPSEC is a verifier.** It *computes and emits* a value. A well-named, documented field is nearly
  self-describing — it can land without any registry or spec existing. **It is not blocked on anything.**
- **OSF/coSWID is a declaration format.** A consumer reading a declared hash must know how to reproduce
  it. A bare digest with no method identifier is ambiguous — and Hughes said plainly that the
  `uSwidEvidence` measured hash *"was designed to be the SHA hash of the binary blob with no futzing."*
  So the OSF ask **is** blocked on a named, versioned profile.

**Consequence: CHIPSEC can go first and independently, and a merged `sha256_norm` upstream becomes the
strongest possible argument for the OSF slot** ("the verifier side already exists in CHIPSEC").

---

## 2. The gap both threads are circling — stated precisely

Hughes' sharpest objection (2026-08-19):

> *"you've made some pretty weird (not to me, but to someone trying to regenerate the hash) changes to
> the PE file that has essentially become ossified as specification API."*

He is right, and it is worse than the thread implies: **the normal form is currently defined only by
45 lines of Python** — `canon_unrebase()` in `producers/reconcile/ffs.py:163-209`. If CHIPSEC ships
`sha256_norm` and OSF ships a measurement slot and neither names a versioned normalization, our
implementation becomes the de-facto spec *by accident* — exactly the outcome he is warning against.

### We already invented the fix, then dropped it twice

The reference SBOM carries a per-module profile tag — on **all 122** hashed modules:

```json
{ "name": "edk2:hashCanonicalForm", "value": "genfw-rebase-0" }
```

That is precisely the *"algorithm/value plus some indication of the measurement/profile"* we proposed to
Hughes on 08-20. It is running today. But:

| Carrier | Profile tag survives? | Consequence |
|---|:--:|---|
| CycloneDX 1.6 (`inputs/sbom.cdx.json`) | ✅ 122/122 | works |
| SPDX 2.3 view (`inputs/sbom.spdx.json`) | ❌ `annotations: null` | profile lost in conversion |
| coSWID (`producers/interop/coswid-emit.py`) | ❌ | **normalized hash rides as a plain payload hash, indistinguishable from a raw-blob hash** |
| the OPA gate | ❌ never read | compares digests without knowing what normal form they are in |

The coSWID row is the important one: **it reproduces Hughes' exact ambiguity inside our own emitter**, in
his own format. We cannot ask the spec to solve a problem our reference implementation still has.

The gate row is a real, if theoretical, soundness gap: `component-byte-integrity` compares a declared
hash to an observed hash with no assertion that both are the same canonical form.

### The under-specified step (the technical risk to all of it)

`canon_unrebase()` finishes by **re-serializing** the image: `pefile.PE(data=buf).write()` after setting
`ImageBase`/`TimeDateStamp`/`CheckSum` to 0. pefile's `write()` reconstructs bytes from parsed structures.
For two *independent* implementations (ours in pefile, CHIPSEC's in stdlib) to agree byte-for-byte, the
serializer behaviour would have to match — which is not something a spec can reasonably require.

**Fix, and it is a change on our side:** define the normalization as **in-place byte patches at file
offsets** on the original buffer — subtract the base at each relocation target, then zero three header
fields at their computed offsets. No parse-and-re-emit. That is implementation-independent, trivially
specifiable, and testable with byte-exact vectors. This is the single highest-value technical change in
the whole plan and it must land before either upstream ask is finalized.

---

## 3. Track 0 — the normalization profile (keystone; unblocks OSF, de-risks CHIPSEC)

**Deliverable:** a short, versioned, producer-neutral profile document + machine-checkable test vectors,
published in this repo and linkable from both upstream threads. Not owned by CHIPSEC, not owned by OSF —
which is exactly why it can be referenced by both.

**Naming.** `genfw-rebase-0` is edk2-flavoured and `edk2:`-namespaced. Needs a neutral, versioned id —
proposal: **`uefi-pe-rebase0/v1`** (keep emitting `edk2:hashCanonicalForm` as an alias for one release so
the reference SBOM and the 26 fixtures do not have to be re-cut immediately).

**Spec content** (derived from the implemented behaviour, not invented):

1. **Input.** The `EFI_SECTION_PE32` payload with the 4-byte `EFI_COMMON_SECTION_HEADER` stripped. TE
   sections, non-PE blobs, and compressed sections are **out of scope — emit no value** (never a guess).
2. **Un-rebase.** If `OPTIONAL_HEADER.ImageBase != 0` **and** a base-relocation directory is present, for
   each relocation entry: `ABSOLUTE(0)` → skip; `HIGHLOW(3)` → subtract `ImageBase` from the LE u32 at the
   target file offset; `DIR64(10)` → subtract from the LE u64. **Any other relocation type → fail, emit no
   value.** Never emit a partially-normalized image.
3. **No relocation table + non-zero ImageBase** → nothing to reverse; header normalization alone is exact.
4. **Header normalization.** Zero `OPTIONAL_HEADER.ImageBase`, `FILE_HEADER.TimeDateStamp`,
   `OPTIONAL_HEADER.CheckSum` — **as in-place patches at their file offsets**. No re-serialization.
5. **Digest.** SHA-256 over the resulting bytes.
6. **Failure is never a pass.** A stripped relocation table on a rebased module fails to match — flagged
   `modified`, never silently canonicalized.

**Test vectors.** Publish `(input bytes, output bytes, sha256)` for: several direct/DXE modules, all 11
XIP/PEI un-rebase cases, one no-reloc-table case, and one negative (unsupported reloc type → no value).
These are what a second implementer actually needs, and they are the honest answer to "someone trying to
regenerate the hash."

**Effort:** M (1–2 days incl. the byte-patch rewrite + vector generation + re-verifying 122/122).
**Acceptance:** the rewritten `canon_unrebase()` reproduces every current declared hash (122/122, no
fixture churn), and the vectors are reproducible from the committed reference image.

---

## 4. Track C — CHIPSEC #2843 → feature PR

One maintainer (`npmitche`) said he likes the idea of an added `sha256_norm` field and routed it to `@BrentHoltsclaw`, who has not replied. That is interest in a field *shape* — not agreement to implement, and nothing has been discussed about *which* normalization. Nothing external blocks filing; nothing external has been promised either.

| # | Step | Note |
|---|---|---|
| C1 | Rebase `houdini91/chipsec:feat/scan-image-normalized-hash` onto current `chipsec2` | base predates the #2842 merge |
| C2 | **Drop the local import shim** | #2842 fixed that bug upstream — the shim is now dead code, and the issue text mentions it |
| C3 | Re-verify against the merged fix | `BIOS_REGION` is the numeric region id; confirm nothing in the feature path assumed the old import |
| C4 | Port the profile from Track 0 — byte-patch normalization, stdlib only | **no `pefile`** (not a CHIPSEC dep); the profile doc makes this a re-implementation, not a port |
| C5 | Reply to `npmitche` on #2843 | confirm `sha256_norm` as the shape (his stated preference = ours), link the profile doc + vectors, note #2692 rebase offer stands |
| C6 | Open the PR | additive; `--norm` opt-in, default off; `sha256` key/`check` untouched; TE/unparseable → field omitted; unit tests; DCO `Signed-off-by: Mikey Strauss <mdstrauss91@gmail.com>` |

**Watch:** #2692 ("UEFI decode: fix parsing bugs and add section decoders") is still **open** and reworks
the same `fv.py`/`spi.py` paths. We promised in #2843 to rebase onto it — hold the offer, don't wait on it.

**Honesty constraints (carried from the drafts):** additive only, never change the default hash / key /
`check`; 122/122 = 111 stored rebase-0 + 11 un-rebased; do **not** re-introduce any "no prior art"
claim — CHIPSEC's own as-found hashing and #2360 are the nearby prior art.

**Effort:** M. **Unblocked now.** **Depends on:** Track 0 ideally (C4), but C1–C3 + C5 can start today.

---

## 5. Track R — OSF #3 → the concrete proposal (owed ~2026-09-10)

Hughes' blocking question is narrow and answerable:

> *"I think this is a good idea, but I have no idea how you'd do this with CycloneDX or SPDX for instance."*

**We already run the CycloneDX answer.** The reply should be a worked mapping, not a concept:

| Format | Value carrier (exists) | Profile carrier (the ask) | Our status |
|---|---|---|---|
| **CycloneDX 1.6** | `components[].hashes[]` | `components[].properties[]` `{name,value}` | ✅ shipping, 122/122 |
| **SPDX 2.3** | `packages[].checksums[]` | `annotations[]` (or `externalRefs`) | ❌ dropped — fix first |
| **SPDX 3.0** | `Hash` / integrity methods | richer; worth naming as the clean long-term home | — |
| **coSWID / RFC 9393** | `evidence` measured hash (**his #100**) | **no home — this is the real ask** | ❌ dropped |

Only the last row genuinely needs him. Frame the ask that small: **one optional method/profile identifier
alongside an existing hash.** Not a new hash type, not a new algorithm-registry entry, not a change to the
existing model.

**What the reply must contain:**

1. **The concession, first and explicitly.** We are *not* asking OSF to define PE normalization. Point at
   the Track 0 profile doc as a separate, versioned, independently-referenceable thing. This directly
   retires the ossification objection rather than arguing with it.
2. **The worked mapping table above**, with the CycloneDX one as running code he can look at.
3. **The coSWID question, narrowed:** where does a profile identifier live next to the #100 measured hash
   — a private-use map key (RFC 9393 permits private-use labels), or a convention on an existing field?
   His format, his call.
4. **Ack the threat-model exchange.** He is right that a compromised signing key is game over; our case is
   the SolarWinds shape (integration influenced, then *legitimately* signed) — already made on 08-20, keep
   it to one line, don't relitigate.
5. **Register for the UEFI Forum firmware-SBOM call** (https://members.uefi.org/wg/SBOM/calendar/, or take
   his offer of a formal invite). Cheap, and it is the room where the ODM/IBV reality he described lives.

**Effort:** S–M for the reply (the thinking is done); the spec-text PR is M and only after he answers (3).

**Strategic caveat — record it honestly.** The `open-source-firmware/sbom` repo has had **no commits since
2025-06-28** and issue #3 is its only open item. Combined with Hughes' own read — IBVs/ODMs refuse anything
costing time, money, or legal risk; the only levers are OEM mandate or regulation (EO / EU CRA) — the OSF
track may not land on merit or timeline. That is an argument for *sequencing CHIPSEC first*, not for
dropping OSF: the relationship and the UEFI-Forum room are worth more than the spec text.

---

## 6. Track D — make the demo prove what we are proposing

Currently the demo relies on both sides agreeing about normalization **out of band**. Every item below is
independently worth doing and each one strengthens an upstream argument.

| # | Change | Why it matters upstream |
|---|---|---|
| D1 | Byte-patch normalization (from Track 0) replaces parse-and-re-serialize | makes the profile implementable by anyone; retires the ossification objection in code |
| D2 | Carry the profile id through the **SPDX** converter (`annotations[]`) | the SPDX half of Hughes' question, demonstrated not asserted |
| D3 | Carry it through **`coswid-emit.py`** | today our coSWID has exactly the ambiguity we are asking him to fix — fix ours first |
| D4 | Emit the neutral `uefi-pe-rebase0/v1` id (alias the `edk2:` one) | a producer-neutral identifier is the thing a spec can reference |
| D5 | **Gate report: refuse to compare across an unknown profile** | closes a genuine soundness gap; turns "we assume both sides agree" into a checked fact |
| D6 | Publish the test vectors + a `make verify-profile` target | what a second implementer needs; also the CHIPSEC PR's evidence |

D5 is the one with real security content: the gate presently compares declared vs observed digests with no
assertion that they share a canonical form.

---

## 7. Sequencing

```
NOW ──> Track 0 (profile doc + byte-patch + vectors)   [M, keystone]
         ├──> D1/D4 land with it
         │
         ├──> Track C  C1-C3, C5 (rebase, drop shim, reply to npmitche)   [S, start today, parallel]
         │      └──> C4/C6 PR                                             [M, after Track 0]
         │
         └──> Track R  reply to #3                                        [S-M, due ~Sept 10]
                └──> spec-text PR                                          [M, after Hughes answers]

then D2/D3/D5/D6 as the demo catches up to what we proposed.
```

**If bandwidth is limited, do Track 0 then Track C.** CHIPSEC has an engaged maintainer, a merged prior
contribution, and a stated preference matching ours. OSF has a dormant repo and a maintainer who has
already told us the ecosystem lacks appetite. A merged `sha256_norm` in CHIPSEC makes the OSF proposal
strictly easier to argue — the reverse is not true.

**The one dated commitment:** we told Hughes twice we would return with a concrete proposal "in about
3 weeks" (08-20, 08-21) → **~2026-09-10**. Track R's reply should not slip past it even if Track 0 is
still in flight; the reply can cite the profile as in-progress with the mapping table already concrete.
