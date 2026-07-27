# C64 Profile Overlay-Safe Addresses — Design

## Problem

The bundled C64 symbol profile models physical RAM plus optional BASIC ROM,
KERNAL ROM, I/O, and color-RAM overlays. Its 165 symbol addresses are
unqualified hexadecimal offsets such as `d011` and `ffd5`.

GhidraMCP-next deliberately refuses a mutating request whose unqualified offset
is mapped by more than one address space. Consequently,
`apply_c64_symbol_profile(create_memory_blocks=false)` succeeds before overlays
exist but fails after the intended overlays have been created:

```text
Ambiguous unqualified address 'd000' maps to multiple program address spaces:
[d000, CHAR_ROM::d000, IO::d000]. Use a qualified <space>:<hex> address.
```

This prevents the profile and its overlay templates from being used together.
The ambiguity guard is correct: silently choosing an overlay could annotate a
different logical occupant.

## Goal

Make the bundled profile idempotently applicable to a standard Ghidra
`6502:LE:16:default` C64 program both before and after overlay blocks exist,
while keeping platform symbols in the CPU's logical/default `RAM` address
space.

## Non-goals

- Do not weaken or special-case GhidraMCP-next's ambiguity guard.
- Do not place VIC, SID, CIA, or KERNAL symbols in captured overlay spaces.
  Static 6510 instruction operands resolve in the default `RAM` space; those
  symbols describe the logical target selected by C64 banking state.
- Do not alter memory-block template starts. They create blocks/address spaces
  and must remain unqualified.
- Do not add runtime program inspection or profile rewriting.
- Do not change the MCP tool surface or connector contract.

## Considered approaches

### 1. Qualify bundled symbol addresses at generation time

Have `tools/generate_c64_profile.py` emit every symbol address as
`RAM:<hex-address>`, then regenerate `c64.json`.

This is the selected approach. The profile returned by
`get_c64_symbol_profile` exactly describes what the generic endpoint receives,
the target address space is explicit, and the fix has no runtime branching.

### 2. Rewrite addresses inside `apply_c64_symbol_profile`

This would keep the source JSON unqualified and transform a private copy before
calling Ghidra. It is rejected because the get and apply tools would expose
different profiles, and the rewrite would obscure the profile's actual
address-space contract.

### 3. Relax the generic ambiguity guard for symbol profiles

This is rejected because it would reintroduce silent cross-overlay writes for
all profiles and move a C64-specific policy into the generic Ghidra bridge.

### 4. Declare one top-level default address space

This would avoid repeating `RAM:` in every symbol, but profile schema version 1
has a closed set of top-level fields and rejects an unknown
`default_address_space` field. Adding that generic schema feature is unnecessary
for this focused repair.

## Data and behavior changes

- Change the `symbol()` generator in `tools/generate_c64_profile.py` to emit
  `RAM:<four-digit-offset>`.
- Change the generated profile version in that script from `1.0.0` to `1.1.0`.
- Regenerate `src/c64_mcp/profiles/c64.json`. The expected output change is all
  165 `symbols[*].address` values gaining the `RAM:` qualifier plus the version
  change.
- Leave all five `memory_blocks[*].start` values unchanged.
- Record the repaired profile/overlay composition in `CHANGELOG.md`.
- Document that the supported target is a `6502:LE:16:default` program whose
  default CPU space is named `RAM` and which has no overlay address space with
  that name.

No runtime Python production code changes are required. The generic profile
endpoint already accepts qualified addresses, and a dry run of the transformed
profile against the live Alter Ego program with `RAM`, `IO`, `CHAR_ROM`,
`BASIC_ROM`, and `KERNAL_ROM` spaces planned all 165 symbols successfully.

## Tests

Update `tests/test_c64_profile.py` before changing the profile:

1. Representative CPU, VIC, SID, CIA, workspace, and KERNAL symbols must equal
   `RAM:<address>`.
2. Every bundled symbol address must start with `RAM:` and contain a valid
   16-bit hexadecimal offset.
3. VIC address cardinality must be computed after splitting the qualified
   address and must still cover `$D000-$D02E` exactly.
4. Preserve the existing exact assertions that memory-block template starts
   remain unqualified.
5. Add a byte-exact generator-parity test. Load
   `tools/generate_c64_profile.py` with `runpy.run_path`, call `profile()`,
   serialize it with the generator's exact
   `json.dumps(..., ensure_ascii=False, indent=2, sort_keys=True) + "\n"`
   settings, and compare that text with the checked-in JSON. This avoids
   changing import paths or the generator's hard-coded output target while
   making hand edits and stale generated output fail the suite.

The first test run must fail because the existing profile is unqualified. After
the generator change and regeneration:

- Run the focused profile tests.
- Run the complete `pytest` suite.
- Run the existing opt-in generic-endpoint validation when available.
- Add an opt-in overlay integration test whose fixture contract requires a
  named `6502:LE:16:default` program with full default RAM and at least one
  overlay covering a platform-symbol offset. No overlay may itself be named
  `RAM`. It must apply the profile twice; the first result must commit and the
  second must report the definitions idempotent without ambiguity. On both
  responses, assert case-insensitively that every reported symbol address is
  in the program's default `RAM` space and none names an overlay space.
- Verify the upgrade path on a disposable full-RAM fixture without overlays:
  apply a frozen 1.0.0-equivalent profile with unqualified addresses, then
  apply 1.1.0 with the default `conflict_policy="error"`. Every existing
  definition must be idempotent and `kept_conflicts` must be empty. The
  independent overlay fixture covers post-overlay address resolution.
- Exercise that integration test against the live Alter Ego overlay program.
- Separately verify `create_memory_blocks=true` on a disposable program whose
  only block exactly matches the bundled zero-filled `RAM` template. RAM must
  be idempotent, the four overlays must be created, and the second application
  must be fully idempotent.

## Release and deployment

After tests and independent implementation review pass, release at the minor
level: the generated profile's public address encoding changes and the current
Unreleased section already contains new tools. Confirm the live tool returns
profile version `1.1.0` before resuming the Alter Ego analysis.
