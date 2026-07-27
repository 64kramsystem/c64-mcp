# C64 Profile Overlay-Safe Addresses Implementation Plan

> **For Codex:** Implement this plan task by task with
> `superpowers:test-driven-development`, and use
> `superpowers:systematic-debugging` for any unexpected failure.

**Goal:** Make the bundled C64 symbol profile safe to apply after Ghidra
overlay spaces exist while preserving the default-RAM meaning of every
platform symbol.

**Architecture:** Keep GhidraMCP-next's ambiguity guard unchanged. Change the
deterministic C64 profile generator so every symbol carries an explicit
`RAM:` address-space qualifier, regenerate the packaged JSON, and verify the
checked-in artifact byte-for-byte. Exercise both an existing-overlay fixture
and a legacy-annotation upgrade fixture through the public generic profile
endpoint.

**Tech stack:** Python 3.10+, pytest, GhidraMCP-next HTTP API, generated JSON.

---

## Task 1: Add failing unit coverage for the new profile encoding

**Files:**

- Modify: `tests/test_c64_profile.py`

### Step 1: Update identity and representative-address expectations

Expect profile version `1.1.0` and representative addresses such as:

```python
assert symbols[("C64::CPU", "PROCESSOR_PORT")] == "RAM:0001"
assert symbols[("C64::VIC", "CONTROL_1")] == "RAM:d011"
assert symbols[("C64::KERNAL", "LOAD")] == "RAM:ffd5"
```

Add an assertion over all 165 symbol records that:

- the prefix is `RAM:`;
- the suffix has four lowercase hexadecimal digits;
- the numeric suffix is within `$0000-$FFFF`.

Split the qualifier before converting VIC addresses to integers so the
cardinality assertion still proves exact `$D000-$D02E` coverage.

### Step 2: Add deterministic generator parity coverage

Load `tools/generate_c64_profile.py` through `runpy.run_path`, call
`profile()`, serialize it with:

```python
json.dumps(
    generated,
    ensure_ascii=False,
    indent=2,
    sort_keys=True,
) + "\n"
```

Compare that text byte-for-byte with
`src/c64_mcp/profiles/c64.json`.

### Step 3: Run the focused tests and prove they fail for the intended reason

Run:

```bash
uv run pytest tests/test_c64_profile.py -q
```

Expected: failures report profile version `1.0.0` and unqualified addresses,
not import, fixture, or serialization errors.

### Step 4: Commit the red tests

```bash
git add tests/test_c64_profile.py
git commit -m "Test overlay-safe C64 profile addresses"
```

## Task 2: Generate the overlay-safe profile

**Files:**

- Modify: `tools/generate_c64_profile.py`
- Regenerate: `src/c64_mcp/profiles/c64.json`

### Step 1: Qualify generated symbol addresses

Change `symbol()` to emit:

```python
"address": f"RAM:{address:04x}",
```

Leave every `memory_blocks[*].start` value unqualified.

### Step 2: Bump the generated profile version

Change the profile version from `1.0.0` to `1.1.0`.

### Step 3: Regenerate the packaged artifact

Run:

```bash
uv run python tools/generate_c64_profile.py
```

Inspect the diff. It must contain exactly the version change and 165 `RAM:`
prefix additions.

### Step 4: Run the focused tests

Run:

```bash
uv run pytest tests/test_c64_profile.py -q
```

Expected: all focused tests pass, including byte-exact generator parity.

### Step 5: Commit the implementation

```bash
git add tools/generate_c64_profile.py \
  src/c64_mcp/profiles/c64.json
git commit -m "Qualify C64 profile symbols in RAM"
```

## Task 3: Add live overlay and upgrade-path regression tests

**Files:**

- Modify: `tests/integration/test_apply_c64_profile.py`

### Step 1: Add response-address assertions

Add a helper that receives a profile-application response and:

- extracts every `symbols[*].address`;
- compares address-space names case-insensitively;
- requires all symbols to resolve into the fixture's default `RAM` space;
- rejects every configured overlay-space name.

Fail explicitly when the response does not include symbol plans, because
absence would make the invariant untested.

### Step 2: Add the existing-overlay fixture test

Gate the test behind:

- `C64_MCP_PROFILE_MUTATE=1`;
- `C64_MCP_PROFILE_OVERLAY_TEST_PROGRAM=<program>`.

The fixture contract is a named `6502:LE:16:default` program with full default
RAM, one or more overlays covering platform-symbol offsets, and no overlay
named `RAM`.

Apply the bundled profile twice with `conflict_policy="error"` and
`create_memory_blocks=false`. Require:

- both calls commit;
- the second reports definitions idempotent;
- neither reports kept conflicts;
- both response plans resolve all symbols into default RAM.

### Step 3: Add the 1.0.0 upgrade fixture test

Gate this separately behind:

- `C64_MCP_PROFILE_MUTATE=1`;
- `C64_MCP_PROFILE_UPGRADE_TEST_PROGRAM=<program>`.

The fixture must be disposable, have full ordinary RAM, and initially have no
platform overlays or C64 profile annotations.

Build a frozen 1.0.0-equivalent profile in the test by deep-copying the
bundled profile, setting its version to `1.0.0`, and stripping `RAM:` from
symbol addresses. Apply it through `GhidraClient.apply_profile` with
`create_memory_blocks=true`, establishing legacy definitions plus overlays.
Then apply bundled 1.1.0 with the default conflict policy and no block
creation. Require every existing definition to be idempotent,
`kept_conflicts` to be empty, and all response symbol addresses to identify
default RAM.

### Step 4: Run non-live integration collection

Run:

```bash
uv run pytest tests/integration/test_apply_c64_profile.py -q
```

Expected: schema validation runs only when explicitly enabled; all mutating
tests skip cleanly without fixture environment variables.

### Step 5: Exercise the real Alter Ego overlay program

Run the existing-overlay test with the imported Alter Ego first-interaction
program configured as `C64_MCP_PROFILE_OVERLAY_TEST_PROGRAM`.

Expected: first apply commits all 165 symbols without ambiguity; second apply
is idempotent; all returned symbol addresses name the default RAM space.

### Step 6: Exercise onboarding and upgrade on a disposable program

Create a disposable fresh `6502:LE:16:default` full-RAM program and run the
upgrade fixture test. This simultaneously verifies the documented
`create_memory_blocks=true` path and the transition from unqualified 1.0.0
definitions to qualified 1.1.0 definitions.

### Step 7: Commit the integration regression

```bash
git add tests/integration/test_apply_c64_profile.py
git commit -m "Cover C64 profile overlays and upgrades"
```

## Task 4: Document the address-space contract

**Files:**

- Modify: `README.md`
- Modify: `CHANGELOG.md`

### Step 1: Update profile documentation

State that bundled platform symbols explicitly target the default `RAM`
address space so they remain unambiguous when ROM and I/O overlays exist.
Document the supported target: `6502:LE:16:default`, default CPU space named
`RAM`, and no overlay also named `RAM`.

### Step 2: Record the repair

Add an Unreleased `Changed` entry describing profile version `1.1.0`,
qualified symbol addresses, and overlay-safe application.

### Step 3: Run documentation and diff checks

Run:

```bash
git diff --check
uv run ruff check .
```

Expected: no whitespace or lint failures.

### Step 4: Commit the documentation

```bash
git add README.md CHANGELOG.md
git commit -m "Document C64 profile RAM qualification"
```

## Task 5: Verify and independently review the implementation

**Files:**

- Inspect all files changed since the design commit.

### Step 1: Run the complete local gate

Run:

```bash
uv run pytest
uv run ruff check .
uv run mypy
git diff --check
```

Expected: all tests pass, live-only tests skip unless their explicit
environment is present, and static checks are clean.

### Step 2: Audit generated-output scope

Confirm:

- exactly 165 symbol addresses have the `RAM:` prefix;
- all five memory-block starts remain unqualified;
- generated JSON is byte-identical to `profile()` serialization;
- no runtime tool schema or connector contract changed.

### Step 3: Request Claude implementation review

Use the existing Claude review session to inspect the committed implementation
against the design. Exclude deployment mechanics from the review, as requested
by the user. Resolve concrete correctness or test-coverage findings
test-first, then re-run the complete gate.

### Step 4: Confirm the live MCP behavior

Deploy the reviewed package, restart only the processes required to load it,
and verify the live tool reports profile version `1.1.0`. Re-run the Alter Ego
overlay fixture once against the deployed service before resuming game
analysis.
