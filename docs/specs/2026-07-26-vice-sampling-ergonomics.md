# VICE tool gaps — sampling ergonomics and a bank-semantics trap

Date: 2026-07-26
Status: specified, not implemented

## Why this exists

A session measuring a pitch/vibrato envelope in a C64 SID player hit the same
friction repeatedly. Recording it now, with the measured costs, because
otherwise it evaporates and the next session rediscovers it.

Measured cost, this session:

- Sampling one frame of the vibrato measurement cost **three round trips** —
  `vice_resume` → `vice_wait_for_stop` → `vice_read_memory` — with the public
  sequence number threaded by hand from the first call into the second.
- Walking **one vibrato cycle** (six sampled frames) took roughly **twenty
  round trips**.
- Four checkpoints placed on orphan code needed only a hit count, never a halt,
  but counting hits required stopping.
- Sampling `$F00C` together with `$F01F`–`$F027` meant either two calls or
  deliberate over-reading, since a read covers one contiguous range.

The friction is not "waiting". It is **sampling**: there is no way to express
"advance, then capture" as one intention.

Priority is not the listed order. Item 6 is a correctness trap rather than an
ergonomics gap, which arguably makes it the highest-value item here. Item 2 is
the cheapest for its value. Item 3 subsumes much of item 1's use case and
depends on item 4.

---

## 1. `vice_run_for(duration_ms)` / `vice_run_frames(n)`

Resume, wait, and stop **atomically**, returning the post-stop state. Collapses
the commonest three-call idiom into one and removes the sequence-number
threading entirely.

**Stated contract, not an open question:** if the target hits a checkpoint
before the duration elapses, the call **returns early with the hit**. This is
the only behaviour consistent with the rest of the surface — `vice_step` already
stops at checkpoints. Written down with that precedent cited so it is not
re-litigated.

Open: whether one tool with a unit parameter beats two tools. Frames are the
natural unit for anything display- or player-tick-synchronous; milliseconds are
the natural unit for everything else.

## 2. Settable `ignore_count` on `vice_set_checkpoint`

The VICE binary monitor supports it and the result already reports it, but it
cannot be set. With it, "stop every 12th hit of `$9931`" samples one full
vibrato cycle per call instead of twelve.

**Implementation is not a one-line Python addition.** Neither `ignore_count` nor
`hit_count` appears anywhere in this repository. `ViceTools.set_checkpoint`
(`src/ghidra_mcp_c64/vice.py`) builds an explicit argument dict for the
connector method `c64_vice_v1_set_checkpoint`, listing `start`, `end`,
`stop_on_hit`, `enabled`, `operations`, `temporary`, `memspace`. The counts are
pass-through from the connector side, so this needs the connector's TraceRMI
method to accept the argument as well as the Python parameter and its bounds
validation. Locate that method before estimating the work.

## 3. Tracepoints — capture on hit without stopping

Checkpoint fires → snapshot a named register/memory window → append to a buffer
→ keep running. One call returns the whole series. A per-frame envelope trace is
exactly this, and today it is only expressible as N stop/read/resume cycles.

**Half of this already exists.** `vice_set_checkpoint` already takes
`stop_on_hit: bool = True` (`src/ghidra_mcp_c64/server.py`), so a non-stopping
checkpoint is available now. What is missing is the **capture buffer** and a
**hit-count read path** — which is why counting hits still required stopping.

The concrete case this session wanted: on each hit of `$9931`, capture `$F00C`
and `$F01F`–`$F027`. That is **a scatter read per hit**, so this item depends on
item 4's range-list shape. Item 4 is a prerequisite, not a peer — and this is a
stronger motivation for item 4 than convenience.

Open: buffer bounds, and how the series is drained (returned on stop, versus a
separate read call).

## 4. Scatter reads — several disjoint ranges per `vice_read_memory`

`$F00C` together with `$F01F`–`$F027` in one call, without over-reading the gap.
Also the range-list shape that item 3's per-hit capture consumes.

## 5. `vice_wait_for_stop` timeout cap — determine and record, do not presume

The cap is 55000 ms, which forces chunking on anything slower.

**Checked: the cap is deliberate, not arbitrary.** `vice.py` sets
`MAX_TIMEOUT_MS = 55_000`, and `GhidraClient.invoke_target_method`
(`src/ghidra_mcp_c64/ghidra_client.py`) builds a nested budget ladder from it:
`generic_timeout_ms = connector_timeout_ms + 5_000`, then
`http_timeout = (generic_timeout_ms + 5_000) / 1000`. A 55000 ms connector
budget lands exactly on a 60 s generic boundary with a 65 s HTTP outer — a
deliberate margin under a 60 s transport limit.

**Conclusion: the cap stays.** Long waits are served by item 1 returning early
plus a re-arm loop, not by lifting a limit that exists to keep the inner budget
inside the transport's.

## 6. `vice_read_memory` bank semantics — a correctness trap

Every read this session passed `bank_id: 1` (ram) explicitly. Getting it wrong
on a C64 is silent-wrong-answer territory: `$F000`–`$F080`, where the entire
player state block lives, reads as **KERNAL ROM** under bank 0/cpu and as
**player state** under bank 1/ram. Same addresses, plausible-looking bytes,
completely different meaning.

The tool description offers no default-bank guidance, and `vice_list_banks` has
to be called just to learn that ram is 1.

This is a correctness gap, not an ergonomics one. Minimum fix is documenting
bank semantics on `vice_read_memory` and `vice_write_memory` — that `bank_id` is
required, what the C64 banks mean, and that a wrong bank returns plausible
wrong data rather than an error. Worth considering whether the bundled C64
symbol profile can supply a named-bank alias so callers write `ram` rather than
`1`.
