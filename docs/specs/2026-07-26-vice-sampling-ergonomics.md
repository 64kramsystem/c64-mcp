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

**Re-establishing a debug session is expensive, which raises the cost of every
round trip above.** The session these numbers come from is gone — the VICE
process was terminated and `vice_disconnect` released the binding. Getting back
to a usable state took a launch, a stuck autostart nudged by writing `$0D` to the
keyboard buffer at `$0277` with the count at `$C6`, and several minutes of
real-time loading before the title screen was reachable. Prerequisites, worth
recording because `vice_connect` will not bind without them: the Ghidra Debugger
tool must be open, and the `UNIX_SHELL:vice-c64.sh` launch offer must be present.

**Items 1 and 2 are correctness items, not ergonomics, and are listed first
deliberately.** Everything after them is friction, which is recoverable. A wrong
bank is not, because it returns plausible bytes and no error; and a protocol error
that can drop the connection is not either.

Order, after review corrected several premises:

- **Item 1** — bank semantics. Silent wrong answers.
- **Item 2** — the pending-checkpoint event defect. Publicly reachable today and
  able to break the connection, by two independent routes. An earlier draft filed
  this under the sampling item as something that would be "carried along" by it;
  that was wrong in both directions — it is reachable without any new feature, and
  it is a **prerequisite** for item 3 rather than a side effect of it.
- **Item 3** — the sampling series. Highest-value ergonomics item; absorbs most
  of item 4's use case. Depends on item 2.
- **Item 4** — `run_for`. Cheapest of the remaining work.
- **Item 5** — scatter reads. Standalone ergonomic win, *not* a prerequisite for
  item 3, contrary to an earlier draft.
- **Item 6** — `ignore_count`. **Blocked upstream**: the checkpoint-set payload
  has no such field. Kept as a record of why, with unblocked alternatives.
- **Item 7** — the timeout cap. Resolves to "no change"; only its rationale
  needed correcting.

Claims in earlier drafts of this spec that were wrong, corrected in place rather
than quietly dropped, because each is a plausible thing to re-assume:

- that the binary monitor supports setting `ignore_count` (it does not; VICE's core
  does, but no wire binding exists — item 6);
- that non-stopping tracepoints were half-implemented (the event model cannot
  currently survive them — item 2);
- that capture-on-hit could be atomic without stopping (monitor commands stop the
  emulator — item 3);
- that the sampling item would carry the event-model fix with it (it is a
  prerequisite, not a by-product);
- that the event defect affected only *non-stopping* checkpoints (two overlapping
  *stopping* checkpoints trigger it too);
- that a cancelled sampling run could return its partial series (inline return
  leaves no channel — cancellation is cleanup only);
- that `vice.py:916` distinguishes `vice_timeout` from `vice_target_method_timeout`
  (it treats them identically; the distinction is made in `vice_contract.py`).

---

## 1. `vice_read_memory` bank semantics — a correctness trap

Every read this session passed `bank_id: 1` (ram) explicitly. Getting it wrong
on a C64 is silent-wrong-answer territory: `$F000`–`$F080`, where the entire
player state block lives, reads as **KERNAL ROM** under bank 0/cpu and as
**player state** under bank 1/ram. Same addresses, plausible-looking bytes,
completely different meaning. No error is raised either way.

The tool description offers no default-bank guidance, and `vice_list_banks` has
to be called just to learn that ram is 1.

Minimum fix is documenting bank semantics on `vice_read_memory` and
`vice_write_memory` — that `bank_id` is required, what the C64 banks mean, and
that a wrong bank returns plausible wrong data rather than an error.

If a named-bank convenience is added on top, resolve `bank_name` through the
**live `vice_list_banks` response**, not through the bundled C64 symbol profile.
Baking `ram == 1` into a static profile would hardcode an emulator-supplied id
that belongs to the running machine's configuration; a stale alias is the same
class of silent wrong answer this item exists to prevent.

## 2. The single pending-checkpoint slot is wrong — LIVE DEFECT

In `_receive_event` (`ghidra-vice-connector/src/main/py/src/vice/protocol.py`), a
checkpoint-info event is parked in the singular `_pending_checkpoint` while the
connector waits for the following `RESP_STOPPED`. A second checkpoint-info
arriving first raises `ViceProtocolError("received two checkpoint-info events
without a stopped event")`.

**Two independent ways to reach that today**, neither needing a new feature:

1. **A non-stopping checkpoint that fires twice.** `vice_set_checkpoint` exposes
   `stop_on_hit: bool = True` (`src/c64_mcp/server.py`), so a caller can
   create one now. It produces no stop, so the second hit breaks the invariant.
2. **Two overlapping *stopping* checkpoints.** Confirmed in the VICE 3.10 source:
   `mon_breakpoint.c` iterates every matching enabled checkpoint at the address
   and calls `mon_breakpoint_event(cp)` for each *before* consulting `cp->stop`.
   One stop therefore emits several checkpoint-info events. An earlier draft of
   this spec treated the defect as non-stopping-only; that was too narrow.

**Fix:**

- replace `_pending_checkpoint` with a pending **list**;
- emit non-stopping hits immediately;
- accumulate stopping hits until `RESP_STOPPED`;
- add a `checkpoints` array to the stopped event, retaining the singular
  `checkpoint` field when exactly one exists, for compatibility.

Rejecting overlapping checkpoints instead would restrict functionality VICE
supports, and would not help case 1.

**The new `checkpoint_hit` event kind needs its contract pinned, because the
production path currently rejects it.** `sync_event` (`commands.py:533`) handles
only `stopped` and `resumed` and raises `ValueError` for anything else, so a test
using the controller's no-op synchronizer would pass while the real connector
records a synchronization failure and publishes nothing. Specify:

- the event kind is exactly `checkpoint_hit`;
- `checkpoint` carries the response; `pc` and `snapshot` are absent or null rather
  than invented;
- trace synchronization is a **no-op** — no monitor command may be issued, since
  that would stop VICE;
- execution state remains `running`;
- the test exercises the **production** synchronization path, not only a
  controller fake.

**The regression tests must assert behaviour, not absence of an exception.**
"Repeated hits do not raise" would pass an implementation that silently discards
events. Assert:

- two **distinct** checkpoint-hit public events are emitted;
- their public sequence numbers increase;
- **no** synthetic stopped event is emitted;
- `wait_for_stop` does not treat either hit as a stop;
- the connection remains usable for a subsequent command;
- **two overlapping stopping checkpoints** yield one stopped event carrying both
  in `checkpoints`;
- a **mixed** stopping/non-stopping pair at one address behaves as both rules
  above require.

### High-rate hits must not break waiting or command liveness

Publishing every hit through the existing controller introduces two failure modes
that the per-event contract above does not address. Both are properties of the
current controller, not of the new event kind:

1. **Spurious history loss.** Public history is capped at
   `EVENT_HISTORY_LIMIT = 1024` (`controller.py:30`), and `wait_for_stop` raises
   `ViceEventHistoryLost` whenever `after_sequence < oldest - 1`
   (`controller.py:812`) — that is, on *any* eviction, regardless of what was
   evicted. A tracepoint firing 1025 times would therefore report
   `event_history_lost` even though no stopped event was ever lost.
2. **Command starvation.** The unsolicited coordinator drains the raw queue to
   empty while holding `operation_lock` (`controller.py:358`). A continuously
   firing tracepoint can keep that queue non-empty indefinitely and starve
   `interrupt` or any other command.

Contract requirements:

- eviction of `checkpoint_hit` events must **not** make `wait_for_stop` report
  history loss unless a **stopped** event was actually evicted — track the last
  evicted stopped sequence separately;
- hit processing must be bounded, or yield `operation_lock`, so commands stay live
  under a continuous hit stream.

Tests:

- more than 1024 `checkpoint_hit` events followed by a stopped event: still
  waitable, no `event_history_lost`;
- an `interrupt` completes while non-stopping hits arrive continuously.

## 3. Sampling series — transparent stop, capture, resume

The wanted intention: on each hit of `$9931`, capture `$F00C` and
`$F01F`–`$F027`, append to a series, and return the whole series from one call.
A per-frame envelope trace is exactly this, and today it is only expressible as
N stop/read/resume cycles. **This is the highest-value ergonomics item**, and it
absorbs most of item 4's use case.

**It cannot be a true non-stopping tracepoint.** Capture cannot be atomic without
stopping: binary monitor commands themselves stop the emulator, so a memory read
issued after a non-stopping hit notification observes a *later* machine state than
the hit. "Capture at hit time while running" is not something the protocol can
honour. An earlier draft promised it; that was wrong.

**Design:** one bounded composite operation — internally set a *stopping*
checkpoint, capture the requested registers and ranges while stopped, resume,
repeat to a caller-specified sample count or deadline, and return the series.
Describe it honestly as *transparent stop/capture/resume*, and state that it
perturbs timing: the emulator is genuinely halted at each sample. If halting is
unacceptable for a given measurement, exact capture is not supported by the
protocol and the measurement needs a different approach.

**Item 2 is a prerequisite.** This operation's internal checkpoint can overlap one
of the caller's, which is the second trigger of that defect. An earlier draft
offered a temporary preflight-and-reject branch as an alternative; that is
disposable behaviour written to be deleted, for no practical gain, since item 2 is
ordered ahead of this anyway.

### Interface

`vice_sample_series`, taking:

| field | notes |
| --- | --- |
| `start`, `end` | trigger address or range, inclusive |
| `operation` | load / store / exec, as `vice_set_checkpoint` |
| `sample_count` | ≤ 256 |
| `deadline_ms` | ≤ 50000 |
| `registers` | list of register names to capture |
| `ranges` | ≤ 16 inclusive `{start, end}` capture ranges |
| `bank_id`, `memspace` | one shared pair for every capture |

Memory capture always uses `side_effects=false`. A sampling loop that mutates
machine state to read it would corrupt the series it is measuring.

### Contract

- **Results are returned inline** from the call. A separate buffer plus drain call
  was considered and rejected: it doubles the surface and adds ownership questions
  for a series already bounded below.
- **Caps** — 256 samples, 16 ranges per sample, 65536 total captured bytes
  (reusing `MAX_MEMORY_BYTES` from `vice.py:24` rather than inventing a second
  ceiling), 50000 ms deadline.
- **`deadline_ms` is a monotonic whole-operation deadline**, covering captures and
  resumes, not just time spent running. Cleanup may run best-effort beyond it.
- **Result object** — `samples` (ordered; each carrying its register values, range
  values, and the checkpoint that produced it), `sample_count`, and
  `termination_reason`, one of `completed`, `deadline`, `foreign_checkpoint`, or
  `capture_failed`.

  `cancelled` is deliberately **not** in that enum. Cancellation has no delivery
  channel with inline return, so it is a cleanup path rather than an observable
  result; listing it as a returnable reason — as an earlier draft did —
  contradicted the cancellation rule below.
- **Checkpoint ownership** — delete only the checkpoint this call created, in a
  `finally`. Never delete a caller's checkpoints.
- **Unrelated stops** — if VICE stops on a checkpoint this call did not create, do
  not auto-resume past it. Return the partial series with reason
  `foreign_checkpoint` and which checkpoint interrupted it; resuming past a user's
  breakpoint silently destroys the reason they set it.
- **Partial data is returned** for `deadline`, `foreign_checkpoint`, and
  recoverable `capture_failed`.
- **Caller cancellation is best-effort cleanup only, with no delivery promise.**
  With inline return there is no response channel left to deliver a partial series
  through, so promising both preservation *and* reporting — as an earlier draft
  did — is not implementable. Cleanup is attempted; the data is lost.
- **Final machine state** — VICE is left **stopped** on every return path,
  including success, so the post-condition does not depend on how the call ended.

Both the stopped post-condition and checkpoint cleanup hold only *while the
connector remains connected and responsive*. Neither is enforceable across
connection loss, and the spec should not imply otherwise.

## 4. `vice_run_for(duration_ms)`

Resume, wait, and stop as **one MCP operation**, returning the post-stop state.
Collapses the commonest three-call idiom into one and removes the sequence-number
threading entirely.

It is *not* atomic, and the spec must not claim it is: internally it still
resumes, waits, and interrupts, with observable races between those steps.

**`duration_ms` is wall-clock, not emulated time, and is bounded `1`–`50000`.**
Item 7's 55000 ms cap bounds each *Java invocation*, not a composite MCP call: a
55 s wait plus interrupt plus state collection exceeds both 55 s and 60 s overall.
So the choice is made here rather than offered — 50 s of running, with the
remaining 5 s reserved for interruption, state synchronization and cleanup.

Race resolution, stated as contract — **three** outcomes, not two:

- a checkpoint stop observed **before** the interrupt wins, and is what the call
  returns;
- if the wait expires first, that is normal duration completion, followed by the
  interrupt;
- if a checkpoint stops VICE **after the wait expires but before the interrupt
  takes effect**, the connector reports `vice_interrupt_superseded` with a
  `checkpoint_event` (`ViceInterruptSuperseded`, `controller.py:48`;
  `automation.py:185`). `run_for` must translate that into a **successful** result
  with termination reason `checkpoint` — not surface it as an error. This outcome
  was missing from an earlier draft;
- **any other** wait error aborts the call rather than being mistaken for duration
  completion.

Match the **serialized error code**, not the connector exception class.
`ViceTimeoutError` lives inside the connector; the MCP layer receives a structured
error result. Treat code **`vice_timeout`** as normal duration expiry, and
specifically **not** `vice_target_method_timeout`, which is a Java-invocation
timeout that must never be reported as a completed run. Transport timeouts likewise
abort.

The distinction is created in `vice_contract.py`: line 147 translates Ghidra's
generic `target_method_timeout` into `vice_target_method_timeout`, while the
connector's own `vice_timeout` is preserved through the failure mapping around line
319. An earlier draft cited `vice.py:916` for this, which is wrong — that line
treats **both** codes identically, adding `outcome_unknown` to each.

Result schema:

```text
termination_reason: duration_elapsed | checkpoint
checkpoint:         object, absent for duration_elapsed
pc:                 integer
registers:          object
sequence:           integer
```

Test the deadline/checkpoint race in both directions, plus the superseded-interrupt
outcome.

**Stated contract, not an open question:** if the target hits a checkpoint
before the duration elapses, the call **returns early with the hit**. This is
the only behaviour consistent with the rest of the surface — `vice_step` already
stops at checkpoints. Written down with that precedent cited so it is not
re-litigated.

**`vice_run_frames(n)` is deferred, not specified.** The binary monitor has no
advance-N-frames operation — the connector's command table offers
advance-instructions and execute-until-return, nothing frame-shaped — and
"frames" would otherwise have to be faked from wall-clock milliseconds, which is
exactly the imprecision a frame-accurate envelope measurement cannot tolerate.
Frames remain the natural unit for display- and player-tick-synchronous work, so
this is worth revisiting once a verified raster or frame-boundary mechanism
exists (a checkpoint on a raster register is the obvious candidate). Until then,
one tool with an honest unit beats two where one lies.

## 5. Scatter reads — several disjoint ranges per `vice_read_memory`

`$F00C` together with `$F01F`–`$F027` in one call, without over-reading the gap.

**Item 3 does not depend on this.** An earlier draft claimed it did, which also
created an awkward inversion where the higher-priority item waited on a
lower-priority one. While stopped, item 3's composite operation can simply issue
several ordinary range reads internally. Scatter reads reduce round trips for
callers reading disjoint state directly; they are a genuine ergonomic win and not
a prerequisite for anything else here.

`vice_read_memory_ranges`. Minimum contract, so this is implementable rather than
a wish:

- **one shared `bank_id` and `memspace`** for the whole call — mixing banks in a
  single scatter read invites exactly the confusion item 1 is about;
- an **ordered list of inclusive `{start, end}` ranges**;
- results returned **in input order**, so callers can zip them against the request
  without matching on addresses; each result object carries at minimum `start`,
  `end`, and the encoded bytes;
- **all ranges, the aggregate length, the bank and the memspace are validated
  before the first read is issued.** This matters most with `side_effects=true`: an
  invalid sixteenth range must not be discovered only after fifteen state-changing
  reads. Runtime failures can still carry `vice_state_may_have_changed`;
- **limits**: 16 ranges, and 65536 total bytes — reusing `MAX_MEMORY_BYTES`
  (`vice.py:24`) rather than introducing a second ceiling;
- **one shared `side_effects` flag, default `false`**, matching the existing
  `vice_read_memory` parameter (`vice.py:254`);
- **failure semantics**: with `side_effects=false`, one bad range fails the whole
  call. With `side_effects=true` it must **not** claim atomic failure — a failure
  after an earlier range has already read may have changed machine state, so the
  error has to carry the existing `vice_state_may_have_changed` warning
  (`vice.py:276`) exactly as the single-range read does.

## 6. Settable `ignore_count` on `vice_set_checkpoint` — BLOCKED UPSTREAM

**BLOCKED UPSTREAM. The premise was wrong: the binary monitor cannot set an
ignore count.** Recorded rather than deleted, because the motivating problem is
real and the reason it cannot be solved this way is worth not rediscovering.

What was verified in the connector
(`ghidra-vice-connector/src/main/py/src/vice/protocol.py`): `checkpoint_set`
packs its `CMD_CHECKPOINT_SET` (0x12) payload as `<HHBBBBB` — start, end,
`stop_on_hit`, `enabled`, `cpu_op`, `temporary`, `memspace`. There is **no
ignore-count field**. `ignore_count` occurs exactly twice in the whole file: as a
field of the response dataclass, and in `parse_checkpoint_info`. It is
report-only, and no amount of connector plumbing changes that — the wire format
has nowhere to put it.

**Confirmed in the VICE 3.10 source, which also shows exactly how small the
upstream fix would be.** The feature exists in the monitor core:
`mon_breakpoint_set_ignore_count` (`mon_breakpoint.c:261`) sets it, and the hit
loop honours it by decrementing and skipping (`mon_breakpoint.c:551`). Only the
*binary* monitor lacks access — in `monitor_binary.c`, `ignore_count` appears
solely in the response writer (line 527); nothing parses it from a request. It is
reachable from the text monitor's `ignore` command alone.

So the upstream ask is narrow and worth filing: an ignore-count field on the
checkpoint-set request, or a dedicated command, wired to the existing
`mon_breakpoint_set_ignore_count`. This is a missing protocol binding, not a
missing capability.

The motivating cases, still valid, still unserved:

- "stop every 12th hit of `$9931`" would sample one full vibrato cycle per call
  instead of twelve.
- `LAB_0730` is a page-copy **loop body**, so an execute checkpoint there fires
  **256 times**. The ways past it are 256 stop/resume cycles, or knowing in
  advance to break at `$073F` — which requires having already understood the
  loop.

Do **not** describe this as a connector pass-through. And be precise about
client-side suppression: layered over a *stopping* checkpoint it buys nothing —
the emulator still stops on every hit, so the round trips, which are the actual
cost, remain and are merely hidden from the caller. A connector could instead
count *non-stopping* hit notifications without stopping each time (once item 2 is
fixed), but even then it could not stop or capture exactly at the Nth hit, which
is what `ignore_count` would have given.

Two directions that are not blocked, in preference order:

1. **Item 3's composite stop/capture/resume**, which absorbs the repeated-hit
   cost into one call rather than eliminating the stops.
2. **A checkpoint condition.** VICE documents a `Condition set` command as `0x22`,
   applied after checkpoint creation, accepting register and memory expressions;
   the connector does not implement it (its `CMD_*` table covers memory,
   checkpoints, registers, advance-instructions, execute-until-return, ping,
   banks, info, exit, quit, reset — no condition). A condition over the player's
   frame counter can express "stop only at a cycle boundary", which serves the
   vibrato case. It is a legitimate alternative but **not** a general
   `ignore_count` replacement: conditions are expressions over machine state, and
   there is no hit-count variable to lean on, so anything phrased as "every Nth
   hit" still needs a counter the program itself maintains.

## 7. `vice_wait_for_stop` timeout cap — resolved, no change

The cap is 55000 ms, which forces chunking on anything slower.

**Checked: the cap is deliberate, not arbitrary — but it is not a transport
limit.** `vice.py` sets `MAX_TIMEOUT_MS = 55_000`, and
`GhidraClient.invoke_target_method` (`src/c64_mcp/ghidra_client.py`)
derives `generic_timeout_ms = connector_timeout_ms + 5_000` and then
`http_timeout = (generic_timeout_ms + 5_000) / 1000`.

The 60 s figure those land on is `DebuggerTargetMethodCore.MAX_TIMEOUT_MS = 60_000`
in ghidra-mcp-next — a **Java invocation cap**, not a transport ceiling. So 55000
is five seconds of headroom inside that Java cap, and the HTTP timeout is the
*outer* 65 s bound rather than the constraint being respected. An earlier draft
of this item had that backwards.

**Conclusion is unchanged: the cap stays.** Longer observation is served by item 4
returning early plus a caller re-arm loop, not by raising a limit whose purpose is
to fail inside the Java invocation budget rather than be killed by it. Note that
the cap bounds each Java invocation, **not** a composite MCP call — see item 4's
whole-call budget.
