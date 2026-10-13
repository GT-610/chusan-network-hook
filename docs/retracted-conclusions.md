# Retracted and superseded conclusions

A running list of every conclusion this investigation asserted and later withdrew, with
what replaced it. The rule applied: **a conclusion is only as strong as the experiment
that supports it, and an experiment that changes two variables at once supports none.**

## Status as of 2026-10-13

Static binary analysis is complete. **No on-machine test has been run on any CI-built
artifact.** The bind question therefore remains open, and is currently a two-way choice
that only a run can settle.

## The one unknown cell

| | CI-built | locally built |
|---|---|---|
| **v0.1.0 / main** | binds (observed, 2026-10-13) | does not bind (observed, 2026-10-13) |
| **Port 1** | **NOT MEASURED** | does not bind (observed, 2026-10-13) |

The diagonal is measured and consistent. The off-diagonal cell — **CI-built Port 1** —
has never been run. It is the only thing that separates "the code is responsible" from
"the environment is responsible", and no offline analysis can substitute for it.

## Withdrawn claims

### W1 — "the hook cannot be responsible; the game simply decides not to bind"

*Asserted in:* `broadcast-interface-regression.md` §1 (still present, must be read as
source-level only), §3.5; `broadcast-interface-triage.md` §2.

*Was based on:* `git diff v0.1.0 0dfd786 -- src/` does not touch `hook_bind`,
`hook_socket` or `g_hooks[]`.

*Why withdrawn:* true at source level, useless as a behavioural argument. The A/B that
appeared to support it compared a **CI-built** v0.1.0 against a **locally built** Port 1,
so it measured the toolchain as well as the source. Source-level equivalence does not
constrain runtime behaviour when the binaries differ.

*Replaced by:* the two-way framing above. Source diffs constrain what the code may do;
only a controlled binary comparison constrains what it does do.

### W2 — "the real variable is the build toolchain"

*Asserted in:* `broadcast-interface-triage.md` header block, §2.5; §4.5;
`build-toolchain-divergence.md` original §1 and §6.

*Was based on:* CI v0.1.0 (CRT 33145) binds, local Port 1 (CRT 27412) does not.

*Why withdrawn:* it treats one cell of the 2×2 as the whole table. Three CI-built
artifacts now show the toolchain is **constant across CI builds** (v0.1.0, main and
Port 1 all use CRT 33145, linker 35228/35229), so it cannot distinguish binds from
does-not-bind between any two CI binaries. It distinguishes only CI from this host.

*Replaced by:* the toolchain is a **real, CI-wide, constant** difference. It is
eliminated as the variable for any CI-vs-CI comparison, and retained as a live
hypothesis only for CI-vs-local.

### W3 — "the branch is not the explanation, so the mechanism is a game-side guard"

*Asserted in:* `broadcast-interface-triage.md` §2 as originally written.

*Why withdrawn:* it inherited W1. The disassembly facts in that section still hold
(`FUN_00a56010`'s guarded `bind`, the guard expression, the two distinct socket-creating
functions), and the guard field's writer is still unidentified. Only the inference that
the guard is the operative variable is withdrawn.

### W4 — "socket-call count identifies whether the guard passed"

*Withdrawn in:* `broadcast-interface-triage.md` §2.3 (already corrected there).

*Measured:* Parent-bound, Child-bound and Child-unbound runs are all **1 socket : 1
attempt**. The second `socket()` inside `FUN_00a79b80` never appears in any log. The
count carries zero information. Only the presence of a `bind` line is diagnostic.

### W5 — "the blocked field is `isRetryEnable`"

*Withdrawn:* it was matched by **vtable slot** `+0x50` on one object against **field
offset** `+0x50` on another. Unrelated. The guarded field
`*( *(*(client+0xb4) + 0xc) + 0x50 )` has no identified writer.

### W6 — "Port 1's new code did not run in the Port 1 log"

*Why withdrawn:* a measurement error, not a finding. Counting with `Select-String 'BIND'`
matched `bind_skipped` and `bind sock=`, and the wrong field index was used. Log lines
are tab-separated with the category at **index 4**.

*Corrected count:* the Port 1 Child log has **0** `BIND` lines; amdaemon in the same run
has **77**. The new code demonstrably ran.

### W7 — "the Rich build number identifies the MSVC version"

*Withdrawn:* Microsoft versions the static CRT separately from the compiler, and the
Rich build numbers are not `_MSC_VER` or the `14.xx` toolset number. Verified locally:
the `27412` group appears **only** under `/MT`, and `/MD` replaces it with
`0x93 / 30729` (`Utc1900_C`). So `27412` and `33145` are two static-CRT builds; **which
MSVC versions produced them is not established**, and this host has only toolset 14.44 so
it cannot be determined by building.

### W8 — "the two DLLs are materially different binaries, so the source is irrelevant"

*Asserted as:* an implicit premise of the toolchain hypothesis.

*Why withdrawn:* measured with the wrong method. CI Port 1 vs CI main differ in 83.6 %
of bytes **by position**, but `.text` grew by exactly 320 bytes (x64) / 208 bytes (x86),
and measured shift-insensitively 92.3 % / 94.9 % of 4-byte code words are shared, with
the string sets differing by exactly the Port 1 log strings. A position-wise byte
percentage cannot distinguish an insertion from a rewrite.

*Related trap:* on x64 `e_lfanew` differs (`0xF0` vs `0xF8`). Subtracting that 8-byte
shift from section **content** offsets produces a bogus 6 % match rate, while comparing
at each section's own raw pointer gives 100 %. See pitfall 9 in
`build-toolchain-divergence.md`.

## Standing facts (not retracted, not causes)

These are verified independently of the bind question and should not be re-litigated:

1. **`netenv` hardcodes `IfIndex = 1` and prefix `/24`**
   (`references/segatools/common/platform/netenv.c:253,301,306`) while the game sends
   Setting/Party/Advertise to the directed broadcast `192.168.139.255`.
   `limited_broadcast_target()` matches only `INADDR_BROADCAST`, so it can never fire.
   This is a real egress bug and is what the archived branch's first commit fixes.
2. **`FUN_00a56010` structure** in `chusanApp.exe`: `FUN_00a79710` creates a broadcast
   socket without binding; a guard on `*( *(*(client+0xb4) + 0xc) + 0x50 )` gates
   `FUN_00a79b80`, which creates its own socket and then binds.
3. **No captured session ever shows a Child receiving `SettingHostAddress`**, with
   either DLL version.
4. **The `10013/WSAEACCES` failures in some logs are a port-exclusion problem**, not this
   bug. `netsh interface ipv4 show excludedportrange` shows no range covering
   50200-50202 on the current host, and `winnat` is stopped, so it does not apply here.

## What would settle it

One run of the **CI-built Port 1** artifact, same machine, same configuration as the
2026-10-13 comparison:

- **does not bind** → the code is responsible; the toolchain is exonerated; Port 1's
  logging code is the only change, so the effect is in the added bind tracing itself
  (an extra `bind` call altering timing or state).
- **binds** → the DLL is exonerated entirely; the difference is the runtime environment
  (adapter count, netenv install order, `Fake Ethernet` presence).

Both outcomes are informative. Neither can be reached by reading binaries.