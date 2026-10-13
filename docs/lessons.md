# Lessons: withdrawn claims and method rules

Every conclusion this investigation asserted and then withdrew, and the rules that
prevent a repeat. The live state is in [`setting-bind-investigation.md`](setting-bind-investigation.md).

The governing rule: **a conclusion is only as strong as the experiment that supports it,
and an experiment that changes two variables at once supports none.**

## The error that cost a night

The 2026-10-13 A/B compared a **CI-built** v0.1.0 against a **locally built** Port 1 and
found one binds and one does not. It was read twice, wrongly, in opposite directions:

1. first as "the hook cannot be responsible, the source is identical";
2. then, after the toolchain difference was found, as "the toolchain is the variable".

Both readings are unsupported. The comparison moved the **code** and the **toolchain**
simultaneously, so it convicts nothing and exonerates nothing. It is one cell of a 2×2
read as the whole table.

## How it was actually resolved

The missing cell was measured: **CI-built Port 1**. It binds, twice. Since the CI Port 1
artifact and the local Port 1 DLL were built from byte-identical `src/`, the Port 1 row is a
one-variable comparison — and it comes out opposite. The build decides, not the source.

Two points are worth more than the answer itself:

- **The fix was a measurement, not a better argument.** Every offline theory before it was
  wrong or unfalsifiable; the run took minutes and ended a night of inference.
- **A single comparison can be self-validating.** The four Child captures interleave
  CI/local/CI, and the CI ones bind while the local ones between them do not. That ordering
  eliminates every "the machine drifted" escape hatch without any extra work — worth
  checking for whenever runs are already on disk.
- **Filling a cell can invalidate a different cell.** Verifying the table exposed that
  `log_5`, recorded as "locally built v0.1.0", cannot be one — its amdaemon log contains
  `bind_virtualized`, a string that did not exist in v0.1.0's source. The row the earlier
  document asserted had never been measured at all. A table is only as good as the
  provenance of each cell in it, and provenance must be *derived from the artifact*, not
  from the filename.

## Withdrawn claims

| # | claim | why withdrawn |
|---|---|---|
| W1 | "the hook cannot be responsible; the game simply decides not to bind" | true at **source** level only (`git diff v0.1.0 0dfd786 -- src/` does not touch `hook_bind`). Source diffs constrain what code *may* do, never what a binary *does*. |
| W2 | "the real variable is the build toolchain" | one cell read as the whole table. The toolchain is **constant across CI** (33145), so it cannot distinguish two CI binaries. |
| W3 | "the branch is innocent, it is a game-side guard" | inherited W1. The disassembly facts in `FUN_00a56010` still hold; only the inference that the guard is the operative variable is withdrawn. |
| W4 | "socket-call count identifies whether the guard passed" | **measured** and refuted: bound-Parent, bound-Child and unbound-Child are all 1 socket per attempt. The second `socket()` in `FUN_00a79b80` never appears in any log. Only the presence of a `bind` line is diagnostic. |
| W5 | "the guarded field is `isRetryEnable`" | matched a **vtable slot** `+0x50` on one object against a **field offset** `+0x50` on another. Unrelated. The writer of the guarded field is still unidentified. |
| W6 | "Port 1's new code did not run in the Port 1 log" | a measurement error. `Select-String 'BIND'` matches `bind_skipped` and `bind sock=`, and the wrong field index was used. Correct count: Port 1 Child has **0** `BIND` lines, amdaemon in the same run has **77**. |
| W7 | "the Rich build number identifies the MSVC version" | Microsoft versions the static CRT separately, and Rich build numbers are not `_MSC_VER` or `14.xx`. Verified: the `27412` group appears **only** under `/MT`; `/MD` replaces it with `0x93 / 30729` (`Utc1900_C`). **Which MSVC versions produced 27412 and 33145 is not established** and cannot be determined here (only toolset 14.44 is installed). |
| W8 | "the DLLs are materially different binaries, so the source is irrelevant" | wrong method. 83.6 % of bytes differ *by position* purely from a code insertion; shift-insensitively 92-95 % of code words are shared and the string sets differ by exactly the Port 1 strings. |
| W9 | "Port 1 has no behaviour change, so it is not the variable" | the mirror of W8, and equally unsupported. A source-level "no control-flow change" is not a behavioural guarantee. **Resolved:** Port 1's *code* is exonerated by the CI Port 1 run; the build is the variable. |
| W10 | "`log_5` is a locally built v0.1.0" | it cannot be. Its amdaemon log contains `bind_virtualized`, added only by `74141ba`, and it ran `force_limited_broadcast=0`. It is a Port-1-era local build. The cell it was used as ("v0.1.0 locally built") was never measured. Caught only by re-deriving each cell's provenance from the artifacts during the final check. |

## Method rules

1. **Hash the DLL before every run.** A run without a hash cannot be compared to anything.
2. **Both sides of an A/B must come from the same build.** Not "same source", not "same
   tag" — same toolchain, verified with `dump_rich.ps1`. A CI-built and a locally built DLL
   of identical source behave differently here; section list and Rich build number tell them
   apart at a glance.
3. **An A/B that changes two variables is not an A/B.** Before running one, list the
   variables and confirm each is held constant — including machine state (adapter count,
   netenv install order).
4. **Count log categories by their category column, index 4, never by substring.**
   `bind_skipped` contains `bind`.
5. **Record the `ADAPTER` section of every run.** Every captured run shows either all real
   adapters or only `Fake Ethernet`, never a mix, and the split does not track the DLL
   version. Until that is pinned down, any single-machine A/B is suspect.
6. **Compare binaries shift-insensitively.** A position-wise byte percentage cannot
   distinguish an insertion from a rewrite. Use word multisets and string sets.
7. **Check `e_lfanew` before comparing sections.** If it differs, the header has shifted;
   subtracting that from section *content* offsets gives a false match rate. Compare at
   each section's own raw pointer.
8. **Distinguish source-level statements from behavioural ones.** A diff that does not
   touch a function is a reason to suspect, never an alibi.
9. **Derive a cell's provenance from the artifact, not its filename.** W10 was caught only
   because a log's *contents* contradicted the label the record had given it. Before
   relying on a cell, assert which build produced it from an artifact-visible property —
   a section list, a Rich build number, a string that only one revision can emit.

## Unresolved, and deliberately so

- **Which build property decides the bind** (CRT 27412 vs 33145, `.fptable`/CFG metadata,
  linker, or code layout). The build is established as the variable; the mechanism is not.
  Using a CI-built DLL reproduces the binding behaviour, so this does not gate the ports.
- The writer of `*( *(*(client+0xb4) + 0xc) + 0x50 )`, the guarded field in `FUN_00a56010`.
- Whether the netenv install-order race is deterministic.
- Whether engaging interface forcing improves any real session. That the pin *engages* is
  proven; that engaging it *helps* is not.
