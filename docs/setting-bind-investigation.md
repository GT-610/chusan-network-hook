# The Setting bind: resolved

**Resolved 2026-10-13 17:00. The CI-built Port 1 artifact binds.** The bind difference is a
property of the **DLL build**, not of the source. `74141ba`'s code is exonerated.

This is the live record. The queue is in [`porting-plan.md`](porting-plan.md); the
withdrawn claims are in [`lessons.md`](lessons.md).

## 1. The answer

In a Child session with no Parent present, whether `chusanApp.exe` binds its Setting UDP
socket to `192.168.139.17:50201` depends on **how the DLL was built**, not on which source
it was built from. The two Port 1 runs below use byte-identical `src/` and reach opposite
outcomes.

Consequence: the archived branch's bind failures were observed only with **locally built**
DLLs, and local builds of unrelated source fail the same way. The branch was therefore never
shown to cause them.

## 2. The completed table

| | CI-built | locally built |
|---|---|---|
| **v0.1.0 / `main`** | **binds** (`log_v0.1.0/..._093817_pid25188`) | not measured |
| **Port 1** | **binds** (`0032f83_release_logs/..._165904_pid26196`) | does not bind (`log_port1/..._094037_pid22192`) |

**The Port 1 row is the load-bearing one, and both its cells are independently verified**
(§3.1). The v0.1.0 row is corroborating: it agrees, and its provenance is consistent, but
the DLL behind `log_v0.1.0` was never retained, so it cannot be hashed after the fact.

The earlier "v0.1.0 locally built" cell was never measured — see §5.

### The Port 1 row, in full

CI-built (`0032f83_release_logs`), twice, ~20.8 s apart:

```
SOCKET +84567.000ms  api=socket af=2 type=2 protocol=0 result=5452 error=0/OK
BIND   +84570.415ms  bind sock=5452 af=2 requested=192.168.139.17:50201 namelen=16 result=0 error=0/OK
NET    +84573.330ms  bind sock=5452 service=SETTING local=192.168.139.17:50201 result=0
...
SOCKET +105328.075ms api=socket af=2 type=2 protocol=0 result=5244 error=0/OK
BIND   +105331.273ms bind sock=5244 af=2 requested=192.168.139.17:50201 namelen=16 result=0 error=0/OK
```

Locally built (`log_port1`), the same loop at the same cadence, with the bind absent:

```
SOCKET +74120.787ms  api=socket af=2 type=2 protocol=0 result=5820 error=0/OK
SOCKET +94804.968ms  api=socket af=2 type=2 protocol=0 result=5216 error=0/OK
```

That is 20.7 s of further log after the first socket with no `bind` — not a truncated
capture.

## 3. Why this is now a valid A/B

- **Source is identical.** `git diff 74141ba 0032f83 -- src/` and
  `git diff 74141ba HEAD -- src/` are both empty. The CI artifact was built from `0032f83`;
  the local DLL from the same `src/`.
- **Same machine, same day, same configuration.** Byte-identical `CONFIG` lines:
  `force_limited_broadcast=1`, `interface_address=192.168.139.17`, `strict=1`.
- **Same runtime environment.** 13 real adapters and **no `Fake Ethernet`** (netenv
  inactive) in both; Child mode in both; the same ~20.7 s retry cadence.
- The only remaining difference is the DLL build.

The adapter sets differ in exactly one address, the DHCP-assigned
`vEthernet (Default Switch)` (`172.23.16.1` at 09:3x, `172.25.160.1` at 16:59). It is
neither the interface in use nor a route to it.

### 3.1 Both Port 1 cells are independently verified

The two Port 1 cells are the ones the conclusion rests on, so each build is pinned by two
independent facts rather than by a filename:

| | `log_port1` (does not bind) | `0032f83_release_logs` (binds) |
|---|---|---|
| captured | 09:40:37 | 16:59:04 |
| CI artifact mechanism existed? | **no** — `build-artifact.yml` reached `main` at 10:54:09 | **yes** — `0032f83_release/` downloaded 10:57:41 |
| therefore | local build | CI build |
| corroborating DLL property | local builds have no `.fptable`, CRT 27412 | artifact is 185856/150528 B with `.fptable`, CRT **33145** |

The timeline alone forces it: at 09:40 there was no workflow that could produce a CI build of
a branch, so that DLL must be local. At 16:59 the artifact existed and its hashes match the
directory. The DLL properties agree independently.

### Machine state is ruled out by the capture order

The four Child captures, in clock order, with the Setting bind result:

| time | build | 50201 bind |
|---|---|---|
| 09:30:37 | local (Port-1 era) | no |
| **09:38:17** | **CI v0.1.0** | **yes** |
| 09:40:37 | local Port 1 | no |
| 16:59:04 | CI Port 1 | **yes** |

The 09:38 CI run binds *between two local runs that do not*, two minutes apart on the same
machine, same adapters, same `ini`. Any "the machine drifted", "the adapters changed",
"something was still running" explanation has to make the state flip on and off again
within four minutes and then back seven hours later — while tracking the DLL build exactly.
The build is the variable.

## 4. The build difference, measured

| | CI (`0032f83_release`) | local (`build/`) |
|---|---|---|
| x86 size | 150528 | 134656 |
| `.text` | 104832 | 90119 |
| sections | `.text .rdata .data .fptable .reloc` | `.text .rdata .data .reloc` |
| static CRT (Rich) | **33145** | **27412** |
| linker (Rich) | 35229 | 35228 |

Both are `/O2 /MT /W4` from the same `build.bat` (blob `e7421213e9` throughout). The
compiler and linker differ, which is where `.fptable` and the size gap come from.

**Which of these properties decides the bind is not established.** It is not needed to
close the question: the build is the variable, and using a CI-built DLL reproduces the
binding behaviour.

## 5. Corrections this measurement forced

1. **`log_5` is mislabelled in the earlier record.** It was called "locally built v0.1.0".
   Both halves of that are wrong, and each is provable from the artifacts:

   - **Not v0.1.0.** Its amdaemon log contains `bind_virtualized`, a string introduced
     **only** by `74141ba`. A DLL that does not contain the literal cannot emit it.
   - **Not a CI build.** It was captured 09:30:37, *before* `74141ba` was even committed
     (09:32:10) and well before `build-artifact.yml` reached `main` (10:54:09) — the only
     way to obtain a CI artifact. So it is a local build of the working tree that became
     `74141ba`.

   It also ran `force_limited_broadcast=0`, so it is not comparable to the `flb=1` group
   regardless. Net effect: the "v0.1.0 / locally built" cell has **never been measured**.
   The earlier document asserted it on the strength of a filename.
2. **Every archived-branch test binary was local.** All nine DLLs in `artifacts/` lack
   `.fptable`, i.e. none is a CI build. The branch's "3 runs lost the bind" were three local
   runs.
3. **The confounded 2026-10-13 read is superseded, not merely withdrawn.** It compared CI
   v0.1.0 against local Port 1 — code *and* build at once. The Port 1 row replaces it with
   the same comparison at one variable.

## 6. Not established

- **Which build property decides it** (CRT version, `.fptable`/CFG metadata, linker, or
  code layout). Recorded as an open question; it does not gate anything.
- Whether the pre-`db6d49a` local runs that "bound" (e.g. the archived
  `bisect_logs/..._015429`, now deleted) are reproducible. The archive itself flags that run
  as confounded (13 real adapters vs `Fake Ethernet`).
- The writer of `*( *(*(client+0xb4) + 0xc) + 0x50 )`, the game-side guard on the bind path
  in `FUN_00a56010`. Still unidentified, and no longer needed for this question.

## 7. Standing facts (independently verified, not causes)

- **`netenv` hardcodes the values the hook needs.** `references/segatools/common/platform/netenv.c:253`
  sets `IfIndex = 1`; lines 301/306 set the prefix to 24. The game sends Setting/Party/
  Advertise to the directed broadcast `192.168.139.255`. `limited_broadcast_target()` matches
  only `INADDR_BROADCAST`, so **it can never fire**. A real egress bug, and what Port 2 fixes.
  Independent of the bind question, and unaffected by this finding.
- **No captured session shows a Child receiving `SettingHostAddress`**, with either version.
  Still true, and still the reason `broadcast_target()` is not adopted on its own merits.
- **The `10013/WSAEACCES` failures in some logs are port exclusion.** No excluded range covers
  50200-50202 on this host and `winnat` is stopped, so it does not apply here.

## 8. Artifacts

All under `references/issues/`, indexed in `references/issues/README.md`.

| artifact | build | outcome |
|---|---|---|
| `log_v0.1.0/` | CI (per its label; DLL not retained, not independently verified) | binds |
| `log_5/` | **local, Port-1 era, `flb=0`** | no bind |
| `log_port1/` | **local**, Port 1, `flb=1` | no bind |
| `0032f83_release/` + `_logs/` | **CI**, Port 1 (hashes + `.fptable` + CRT 33145) | **binds** |

`main` carries `.github/workflows/build-artifact.yml`, which builds any branch on demand and
uploads an artifact without creating a release. **Use CI artifacts for any A/B.**

## 9. Tools

- [`porting-plan.md`](porting-plan.md) — the port queue and the rules for running an A/B.
- [`lessons.md`](lessons.md) — withdrawn claims, method rules, and the pitfalls behind them.
- [`archive-evidence.md`](archive-evidence.md) — the preserved raw evidence from the branch.
- `tools/dump_rich.ps1` — decodes the PE Rich header (toolchain fingerprint). This is what
  separates a CI build from a local one; run it before any comparison.
- `tools/dump_imports.ps1` — decodes the PE import directory.
- `tests/probe_resolve.cpp` — loads a hook DLL into a probe process and prints the resulting
  log, isolating interface resolution from the game.
- `tests/probe_iat_race.cpp` — polls `GetAdaptersAddresses` after `LoadLibrary` and reports
  when netenv's synthetic adapter first appears.

The PowerShell tools need `pwsh`; Windows PowerShell 5.1 cannot parse them.
