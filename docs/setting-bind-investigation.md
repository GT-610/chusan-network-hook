# The Setting bind: state of the investigation

**Phase closed 2026-10-13. All analysis that does not require a machine is done. The
question is now blocked on exactly one measurement.**

This is the live record. The queue of work is in [`porting-plan.md`](porting-plan.md);
the mistakes and withdrawn claims are in [`lessons.md`](lessons.md).

## 1. The question

In a Child session with no Parent present, `chusanApp.exe` creates the Setting UDP socket
but does not bind it. A Parent in the same build binds normally. In the working case
(2026-10-13, `references/issues/log_v0.1.0`) the Child bound 50201 successfully.

## 2. What is measured

| | CI-built | locally built |
|---|---|---|
| **v0.1.0 / `main`** | **binds** (`log_v0.1.0/..._093817_pid25188`) | does not bind (`log_5/..._093037_pid10836`) |
| **Port 1** | **NOT MEASURED** | does not bind (`log_port1/..._094037_pid22192`) |

The diagonal is measured. The off-diagonal cell — **CI-built Port 1** — has never been run,
and it is the only thing that separates "the code is responsible" from "the environment is
responsible". No amount of binary analysis substitutes for it.

All three compared runs used `forceLimitedBroadcast=1` with byte-identical `CONFIG`
lines and the same 13 real adapters, with no `Fake Ethernet` (netenv inactive), at the
same ~20.7 s retry cadence.

## 3. What is established

**`main` and `v0.1.0` are the same program.** CI builds of the two differ only in the PE
timestamp and the linker build number:

| | CI v0.1.0 | CI `main` |
|---|---|---|
| x86 identical bytes | — | 150497 / 150528 (99.98 %) |
| x64 `.text` identical | — | **117248 / 117248 (100 %)** |
| `.rdata` string diff | — | **none** |

On x64 `e_lfanew` also differs (`0xF0` vs `0xF8`), an 8-byte header shift from the
linker; once accounted for, the section tables are byte-identical.

**The CI Port 1 artifact is a faithful build of Port 1.** It differs from CI `main` in
83.6 % of bytes *by position*, but that is a layout shift from a code insertion:

| | x86 | x64 |
|---|---|---|
| `.text` growth | +208 bytes | +320 bytes |
| `.text` shared 4-byte words | 94.9 % | 92.3 % |
| string diff | the 2 Port 1 log strings | the same 2, plus 3 prologue artefacts |
| `.reloc` growth | +6 entries | none |

Both architectures show the same profile when `.text` is halved: the half containing the
insertion scores lower, the half after it scores higher, which is the expected signature
of an insertion.

**The toolchain is constant across CI.** All three CI artifacts use static CRT build
**33145**; this host uses **27412**. So the toolchain cannot distinguish binds from
does-not-bind between any two CI binaries. It is only a live hypothesis for CI-vs-local.

## 4. Standing facts (independently verified, not causes)

- **`netenv` hardcodes the values the hook needs.** `references/segatools/common/platform/netenv.c:253`
  sets `IfIndex = 1`, and lines 301/306 set the prefix to 24. The game sends
  Setting/Party/Advertise to the directed broadcast `192.168.139.255`.
  `limited_broadcast_target()` matches only `INADDR_BROADCAST`, so **it can never fire**.
  This is a real egress bug and is what the archived branch's first commit fixes. It is
  independent of the bind question.
- **`FUN_00a56010` structure** (`chusanApp.exe`, `0x00a56010`): `FUN_00a79710` creates a
  broadcast socket and never binds; a guard on `*( *(*(client+0xb4) + 0xc) + 0x50 )`
  gates `FUN_00a79b80`, which creates its own socket and then binds. The writer of that
  guarded field has not been identified.
- **No captured session ever shows a Child receiving `SettingHostAddress`**, with either
  DLL version.
- **The `10013/WSAEACCES` failures in some logs are port exclusion**, a different problem.
  `netsh interface ipv4 show excludedportrange` shows no range covering 50200-50202 on
  this host and `winnat` is stopped, so it does not apply here.

## 5. The one measurement that settles it

Run the **CI-built Port 1** artifact (`references/issues/0032f83_release`) on this
machine under the same conditions as the 2026-10-13 comparison. Both outcomes are
informative:

- **does not bind** → the code is responsible and the toolchain is exonerated. Port 1
  changes only logging, so the effect would be in the added bind tracing itself (an extra
  `bind` call altering timing or state).
- **binds** → the DLL is exonerated entirely; the difference is the runtime environment
  (adapter count, netenv install order, `Fake Ethernet` presence).

Record the `ADAPTER` section of the run, and hash the DLL first.

## 6. Reference artifacts

All under `references/issues/`, indexed in `references/issues/README.md`.

| artifact | build | x86 SHA256 (head) |
|---|---|---|
| `v0.1.0_release/` | CI, tag v0.1.0 | `8BCA7F78B2D916D6…` |
| `main_release/` | CI, `main` @ `01450ac` | `563B94F04D6AB1B0…` |
| `0032f83_release/` | CI, Port 1 @ `0032f83` | `356EBEAF71C55A0E…` |

Use these rather than local builds for any A/B, and hash whichever is used. Local Port 1
builds (`x86 990E96735FC84434…`, `x64 A53FCCC9587DC125…`) use CRT 27412 and are **not**
comparable to CI artifacts.

`main` carries `.github/workflows/build-artifact.yml`, which builds any branch on demand
and uploads an artifact without creating a release.

## 7. Tools

- [`porting-plan.md`](porting-plan.md) — the port queue and the rules for running an A/B.
- [`lessons.md`](lessons.md) — withdrawn claims, method rules, and the pitfalls that
  produced them.
- `tools/dump_rich.ps1` — decodes the PE Rich header (toolchain fingerprint).
- `tools/dump_imports.ps1` — decodes the PE import directory.
- `tests/probe_resolve.cpp` — loads a hook DLL into a probe process and prints the
  resulting log, isolating interface resolution from the game.
- `tests/probe_iat_race.cpp` — polls `GetAdaptersAddresses` after `LoadLibrary` and
  reports when netenv's synthetic adapter first appears. This is the instrument for the
  netenv install-order race.

The PowerShell tools need `pwsh`; Windows PowerShell 5.1 cannot parse them.
