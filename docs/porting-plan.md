# Porting plan: `fix-broadcast-interface-resolution` onto `main`

Branch `port/broadcast-interface-resolution`. One port per commit, in dependency order.
Each port is verified on-machine before the next one starts.

Read these two first:

- [`docs/build-toolchain-divergence.md`](build-toolchain-divergence.md) — **the blocker.**
  The v0.1.0 release binary is a CI build; a local build of the same tag behaves
  differently. Until the build is held constant, no A/B on the bind is meaningful.
- [`docs/broadcast-interface-triage.md`](broadcast-interface-triage.md) — per-commit
  verdicts (all eight commits are worth porting).

## Why Port 1 is diagnostics

The archived branch was abandoned because three Child runs lost the Setting bind and the
mechanism was never found. Port 1 changes no behaviour: it only closes the logging gap
that made the bind question require a bisect, by logging every bind unconditionally rather
than only those on the five known ports.

It is kept separate from the behaviour ports so that a later run can attribute an effect
to exactly one change.

## Port 1 — trace every bind and every socket unconditionally

**Status: built and smoke-tested locally. On-machine run done; verification incomplete.**

`log_io` drops any call whose port is not one of the five known services, so a captured
log could not distinguish "the game never called bind" from "the game called bind with an
address we did not expect". `broadcast-interface-regression.md` §6 named this as priority
1 and it was never done.

Adds a `BIND` category logged unconditionally from `hook_bind`, for both the real and
the virtualized (LAN Install) path, carrying the socket, `sa_family`, the requested
endpoint, `namelen`, the result and the Winsock error.

### What the on-machine run showed

The Child log (`references/issues/log_port1/..._094037_pid22192`) contains **zero** `BIND`
lines, while amdaemon from the same run contains 77. The category works, and the Child made
no bind call on any address or port — not `0.0.0.0`, not the virtualized one. That is what
distinguishes "no bind" from "bind we failed to log", which was the point of the port.

### What that run also showed

A more useful result than the bind itself: a controlled A/B. The CI-built v0.1.0 binds
50201 twice; the locally built Port 1 does not bind at all — under byte-identical
configuration and identical adapter enumeration. See `docs/build-toolchain-divergence.md`
§2. That comparison is what redirected the investigation, and it is why the behaviour ports
below are blocked.

## Remaining ports

Not started. Each depends on the one before it and needs its own verification pass. **All
of them are blocked on the toolchain question above**: porting behaviour changes and then
A/B-ing them against a CI-built binary would repeat the exact mistake this document exists
to prevent.

| # | from | port | note |
|---|---|---|---|
| 0 | — | reproduce the CI build locally, or build on CI | **prerequisite** |
| 2 | `db6d49a` | accept the directed subnet broadcast; take the ifindex from `GetIpAddrTable` | the real fix; the hook currently never pins anything |
| 3 | `736c485` | cross-check across `GetIpAddrTable`/`GetBestRoute2`/`GetIfEntry`; refuse loopback | needs `src/interface_resolution.h` |
| 4 | `c620b75` | also accept the netenv-style `/24` form | |
| 5 | `0dfd786` | log which broadcast form matched; per-socket reuse | only meaningful after 2 |
| 6 | `cfdebf4` | smoke-test assertions for interface pinning | |
| 7 | `4389370` | unit-test the decision table | |
| 8 | `493436c`, `6fa6a88` | docs, `build.bat` include path, CI steps | |

Ports 2-5 are behaviour changes and each needs an on-machine capture showing
`INTERFACE action=force_broadcast ... matched=<form>`. Ports 6-7 are the tests that make
them defensible without a machine.

## Rules for the next session

1. **Hash the DLL before every run.** Record `Get-FileHash -Algorithm SHA256`. A run
   without a hash cannot be compared to anything.
2. **Both sides of an A/B must come from the same build.** Not "same source", not "same
   tag" — same toolchain.
3. **Check the Rich header** (`pwsh -File tools/dump_rich.ps1`) when a build looks
   unfamiliar. The first four entries identify the CRT generation in one command.
4. **Count log categories by their category column (index 4), not by substring.**
   `bind_skipped` contains `bind`; counting substrings mixes categories.
5. **Record the `ADAPTER` section** of every run. `broadcast-interface-regression.md` §6.2:
   every captured run shows either all real adapters or only `Fake Ethernet`, never a mix,
   and the split does not track the DLL version.

## Environment notes

This machine has no excluded port ranges covering 50200-50202
(`netsh interface ipv4 show excludedportrange`) and `winnat` is stopped, so the
`10013/WSAEACCES` failure in §2.3 of `broadcast-interface-regression.md` does not apply
here.

Local toolchain: MSVC `cl.exe` 19.44.35228, static CRT build **27412**. The CI runner
produced static CRT build **33145** — see the divergence document.

Building `v0.1.0` locally reproduces the failing behaviour, which is the control the
investigation needed:

```powershell
git worktree add --detach ..\wt_v010 v0.1.0
..\wt_v010\build.bat
pwsh -File tools\dump_rich.ps1 -Path ..\wt_v010\build\chusan_network_hook_x86.dll
```

The Rich header should report CRT build 27412, matching the failing Port 1 build and
differing from the working release binary's 33145. The tools need `pwsh`; Windows
PowerShell 5.1 cannot parse them.