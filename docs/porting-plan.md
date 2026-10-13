# Porting plan: `fix-broadcast-interface-resolution` onto `main`

Branch `port/broadcast-interface-resolution`. One port per commit, in dependency order,
each verified on-machine before the next starts.

Context: [`setting-bind-investigation.md`](setting-bind-investigation.md) for the state
of the bind question, [`lessons.md`](lessons.md) for the rules any A/B must follow.

## Why these ports exist

The archived branch's diagnosis is **correct and independently confirmed**:
`limited_broadcast_target()` matches only `INADDR_BROADCAST`, but the game sends to the
directed broadcast `192.168.139.255`, and `netenv` reports a synthetic adapter
(`IfIndex = 1`, prefix 24). So interface forcing **never engages**. `force_broadcast`
appears 0 times across the `v0.1.0` logs.

That is a real egress bug, independent of the bind question. These ports fix it.

| # | from | port | note |
|---|---|---|---|
| 1 | — | trace every bind and socket unconditionally | **done and verified** — CI artifact binds, see below |
| 2 | `db6d49a` | accept the directed subnet broadcast; take the ifindex from `GetIpAddrTable` | the actual fix |
| 3 | `736c485` | cross-check across `GetIpAddrTable`/`GetBestRoute2`/`GetIfEntry`; refuse loopback | needs `src/interface_resolution.h` |
| 4 | `c620b75` | also accept the netenv-style `/24` form | |
| 5 | `0dfd786` | log which broadcast form matched; per-socket reuse | meaningful after 2 |
| 6 | `cfdebf4` | smoke-test assertions for interface pinning | |
| 7 | `4389370` | unit-test the decision table | |
| 8 | `493436c`, `6fa6a88` | docs, `build.bat` include path, CI steps | |

Ports 2-5 are behaviour changes and each needs an on-machine capture showing
`INTERFACE action=force_broadcast ... matched=<form>`. Ports 6-7 are the tests that make
them defensible without a machine.

### Port 1's verdict

The CI-built Port 1 artifact was run (`0032f83_release_logs`). It **binds** 50201 twice,
exactly as CI v0.1.0 does, and its only new lines are the `BIND` traces Port 1 adds. Against
the locally built DLL from byte-identical source — which does not bind — that is a
one-variable comparison, and it clears Port 1's code.

It also clears the archived branch generally: the branch's observed bind failures were all
produced by **local** builds (all nine DLLs in `artifacts/` lack `.fptable`), and a local
build of unrelated source fails identically. See
[`setting-bind-investigation.md`](setting-bind-investigation.md) §2 and §5.

**The diagnostic goal is met without another bisect**: a captured log now distinguishes
"the game never called bind" from "bind was called with an unexpected address".

## What was done differently

- One concern per commit, each building and smoke-testing on its own, so a regression is
  attributable to a single change.
- The diagnostic gap was closed **first**, before any behaviour change, so the next run
  answers the bind question without another bisect.
- The API choice is not "unhooked by segatools" but a different question asked of a
  different API — the right shape for a hook that coexists with segatools. The
  cross-check refuses to fall back to a virtualized index when no source answers.
- The decision table was extracted into `src/interface_resolution.h` as a pure function,
  which is what makes it testable without reproducing segatools' install race in a test
  process. This is what made the branch's logic reviewable at all.

## Per-commit verdicts

No commit on the archived branch is wrong on its own. The branch failed as a *method*, not
as a set of changes — see [`archive-evidence.md`](archive-evidence.md) §4.

| # | sha | purpose | verdict |
|---|---|---|---|
| 1 | `db6d49a` | accept the directed subnet broadcast; take the ifindex from `GetIpAddrTable` | port — the actual fix |
| 2 | `cfdebf4` | assert interface forcing in the smoke test | port |
| 3 | `493436c` | document directed broadcast; CI runs forcing against a real address | port |
| 4 | `736c485` | cross-check ifindex across `GetIpAddrTable`/`GetBestRoute2`/`GetIfEntry`; refuse loopback | port |
| 5 | `4389370` | unit-test the decision table; restructure the forcing test | port |
| 6 | `6fa6a88` | document the cross-check; `/I"%ROOT%src"` in `build.bat`; extend CI | port |
| 7 | `c620b75` | also accept the netenv-style `/24` broadcast | port |
| 8 | `0dfd786` | log which broadcast form matched; per-socket reuse logging | port |

## Building artifacts to compare

`main` carries `.github/workflows/build-artifact.yml`: trigger it from the Actions page
with a branch name, and it uploads a zip without creating a release.

```yaml
on:
  workflow_dispatch:
    inputs:
      branch: { required: true, default: main, type: string }
```

Use CI artifacts for any A/B — they share one runner image and toolchain.

**This is not a nicety.** A CI-built and a locally built DLL from byte-identical source
behave differently: the CI build binds the Setting socket, the local build does not
([`setting-bind-investigation.md`](setting-bind-investigation.md) §2). Check with
`dump_rich.ps1` — a CI build carries Rich build **33145** and a `.fptable` section; a local
build carries **27412** and no `.fptable`. A local build is fine for a drop-in smoke test,
never for an A/B.

## Environment

No excluded port ranges cover 50200-50202 on this host and `winnat` is stopped, so the
`10013/WSAEACCES` failure mode does not apply here.

Local toolchain: MSVC `cl.exe` 19.44.35228, static CRT build **27412**.

```powershell
# compare toolchain fingerprints (needs pwsh, not Windows PowerShell 5.1)
pwsh -File tools\dump_rich.ps1 -Path build\chusan_network_hook_x86.dll
```

To rebuild a historical tag locally:

```powershell
git worktree add --detach ..\wt_v010 v0.1.0
..\wt_v010\build.bat
```
