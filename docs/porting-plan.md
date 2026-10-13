# Porting plan: `fix-broadcast-interface-resolution` onto `main`

Branch `port/broadcast-interface-resolution`. One port per commit, in dependency order.
Each port is verified on-machine before the next one starts.

Read `docs/broadcast-interface-triage.md` first: it contains the per-commit verdicts
(all eight commits are worth porting) and the static-analysis finding that explains why
none of them can fix the Setting bind regression.

## Why the diagnostic comes first

The archived branch was abandoned because three Child runs lost the Setting bind and the
mechanism was never found. Reading `FUN_00a56010` settles it: the bind is guarded by a
game-side condition, and the branch never touched that code path. So the broadcast work
is worth porting on its own merits, but it is not the bind fix.

Porting it blind would repeat the original mistake. So Port 1 changes no behaviour at
all — it only closes the logging gap that made the bind question require a bisect — and
is meant to be run and inspected before anything else lands.

## Port 1 — trace every bind and every socket unconditionally

**Status: ready to verify.**

`log_io` drops any call whose port is not one of the five known services, so a captured
log could not distinguish "the game never called bind" from "the game called bind with an
address we did not expect". `broadcast-interface-regression.md` §6 named this as priority
1 and it was never done.

Adds a `BIND` category logged unconditionally from `hook_bind`, for both the real and
the virtualized (LAN Install) path, carrying the socket, `sa_family`, the requested
endpoint, `namelen`, the result and the Winsock error. `hook_socket` and `hook_wsasocketw`
comments now record why socket calls are logged unconditionally too — they already were,
but the reason was not written down anywhere.

No behaviour change: `hook_bind`'s control flow and return values are untouched.

### What to look for in the next Child run

Setting's guarded bind is `FUN_00a79b80` (`0x00a79b80`), which calls `socket(2,2,0)` and
then `bind`. The broadcast socket from `FUN_00a79710` is a *different* socket and is never
bound. So per attempt:

| observed | reading |
|---|---|
| one `SOCKET af=2 type=2`, then a `BIND` on that same socket | the guard passed and the bind ran |
| one `SOCKET af=2 type=2`, no `BIND` at all | the guard evaluated false; the game chose not to bind |
| two `SOCKET af=2 type=2` before any `BIND` | both socket objects were created |
| a `BIND` with `requested=` an address or port we did not expect | previously invisible; this is what `log_io` was hiding |

The third failing capture (`logs_3/B_guest/..._223601_pid8684.log`) shows one `SOCKET` per
retry and no `bind`, on the ~20.6 s cadence. If the new run reproduces that shape and the
`BIND` category is silent, the guard is confirmed false and the question moves to the
game's Setting configuration — the field read by
`*( *(*(client+0xb4) + 0xc) + 0x50 )`, adjacent to the bind address string at `+0x54`.

If instead a `BIND` line appears that `log_io` would have dropped, that is a different
bug and the new line is the only evidence of it.

Note that `detailed=1` in `[log]` is required for any of this to be written; with the
default `detailed=0` the lines are suppressed as usual. The captured logs in
`references/issues` were all taken with `detailed=1 writeFile=1`.

### Verified locally

Builds clean at `/W4` for x86 and x64. Smoke test passes. With `detailed=1` the new lines
appear for both paths:

```text
BIND  bind sock=360 af=2 requested=127.0.0.1:50200 namelen=16 result=0 error=0/OK
BIND  bind_virtualized sock=360 af=2 requested=0.0.0.0:40110 namelen=16 result=0 error=0/OK
```

## Remaining ports

Not started. Each depends on the one before it and gets its own verification pass.

| # | from | port | note |
|---|---|---|---|
| 2 | `db6d49a` | accept the directed subnet broadcast; take the ifindex from `GetIpAddrTable` | the real fix; the hook currently never pins anything |
| 3 | `736c485` | cross-check across `GetIpAddrTable`/`GetBestRoute2`/`GetIfEntry`; refuse loopback | needs `src/interface_resolution.h` |
| 4 | `c620b75` | also accept the netenv-style `/24` form | |
| 5 | `0dfd786` | log which broadcast form matched; per-socket reuse | only meaningful after 2 |
| 6 | `cfdebf4` | smoke-test assertions for interface pinning | |
| 7 | `4389370` | unit-test the decision table | |
| 8 | `493436c`, `6fa6a88` | docs, `build.bat` include path, CI steps | |

Ports 2-5 are behaviour changes and each one needs an on-machine capture showing the
`INTERFACE action=force_broadcast ... matched=<form>` line. Port 6-7 are the tests that
make them defensible without a machine.

## Known confounder to control for

`broadcast-interface-regression.md` §6.2: every captured run shows either all real
adapters or only `Fake Ethernet`, never a mix, and the split does not track the DLL
version. Until that is pinned down, an A/B on one machine is not an experiment. Record
the `ADAPTER` section of each run's log alongside the result, and do not attribute a
difference to a code change unless the adapter list matches across both runs.

This machine currently has no excluded port ranges covering 50200-50202
(`netsh interface ipv4 show excludedportrange`), and `winnat` is stopped, so the
`10013/WSAEACCES` failure in §2.3 of the archive record does not apply here.