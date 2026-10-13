# Archive evidence: broadcast interface resolution

> **Preserved evidence, not a live conclusion set.** The findings in §2 are verified and
> still stand. The causal claims in §1 and §3 are **withdrawn** — the comparisons below
> varied the code and the toolchain at once, so they support no causal conclusion. See
> [`lessons.md`](lessons.md) for the full list and
> [`setting-bind-investigation.md`](setting-bind-investigation.md) for the current state.
>
> Kept for the raw evidence it contains: the per-commit summary, the 18-log matrix, and
> the clock-jump analysis in §4 that rules out cross-machine delivery.

**Status: archived. The changes described here are not on `main`.**

An investigation into broadcast interface pinning across nine commits on the
`fix-broadcast-interface-resolution` branch (`db6d49a` .. `0dfd786`). The work is
preserved because the underlying findings are solid and reusable; the code changes were
never shown to improve a real session. Porting is tracked in
[`porting-plan.md`](porting-plan.md).

The archive tag is `archive/fix-broadcast-interface-resolution`. Per-commit DLLs can be
rebuilt with `bisect_build.bat` into `artifacts/<short-sha>/`.

## 1. What the branch changed

`git diff v0.1.0 0dfd786 --stat`:

| file | change |
|---|---|
| `src/interface_resolution.h` | new, 106 lines: pure decision helpers |
| `src/network_hook.cpp` | +285 lines |
| `tests/smoketest.cpp` | +463 lines |
| `README.md`, `build.bat`, `.github/workflows/release.yml` | build and docs |

Two behavioural changes, both confined to `resolve_network_interface()` and to the
`hook_sendto` / `hook_wsasendto` broadcast-matching call sites:

1. **Accept the directed subnet broadcast, not just the limited broadcast.**
   `limited_broadcast_target()` matched `INADDR_BROADCAST` only. It was renamed to
   `broadcast_target()` and now also matches the configured interface's own
   subnet broadcast derived from the real netmask.

2. **Resolve the interface index through APIs `netenv` does not hook.**
   `GetAdaptersAddresses` reports a synthetic adapter; the index and prefix are
   now taken from `GetIpAddrTable`, cross-checked against `GetBestRoute2`, and
   validated with `GetIfEntry`.

`hook_socket`, `hook_bind`, `hook_listen`, `hook_connect`, `install_iat_hooks`,
`g_hooks[]` and `DllMain` are untouched between `v0.1.0` and `0dfd786`: none of
those identifiers appear anywhere in `git diff v0.1.0 0dfd786 -- src/`. The only
hunks are in `resolve_network_interface()`, the new `lookup_real_ipv4_interface()`,
`broadcast_target()`, `network_failure()`, `ensure_broadcast_interface()`,
`hook_sendto()` and `hook_wsasendto()`.

**What this does and does not license.** It is a *source-level* statement: the branch
did not edit the bind path. It is not a *behavioural* statement. A runtime difference
between a CI-built binary and a locally built binary of comparable source cannot be
excluded by a source diff, and the one A/B that seemed to demonstrate this
(§3.5, §4) in fact compared binaries from different toolchains and supports no such
inference. Treat it as a reason to suspect the source, never as an alibi. See
[`lessons.md`](lessons.md) W1.

## 2. Verified findings

These hold independently of whether the branch is ever revived.

### 2.1 `netenv` hardcodes the values the hook needs

`references/segatools/common/platform/netenv.c`:

- line 253: `env->head.IfIndex = 1;`
- line 301: `env->iface.OnLinkPrefixLength = 24;`
- line 306: `env->prefix.PrefixLength = 24;`

`netenv` hooks `GetAdaptersAddresses`, `GetAdaptersInfo`, `GetBestRoute` and
`GetIfTable` (lines 130-152) via `hook_table_apply(NULL, ...)`, i.e. across every
loaded module. Any code that trusts the enumerated `IfIndex` for
`setsockopt(IP_UNICAST_IF)` will pin traffic to an index that does not exist in
the real stack. `IP_UNICAST_IF` wants the index in **network byte order**;
getting that wrong silently selects the wrong adapter.

`GetIpAddrTable`, `GetBestRoute2` and `GetIfEntry` are *not* in netenv's hook
table. That is what the branch exploited — but note this is a coincidence of the
current segatools release, not a contract.

### 2.2 Game traffic goes to the directed broadcast, not the limited one

Every `ROUTE` line recorded against a real session shows the game addressing
`192.168.139.255`, e.g. from `logs_3/B_main`:

```
ROUTE destination=192.168.139.255:50201 result=0 best_if_index=20 source=192.168.139.18:0 route_metric=256
```

`v0.1.0`'s `limited_broadcast_target()` therefore never fired. Across all six
`v0.1.0` logs in `references/issues`, `action=force_broadcast` appears **zero**
times. Across the branch's chusanApp logs it appears 2-3 times, with
`matched=directed`:

```
INTERFACE action=force_broadcast socket=3448 service=SETTING port=50201 address=192.168.139.18 if_index=20 matched=directed result=0
```

So on a machine where the configured address is reachable, the branch does
engage, and it corrects the index from netenv's `1` to the real `20`.

### 2.3 Port exclusion is a separate, dominant failure

`references/issues/network_hook_logs/network_hook_20261010_235400_pid22928.log`
contains **99 consecutive bind failures, all `10013/WSAEACCES`**, on
`0.0.0.0:50201` and `0.0.0.0:50200`:

```
NET bind sock=3388 service=SETTING local=- remote=- target=0.0.0.0:50201 result=-1 error=10013/WSAEACCES
```

`10013` is `WSAEACCES`, which on Windows means the port falls inside a reserved
or excluded port range — not that it is occupied (`10048`) and not that the
address is unavailable (`10049`). Exclusion ranges are **per protocol**, which is
why 50201 can work for UDP and fail for TCP on the same host. The remedy is to
remove the range (or stop `winnat`), never to add one.

This was the actual cause of one machine's failure and is unrelated to this
branch.

## 3. Open problem: the Child's Setting bind

### 3.1 The observation

`v0.1.0` in Child mode creates the Setting UDP socket and binds it to the
interface address ~3-4 ms later:

```
SOCKET  +80322ms  api=socket af=2 type=2 protocol=0 result=6032
NET     +80327ms  bind sock=6032 service=SETTING local=192.168.139.17:50201 result=0
```

With the branch, in three separate runs, the socket appears but the bind does
not, and the 20.6 s retry cadence is unchanged:

```
SOCKET  +65432ms  api=socket af=2 type=2 protocol=0 result=5828
SOCKET  +86088ms  api=socket af=2 type=2 protocol=0 result=5828
```

All four of those captures are `writeFile=1` complete file logs, so this is not
console line loss.

The two calls the game makes here, from `FUN_00a56010`:

```cpp
cVar1 = thunk_FUN_00a79710(addr, port);   // socket() + setsockopt(SO_BROADCAST) — no bind
if (cVar1 != '\0') {
    iVar4 = thunk_FUN_007e42a0();
    if (iVar4 != 0) thunk_FUN_00a79b80(iVar4, port);   // socket() + bind(iface:port)
}
```

The failing logs contain only the first socket, which is consistent with
`FUN_00a79710` having run and the guarded `FUN_00a79b80` not having run. That is
suggestive, not conclusive.

### 3.2 Counter-evidence that rules out the obvious explanations

Both `logs_2/B_host` and `logs_3/B_main` are **Parents** captured with the
branch, `forceLimitedBroadcast=1`, and netenv already hooked (their `ADAPTER`
section lists only `Fake Ethernet`). They bind `0.0.0.0:50201` + `listen`
**successfully**, 26 and 14 times respectively.

So under identical DLL, identical ini and identical netenv timing:

| role | bind `0.0.0.0:50201` | bind `<iface>:50201` |
|---|---|---|
| Parent | 26 / 14 OK | — |
| Child | — | 0 in 3 runs |

This rules out "netenv hooking breaks our bind" and "`forceLimitedBroadcast=1` breaks our
bind" **as blanket explanations for a Parent-vs-Child difference within one run**. Note
carefully what it does *not* do: the Parent and Child runs in this table share a DLL, so
this comparison cannot address which DLL is responsible across runs. That question is
unresolved — see §3.5 and [`lessons.md`](lessons.md).

### 3.3 A confounded experiment

Setting `forceLimitedBroadcast=0` restored the Child's bind
(`bisect_logs/..._015429`). But that run's `ADAPTER` section lists **13 real
adapters**, not `Fake Ethernet` — meaning netenv had not yet hooked when the log
ran, where the failing runs all show `Fake Ethernet`. Two variables changed at
once, so this does not isolate `forceLimitedBroadcast`.

Note also that `forceLimitedBroadcast` only gates `ensure_broadcast_interface()`,
which is called exclusively from `hook_sendto` / `hook_wsasendto`. The failing
Child logs contain no `NET sendto`, no `ROUTE` and no `force_broadcast` line at
all before the socket appears, so that code path never ran in them.

## 4. Evidence matrix

All 18 hook logs in `references/issues`, ordered by DLL.

| log | proc | DLL | flb | ADAPTER | bind 50201 |
|---|---|---|---|---|---|
| `logs_4/..._224949_pid10436` | chusanApp | v0.1.0 | 1 | 14 real | 2 OK |
| `bisect_logs/..._005404_pid21292` | chusanApp | v0.1.0 | 1 | 14 real | 2 OK |
| `network_hook_logs/..._235400_pid22928` | chusanApp | v0.1.0 | 1 | 1 fake | 99 ERR (`10013`) |
| `logs_2/..._214740_pid16132` | chusanApp | branch | 1 | 1 fake | 0 |
| `logs_3/..._223601_pid8684` | chusanApp | branch | 1 | 1 fake | 0 |
| `bisect_logs/..._005605_pid18328` | chusanApp | branch | 1 | 1 fake | 0 |
| `logs_2/..._213331_pid23348` | chusanApp | branch | 1 | 1 fake | **26 OK** (Parent) |
| `logs_3/..._222903_pid5808` | chusanApp | branch | 1 | 1 fake | **14 OK** (Parent) |
| `bisect_logs/..._015429_pid9752` | chusanApp | branch | **0** | 13 real | 2 OK |
| the six amdaemon logs | amdaemon | both | 1 | mixed | n/a |

### No session shows the Child receiving `SettingHostAddress`

No `.17` process in any captured log ever received a `SettingHostAddress`. The
Child in `logs_2/..._214740_pid16132` produces two bare `SOCKET` lines and
nothing else. `logs_4/..._224949_pid10436` ends its two bind cycles with
`tx_bytes=0 rx_bytes=0`.

The Parent in `logs_2/..._213331_pid23348` does receive 146 `SettingHostAddress`
frames "from" `192.168.139.17`, but read the wall clock carefully: the game's
in-process UTC+9 hook jumps the displayed time by one hour right after startup
(first line `21:33:31`, second line `22:33:32`, `+281ms` later). Those 146 frames
are stamped `22:34:39`-`22:42:03`, i.e. **real 21:34-21:42** — before the `.17`
Child even started at 21:47:40. They are the `.18` host's own broadcast, re-seen
by the `.18` listener (`remote=192.168.139.18:63789` in the first frames). They
are not evidence of cross-machine delivery.

The Party handshake in the same Parent log (`RequestJoin` -> `JoinResult` ->
heartbeats) is entirely over `127.0.0.1:50200` <-> `127.0.0.1:55446`, and its
`StartRecruit` frames come from `192.168.139.18:50367`, i.e. itself. It is a
loopback self-test, not a two-machine session.

So across every available capture there is **no evidence that the Child ever
received the Parent's `SettingHostAddress`**, with either DLL version. The one
question that matters for the original symptom is unanswered by this data set.

## 5. Tools preserved

- `bisect_build.bat` — builds one x86+x64 DLL pair per commit in
  `v0.1.0..HEAD` into `artifacts/<short-sha>/`. Extracts each commit's source
  with PowerShell because the host has no `tar`.
- `build_dll_only.bat` — builds both DLLs without the smoke tests, for fast
  drop-in replacement.
- `tests/probe_resolve.cpp` — loads a hook DLL into a probe process, lets it
  resolve the interface, and prints the resulting log. Isolates interface
  resolution from the game.
- `tests/probe_iat_race.cpp` — polls `GetAdaptersAddresses` at 0/10/50/100/250/
  500/1000/2000 ms after `LoadLibrary` and reports when netenv's synthetic
  adapter first appears. This is the instrument for the netenv install-order
  race.

Build a probe with:

```bat
cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS tests\probe_resolve.cpp ^
  /link ws2_32.lib iphlpapi.lib
```

## 6. If this is picked up again

In rough priority order:

1. **Make `hook_bind` log unconditionally.** Today `log_io()` returns early when
   the port is not one of 50200/50201/50202/40110/40112, so "the game never
   called bind" and "bind was called with an unexpected address" are
   indistinguishable in the captured logs. One unconditional line per bind would
   settle §3.1 immediately.
2. **Establish whether the netenv install order is deterministic.** Every
   captured run either lists all real adapters or only `Fake Ethernet`, never a
   mix, and the split does not track the DLL version alone. `probe_iat_race.cpp`
   measures it. Until this is pinned down, any A/B on one machine is suspect.
3. **Stop trusting `GetIpAddrTable` / `GetBestRoute2` / `GetIfEntry` as
   "unhooked".** They happen to be unhooked in the current segatools. The
   cross-check design in `interface_resolution.h` is the right shape; the API
   choice needs a comment tying it to a segatools version.
4. **Do not adopt `broadcast_target()` on the strength of §2.2 alone.** That the
   pin engages is proven; that engaging improves anything is not. No captured
   session shows a Child receiving `SettingHostAddress`.

## 7. Why it was not merged

- The branch never produced a session with non-zero receive on the Child.
- Three Child runs with the branch lost the Setting bind; two Parent runs did
  not. The mechanism is unexplained, and the branch is not established as the cause —
  nor exonerated. See [`lessons.md`](lessons.md).
- The originating failure was the port exclusion in §2.3, which this branch does
  not address.
- `main` is `3d5e6df`, one packaging commit past `v0.1.0`. Its DLL behaviour is
  that of `v0.1.0`.
