# netenv takeover: design record

**Status: agreed direction, implementation in progress on `feature/netenv-takeover`.**
This document is the decision record. `docs/adapter-selection.md` holds the evidence it is
built on.

## 1. The decision

`chusan_network_hook` takes over the job segatools' `[netenv]` does, so that a user who
installs the hook keeps working **with the stock `segatools.ini` unmodified**, and so that
network problems surface as a startup diagnostic instead of as a silent failure deep
inside the game.

The takeover has three parts:

1. **Read `segatools.ini`** — `[netenv]` and `[keychip]` — so the default configuration is
   honoured without the user editing anything.
2. **Choose a real interface** by address, name or index, and read the rest of the
   adapter's properties from the live stack instead of declaring them.
3. **Present that interface to the game** through `GetAdaptersInfo`,
   `GetAdaptersAddresses` and `GetIfTable`, normalised to what the game accepts.

## 2. Why not simply mirror netenv

netenv conflates two responsibilities:

| responsibility | verdict |
|---|---|
| make an adapter acceptable to the game (`Type == 6`) | **necessary** — see below |
| invent the address, index and prefix | **harmful** — replace with the real ones |

The invented identity is harmful for three measured reasons:

- `bind()` to an address no adapter owns fails with `10049 WSAEADDRNOTAVAIL`, so the fake
  address is only safe when it happens to equal a real one. In the captured sessions it
  did — `192.168.139.17` was really owned by ZeroTier — which is why the setup worked and
  why the fragility was invisible.
- `IP_UNICAST_IF` is an interface **index**. Feeding it netenv's hardcoded `1` pins
  nothing (`netenv.c:253`); the real index is the only value that works.
- netenv patches `GetAdaptersAddresses` process-wide, which is what derailed this hook's
  own interface resolution and produced the "CI build binds, local build does not"
  mystery. Two components patching the same API with no arbitration is the root defect.

So the rule is **normalise, do not fabricate**: keep the real `IfIndex`, the real IPv4, the
real prefix and the real MAC; change only the fields the game refuses.

## 3. What the game actually demands

Established by disassembly, see `adapter-selection.md` §2 and §7:

| consumer | acceptance rule |
|---|---|
| `chusanApp.exe` (x86) | `IP_ADAPTER_INFO.Type == 6` and nothing else |
| `amdaemon.exe` (x64) | rejects `Type` 1 and 24, accepts 71 (Wi-Fi) with a larger budget |

Consequences:

- An **Ethernet** NIC needs no rewriting at all.
- A **Wi-Fi** NIC (`IF_TYPE_IEEE80211` = 71) is refused by the game but accepted by the
  daemon; presenting it as `Type = 6` is the one rewrite that is actually required.
- A **loopback** adapter is refused by both (`Type` 24). Presenting it as `Type = 6` is
  opt-in only (`allowLoopback`), because doing it by default would make the game treat
  `127.0.0.1` as a LAN peer and broadcast to it.

The daemon additionally looks adapters up **by `IfIndex`** through a second API
(`amdaemon.exe` `FUN_1402f7340`). Returning the real index keeps that lookup valid without
having to fake a second API in lockstep — the strongest argument for real indices.

## 4. Configuration

Everything new is optional. With no edits at all the hook behaves as before.

```ini
[network]
; 1 = take over interface presentation and pinning
enable=1
; Empty = decide automatically (see §5). Accepts an address, a friendly name, or an index.
interface=
; auto | native | compat.  auto is the default and picks per §5.
mode=auto
; 1 = present only the chosen adapter. Deterministic; matches what netenv did.
exclusive=1
; 1 = also present loopback as an accepted adapter. Off by default; see §3.
allowLoopback=0
; 1 = also pin directed subnet broadcasts (a.b.c.255), not just 255.255.255.255.
forceDirectedBroadcast=1
forceLimitedBroadcast=1
forceTcpSource=1
strict=1

[segatools]
; Empty = search beside the DLL, one level up, and beside the executable.
path=
```

## 5. Resolution order (`mode=auto`)

1. `[network] interface` — address, name or index, if set.
2. `[keychip] subnet` + `[netenv] addrSuffix` from `segatools.ini`, giving the address the
   game was told to expect. If a real adapter owns that address, use it. **This is the
   common case** and it is what makes the stock configuration work unchanged.
3. A real adapter whose IPv4 falls inside `[keychip] subnet`.
4. The only adapter with a routable IPv4 (excluding APIPA `169.254/16` and loopback).
5. Nothing usable → if `[netenv] enable=1`, fall back to `mode=compat` and say so loudly;
   otherwise fail the preflight.

`mode=native` skips 5 (never fabricates). `mode=compat` reproduces netenv's synthetic
adapter exactly, for hosts where no acceptable NIC exists.

## 6. Preflight diagnostics

The hook refuses to start quietly. Before the game runs, it reports:

- which `segatools.ini` was found, and whether `[netenv] enable` is 1;
- the subnet and `addrSuffix` read from it, and the resulting expected address;
- the resolved adapter: name, IPv4, mask, prefix, `IfIndex`, `IfType`;
- whether any field is being rewritten, and which;
- every problem as an explicit `ERROR` line with the fix, never a silent fallback.

Problems that must be reported rather than tolerated:

| condition | report |
|---|---|
| expected address not owned by any adapter | name the subnet and the suffix that produced it |
| `[keychip] subnet` is not the LAN's subnet | say so, and name both |
| no acceptable adapter | say why each candidate was rejected |
| `segatools.ini` absent | say that `mode=auto` is using a real adapter instead |
| `[netenv] enable=1` and this hook active | say the two would fight, and which one is in charge |

## 7. Load order

The previous implementation installed its hooks on a worker thread, so whether it won the
race against the game's first enumeration depended on timing — the unexplained variable in
`docs/broadcast-interface-regression.md`. Interface presentation cannot tolerate that: a
late hook means the game already enumerated the real list.

The adapter hooks are therefore installed **synchronously in `DllMain`**, before the
worker thread that does logging exists. Only the parts that may allocate, open files or
call into the loader stay on the thread.

## 8. Egress

Pinning works on the real stack, so it is unchanged in mechanism and now correct in value:

- `IP_UNICAST_IF` with the **real** index, for limited *and* directed broadcast;
- source bind to the **real** address for outbound TCP;
- loopback peers left alone, so the local Join Party path keeps working.

`netenv`'s `redirectBroadcast` (rewriting `a.b.c.255` to `255.255.255.255`) exists only to
paper over a subnet mismatch. When the presented subnet is the real one, the directed
broadcast is legitimate and no rewrite is needed. The old `limited_broadcast_target()`
matched `255.255.255.255` only, which is why the pinning never engaged on real sessions
that addressed `192.168.139.255`.

## 9. DNS

netenv does not intercept name resolution; that is `[dns]` in segatools
(`common/hooklib/dns.c`), enabled independently and still active with `[netenv] enable=0`.
What netenv *does* control is the adapter's DNS **server list**, which `chusanApp` reads
through `FirstDnsServerAddress` while enumerating. This hook keeps the real list when the
adapter has one and falls back to the `[netenv] routerSuffix` address when it does not,
which is the only value netenv ever reported. See `adapter-selection.md` #10.

## 10. Out of scope

- LAN Install virtualisation (`[lanInstall]`) is unchanged.
- No packet payload rewriting. The address the game serialises into its packets must be
  reachable on the chosen interface, which the preflight now checks.
`</content>
