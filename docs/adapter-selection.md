# Adapter selection and presentation: what chusanApp accepts

**Status: verified by disassembly and measurement on this host.**

This is the single reference for why the hook presents what it presents. It covers what
the game and the daemon accept, what the hook overrides, and how the two network-test
items that used to misbehave are now answered.

Everything here was established against SDHD 2.50 (`chusanApp.exe` x86, `amdaemon.exe`
x64). Addresses are file offsets in those images.

## 1. The gate: `Type == 6`, and nothing else

`chusanApp.exe` `0x01026820` — an ANY-address function not defined in the Ghidra project,
referred to here as `allnet_enumerate_adapters` — fills an adapter vector inside the
network-manager object passed in `ECX` (`+0x08` begin, `+0x0c` end). It is called from
exactly one site, `0x0044dcc5`.

It runs three passes:

| pass | API | role |
|---|---|---|
| 1 | `GetAdaptersInfo` | **the only gate** — decides which adapters exist at all |
| 2 | `GetAdaptersAddresses` | enrichment only — `OperStatus` and all unicast IPv4s |
| 3 | `GetIfTable` | enrichment only — per-index row (speed/status) |

### Pass 1

```
01026898  CALL GetAdaptersInfo            ; size probe, must return 0x6F BUFFER_OVERFLOW
010268B2  CALL operator new[]             ; buffer for the reported size
010268CD  CALL GetAdaptersInfo            ; real call, must return 0
```

Per `IP_ADAPTER_INFO` node the fields are copied out. Offsets are confirmed by the
`AddressLength`/`Address[8]` pair falling exactly where `MAX_ADAPTER_DESCRIPTION_LENGTH +
4` puts them:

| offset | field | used as |
|---|---|---|
| `+0x190` | `AddressLength` | stored |
| `+0x194` | `Address[8]` | 8-byte copy — MAC |
| `+0x19C` | `Index` | stored, also the map key |
| **`+0x1A0`** | **`Type`** | **`CMP [ECX+0x1a0], 6` — adapters that fail this are dropped** |
| `+0x1A4` | `DhcpEnabled` | numeric flag, `0` or `1`; gates the `DhcpServer` read below |
| `+0x1B0` | `IpAddressList.IpAddress.String` | parsed to a packed IPv4 |
| `+0x1C0` | `IpAddressList.IpMask.String` | parsed to a packed IPv4 |
| `+0x1D4` | `GatewayList` (i.e. its `Next`) | start of the list, handed to the parser |
| `+0x1D8` | `GatewayList.IpAddress.String` | parsed into a vector |
| `+0x200` | `DhcpServer.IpAddress.String` | copied only when `DhcpEnabled != 0` |

`DhcpEnabled` is a `BOOL`, not a string, and `+0x200` is a different field:
`01026979  CMP dword ptr [ECX + 0x1a4], 0` / `JNZ` either clears the DHCP-server slot or
duplicates the string at `+0x200`. `GatewayList` itself begins at `+0x1D4` — that is where
`Next` lives — and the enumeration code passes `+0x1D4` to the parser, which reads `+4`
from it (`thunk_FUN_01033d90(puVar3 + 1)`), so the string it actually parses is `+0x1D8`.

`0x010268F0` is `CMP dword ptr [ECX + 0x1a0], 0x6` / `JNZ skip`. `Type == 6` is
`MIB_IF_TYPE_ETHERNET`. There is **no other acceptance test** in this pass: no speed, no
`OperStatus`, no address-family check, no name matching.

### Pass 2 cannot add an adapter back

```
01026a50  MOV EAX, [ESI+0x04]      ; adapter->IfIndex
01026a61  CALL map.lower_bound / equal_range
01026a79  JZ   0x01026b00          ; not found -> skip this adapter
01026b00  MOV ESI, [ESI+0x08]      ; ESI = adapter->Next  (advance, no insert)
```

The pass is keyed on the `IfIndex` pass 1 already recorded, so an adapter that failed the
`Type == 6` gate is never enriched and never appears in the result. For adapters already
present it adds:

- `OperStatus` from `IP_ADAPTER_ADDRESSES +0x44`, normalised by `FUN_010266f0` to `0..7`
  (`1` = `IfOperStatusUp`);
- **every** unicast IPv4, by walking `FirstUnicastAddress` (`+0x1c`) and running
  `getnameinfo(..., NI_NUMERICHOST)` on each — a multi-address NIC yields several entries,
  which `GetAdaptersInfo`'s single `IpAddressList` cannot express.

### Pass 3 and ordering

`GetIfTable` rows are matched to records by `dwIndex`, then the vector is sorted with
comparator `FUN_01026640`, which compares the record's first dword — the `IfIndex`. The
result is ordered **ascending by interface index**, which is why a lower-index adapter wins
unless the hook hides it.

## 2. `amdaemon` uses a different, more permissive filter

`FUN_1402f7400` (`amyNetworkGetInterfaceInfo`) calls `GetAdaptersInfo` into a fixed `0x3000`
buffer and hands the chain to `FUN_1402f6470` (`amyNetworkAnalyzeInterfaceInfo`):

```c
iVar1 = *(int *)(adapter + 0x1a4);                       /* Type */
if (iVar1 != 0x18 && iVar1 != 1 && *(int *)(adapter + 0x194) == 6)   /* and MAC length 6 */
```

The offsets only make sense once the pointer-size shift is applied — `Next` is 8 bytes on
x64, which moves every following field by 4 relative to the x86 table above:

| field | x86 (chusanApp) | x64 (amdaemon) |
|---|---|---|
| `AddressLength` | `0x190` | `0x194` |
| `Address` | `0x194` | `0x198` |
| `Index` | `0x19C` | `0x1A0` |
| `Type` | `0x1A0` | `0x1A4` |
| `DhcpEnabled` | `0x1A4` | `0x1A8` |

Measured on both architectures; §10 records the provenance. The `0x194 == 6` test
is therefore `AddressLength == 6` (MAC length), and `0x1A4` is `Type` — not the Wi-Fi/link
field it first resembles.

| value | constant | amdaemon | chusanApp |
|---|---|---|---|
| 1 | `MIB_IF_TYPE_OTHER` | reject | reject |
| 6 | `MIB_IF_TYPE_ETHERNET` | accept | **accept (only)** |
| 24 | `IF_TYPE_SOFTWARE_LOOPBACK` | reject | reject |
| 71 | `IF_TYPE_IEEE80211` | **accept**, with a larger slot budget (`0x400` vs `4`) | reject |

So the daemon tolerates Wi-Fi and the game does not. The daemon additionally looks adapters
up **by `IfIndex`** through `GetAdaptersAddresses` (`FUN_1402f7340`), which is the strongest
argument for keeping the index real instead of inventing one.

## 3. Measured on this host

Passes 1–2 reproduced against the live stack:

| Idx | Type | Description | IP | verdict |
|---|---|---|---|---|
| 20 | 6 | Red Hat VirtIO Ethernet Adapter #2 | 169.254.158.1 | **ACCEPT** |
| 10 | 6 | Red Hat VirtIO Ethernet Adapter #5 | 172.16.10.235 | **ACCEPT** |
| 18 | 53 | TAP-Windows Adapter V9 | 0.0.0.0 | reject |
| 7 | 53 | Tailscale Tunnel | 100.76.171.50 | reject |

Two things follow:

- **Virtual NICs are rejected by the game itself.** `IF_TYPE_PROP_VIRTUAL` is 53, so TAP,
  Tailscale and WireGuard-style tunnels never enter the list. No hook-side work is needed
  for them; they are simply not counted as candidates, so they cannot make the choice look
  ambiguous.
- **Two physical Ethernet NICs both qualify.** The game does not disambiguate beyond
  "lowest `IfIndex` first", which on this host is index 10, not the APIPA adapter at 20.
  Hiding the rest is the hook's job.

## 4. What the hook presents

The rule is **normalise, do not fabricate**: keep the real `IfIndex`, IPv4, prefix and MAC;
change only the fields the game refuses.

| field | rule | why |
|---|---|---|
| `Type` / `IfType` | rewritten to 6 | the game's only gate; Ethernet needs no rewrite |
| `IfIndex` | **real** | `IP_UNICAST_IF` and `bind()` act on the real stack; the daemon looks it up by index |
| address / mask / prefix | real, from one unicast entry | `bind()` to an address no adapter owns fails with `10049 WSAEADDRNOTAVAIL` |
| `gateway` | real if inside `address & mask`, else the segment router | see §5 |
| `DHCP` flag | set | `config_common.json` ships `"dhcp": true`, and `FUN_1402f76f0` reads the bit |
| DNS server list | real if present, else the segment router | `chusanApp` walks `FirstDnsServerAddress` while enumerating |
| adapter count | only the chosen one (`exclusive`) | the game takes the lowest index, which may be the wrong NIC |

The segment router is `[keychip] subnet | [netenv] routerSuffix` when `segatools.ini` is
present — the same address netenv invented — and otherwise the last usable host of the
presented subnet. The configured value is validated against the presented subnet rather than
trusted: `[keychip] subnet` describes what the game was *told* to expect, and when the chosen
adapter is on another subnet the invented address falls outside its own network and would
fail the very comparison it exists to satisfy.

The substitution is unconditional on both enumeration APIs whenever a gateway is to be
presented, not only when the field is empty. A field that is merely non-empty can still be
the wrong address, and `chusanApp` reads the gateway from `GetAdaptersInfo`
(`GatewayList.IpAddress.String`, `+0x1D8`) during
enumeration — so correcting one API and leaving the other would hand the game the bad value
while the log showed a good one.

`exclusive=1` moves the chosen adapter to the front of the caller's buffer rather than
allocating a new list: `IP_ADAPTER_INFO` keeps its strings inline, and
`IP_ADAPTER_ADDRESSES`' pointers address data elsewhere in the same buffer, so only the
fixed-size header moves and only `Next` has to be cleared.

## 5. The gateway rule

`FUN_1403c0270` is `alwAuthPhaseGateway`, the gateway phase of the ALL.Net authentication
state machine. In its first phase it performs a comparison and fails immediately:

```c
puVar8 = FUN_1403b0f20();          /* the network state block */
if ((*(int *)(puVar8 + 7) == 0) &&
    ((*(uint *)((longlong)puVar8 + 0xcc) & *(uint *)(puVar8 + 0x19)) !=   /* gateway & mask */
     (*(uint *)((longlong)puVar8 + 0xc4) & *(uint *)(puVar8 + 0x19)))) {  /* address & mask */
    FUN_1403c74a0(0xfffffffe, 0x1f42);                                    /* 0x1F42 = 8002 */
```

`puVar8` is `undefined8 *`, so the offsets are bytes: `+0xc4` the interface address, `+0xc8`
the mask, `+0xcc` the gateway. The test is:

> **`(gateway & mask) != (address & mask)` → fail with 8002.**

That is a pure integer comparison. It sends nothing, which is why GATEWAY can turn BAD
immediately with no `IcmpSendEcho2` call in the log, and it is the same `0x1F42` that
appears as error 8002 in a misconfigured run.

netenv never failed it because it reported `subnet | routerSuffix` as the gateway and
`subnet | addrSuffix` as the address: both came from the same invented subnet, so
`gateway & mask == address & mask` held trivially. A real adapter carries no such guarantee
— a flat L2 segment such as ZeroTier can report a gateway on another prefix, and then the
check fails on the arithmetic alone.

The hook therefore keeps a real gateway only when it satisfies exactly that condition, and
otherwise substitutes the segment router, which satisfies it by construction. The same value
is used for the adapter field, the `GetAdaptersInfo` string and the route next hop, because
the game cross-checks them.

**ZeroTier is the case that matters in practice:** a flat L2 segment reports no gateway at
all, so `FirstGatewayAddress` is null. Virtualising ICMP cannot help a comparison that never
happens, which is why supplying the address — not answering the echo — is what fixed the
item.

## 6. The consistency invariant

The whole difference between this hook and netenv, in one sentence: **netenv's adapter was
internally consistent because everything in it came from one invented subnet, and a real
adapter is not.** Every field a consumer can cross-check agreed for netenv for free.

The presentation enforces these now, rather than passing reality through:

| pair | rule |
|---|---|
| address / mask / prefix | taken from the same unicast entry |
| gateway vs subnet | kept only if inside `address & mask`, else the segment router |
| `GetBestRoute` next hop vs gateway field | one value feeds both |
| `GetAdaptersInfo.GatewayList` vs `GetAdaptersAddresses.FirstGatewayAddress` | both written from that same value; the literal `"0.0.0.0"` counts as absent |
| `IfIndex` | real, so `GetIfEntry` and `IP_UNICAST_IF` stay valid |

The one field that deliberately stays real is `IfIndex`, because faking it is what breaks
`IP_UNICAST_IF` and `bind()`. netenv used `1`, which is also the loopback index.

`GetBestRoute` is answered from the presented adapter for **every** destination, not only
those inside the subnet. netenv did the same (`netenv.c:422-451`) because `amdaemon` treats
"GetBestRoute succeeded" as evidence that a default gateway exists; scoping by destination
made the answer depend on which address happened to be asked about. It is a query only, so
real egress is unaffected.

The presented record is dumped once per process, so a run that still fails reports every
field rather than requiring another round of guessing:

```
ADAPTER  presented: if_index=10 if_type=6 oper=1 flags=0x3E5 mtu=1500
         ip=172.16.10.235 gw=172.16.10.254 dns=100.127.129.129 exclusive=1
```

## 7. DNS: what netenv controlled there, and what it did not

netenv hooks `GetAdaptersAddresses`, `GetAdaptersInfo`, `GetBestRoute`, `GetIfTable` and
`IcmpSendEcho2`, plus `ws2_32!sendto`. It never patches `dnsapi.dll`, `getaddrinfo`,
`GetAddrInfoW`, `DnsQuery_*` or `WinHttpConnect`.

Name redirection lives in a separate segatools component, `common/hooklib/dns.c`, driven by
`common/platform/dns.c`, enabled by `[dns]` (default **1**) and independent of `[netenv]
enable` (default **0**). With `[netenv] enable=0` the domain table still applies.

What netenv *does* control is the adapter's DNS **server list**. `chusanApp` walks
`FirstDnsServerAddress` while enumerating:

```c
uVar1 = puVar9[7];                       /* +0x1c = FirstDnsServerAddress */
for (; uVar1 != 0; uVar1 = *(uint *)(uVar1 + 8)) {   /* Next at +0x08 */
    getnameinfo(*(uint *)(uVar1 + 0x0c),             /* Address.lpSockaddr */
                *(uint *)(uVar1 + 0x10),             /* Address.iSockaddrLength */
                local_40c, 0x401, 0, 0, 2);
```

netenv supplies that list unconditionally (`netenv.c:256`, `netenv.c:326` →
`subnet | routerSuffix`). The hook keeps the real list when the adapter has one and falls
back to the same address when it does not, because an empty list is a state netenv never
produced. Note the asymmetry: netenv's `hook_GetAdaptersInfo` never assigns `DnsServerList`,
but the game does not read it there — pass 1 only parses IP, mask and gateway.

**Not verified:** an adapter that genuinely reports no DNS server. This host's chosen
adapter has two, so only the "keep the real list" branch is measured. The fallback branch
is exercised by the same code path as the gateway one, which is measured.

## 8. The two egress paths, and why they stay separate

A host doing remote head-to-head over a virtual L2 network has two network roles that must
not share one interface:

| role | destinations | must use |
|---|---|---|
| LAN peer | UDP 40112, TCP 40110, UDP/TCP 50200-50202 | the LAN adapter, possibly a virtual one |
| internet client | the game server, `[dns] default` | whatever the default route says |

Pinning is therefore scoped **by port**, not by process:

- `ensure_broadcast_interface` is reached only from `hook_sendto` / `hook_wsasendto`, and
  only when the port is one of the five;
- `ensure_tcp_source` is reached only from `hook_connect` / `hook_wsaconnect`, likewise.

Every other socket — WinHTTP, DNS, the keychip layer — keeps the system's normal source
selection and default route. Adapter presentation does not change that either: it patches
`GetAdaptersInfo`, `GetAdaptersAddresses` and `GetIfTable`, none of which WinHTTP consults.

`report_server_route()` reads `[dns] default`, asks `GetBestRoute2` which interface the
system would use, and says so at start-up. It reports; it does not reroute. If the LAN
adapter is the only one with a default route and cannot reach the server, that is a routing
decision, not something an adapter hook should paper over.

```
# LAN pinned to one adapter, server reached through another
INFO  Server traffic to 100.76.171.50 leaves through interface 7, not the pinned LAN
      interface (index 10). The game LAN and the server therefore take different paths,
      which is what a LAN-only virtual adapter such as ZeroTier needs.
```

## 9. The two ICMP-driven network-test items

The screen (IP ADDRESS / GATEWAY / DNS(LAN) / NUMBER OF HOP / LINE TYPE / ALL.Net
AUTHENTICATION / Aime SERVER / E-MONEY / TITLE SERVER / MATCHING SERVER) is rendered by
`chusanApp`, but the verdicts are computed by `amdaemon` and handed over — `chusanApp`
imports no ICMP entry point at all. Item verdicts come from
`FUN_14021e500(checker, verdict, code)`, where the code is 0 = CHECKING or blank, 1 = `N/A`,
2 = `GOOD`, 3 = `BAD`.

Both ICMP-driven items go through `altrIcmpSendEcho` (`0x1403f0b00`), the only caller of
`IcmpSendEcho2` in the process:

```c
local_28.Ttl = *param_1;
DVar1 = IcmpSendEcho2(handle, event, NULL, NULL, target, NULL, 0, &local_28, ...);
if ((DVar1 == 0) && (DVar1 = GetLastError(), DVar1 != 0x3E5)) { /* failure */ }
/* success: 0x3E5 is ERROR_IO_PENDING, which the async form returns */
```

`hook_IcmpSendEcho2` answers every destination with `IP_SUCCESS`, sets
`ERROR_IO_PENDING` and signals the event — the same shape netenv used.

### NUMBER OF HOP reads 1, and always has

The item is a **traceroute result**: the TTL needed to reach the ALL.Net authentication
server. The chain is `HopsChecker::update` (`0x140296230`) → `Manager+0x1138` →
`LocationRouterChecker+0x148` ← `FUN_140294c80` copies from `HopsCounter+0x1e4` ←
`HopsCounter::update` (`0x1402aafe0`) → `altrGetResultTtl` (`0x1403b9ff0`).

The trace starts at TTL 1: `FUN_1403ba120` sets the state word to 1, and `FUN_1403d7a60`
gives the first three probes TTL 1 (10 TTLs, 3 probes each). netenv never read
`RequestOptions`, never transmitted, and always set `pong->Status = IP_SUCCESS`
(`netenv.c:490-559`). So the very first TTL=1 probe was indistinguishable from one that had
reached the server, `FUN_1403d7850` marked it done, `FUN_1403d75c0` ended the trace, and
`altrGetResultTtl` reported 1.

**The 1 was never a measurement.** It is what answering the first probe of a trace that
never ran produces, and it is what this hook reproduces.

The item's only consumer compares it against zero:

```c
iVar2 = FUN_140247240(manager);                        /* the hop count */
if (iVar2 == 0) { FUN_14021e500(param_2, 2, 3); return; }   /* 3 = BAD */
FUN_14021e500(param_2, 2, 2);                               /* 2 = GOOD */
FUN_14021e570(param_2, iVar2);                              /* "%u" into the item */
```

There is no threshold, no second consumer, and no arithmetic. Any non-zero value passes.

### Why the answer must reach every destination

An earlier revision scoped ICMP virtualisation to the presented subnet, on the reasoning
that a real failure outside the LAN should stay visible. The traceroute's target is a public
address, so those probes went out on the real network; when that path did not answer — ICMP
filtered, target unreachable, or the presented interface pinned as the egress — the item
never left CHECKING, the network test never finished, and the game never started.

Answering everything is therefore not a cosmetic choice. `virtualizeIcmp=0` is available for
a host whose real ICMP path is known to work, and the hook warns at start-up that both items
then depend on it.

Reproducing a genuinely measured hop count is not attempted: TTL-expired replies would have
to be invented for routers that cannot be observed, so any other value would be an equally
fabricated constant, merely a less familiar one.

## 10. Provenance

The numbers in §1–3 and in "NUMBER OF HOP reads 1" came from throwaway probes run on this
host, and those probes are gone: they measured the Windows stack and the game's own
filters, not this hook, so none of them could fail when the hook regressed. Git history
still has them if a measurement has to be repeated.

Three probes remain, and all three guard shipped behaviour:

| probe | what it pins down | built | run |
|---|---|---|---|
| `tests/probe_icmp.cpp` | `hook_IcmpSendEcho2` answers every destination, at any TTL | `build.bat` | `release.yml` |
| `tests/probe_ownership.cpp` | `[netenv] enable=1` leaves presentation and pinning to segatools while LAN Install virtualisation keeps running | `build.bat` | `release.yml` |
| `tests/smoketest.cpp` | LAN Install virtualisation, and the loopback Party path | `build.bat` | `release.yml` |

`tests/probe_presentation.cpp` stays as a hand-held inspection tool: it loads the DLL into
a scratch process and prints the adapter list all three APIs return, which is the only way
to see a presentation decision without starting the game.

Ghidra side: `allnet_enumerate_adapters` @ `0x01026820`, single caller `0x0044dcc5`;
`alwAuthPhaseGateway` @ `0x1403c0270`; `alwAuthPhaseTraceroute` @ `0x1403c1a00`;
`altrGetResultTtl` @ `0x1403b9ff0`.
