# Adapter selection: what chusanApp actually accepts

**Status: verified by disassembly + measurement on this host.**
This closes the open question that `broadcast-interface-regression.md` §2.1 left as a
coincidence ("netenv happens not to be hooked") and that the segatools comment
("Chunithm is extremely picky about its LAN environment") asserted without proof.

The question it answers: *can `[netenv]` be turned off and left to `chusan_network_hook`?*

## 1. The function

`chusanApp.exe` `0x01026820` — an ANY-address function that was not defined in the Ghidra
project, so it is assigned here as `allnet_enumerate_adapters`. Signature from the
prologue (`PUSH EBP; LEA EBP,[ESP-0x408]; SUB ESP,0x408`, ~1 KiB frame plus a `/GS`
cookie): it fills an adapter **vector** inside the network-manager object passed in
`ECX` (`+0x08` = begin, `+0x0c` = end). It is called from exactly one site,
`0x0044dcc5`.

It runs three passes and nothing else:

| pass | API | role |
|---|---|---|
| 1 | `GetAdaptersInfo` | **the only gate** — decides which adapters exist at all |
| 2 | `GetAdaptersAddresses` | enrichment only — `OperStatus` and all unicast IPv4s |
| 3 | `GetIfTable` | enrichment only — per-index row (speed/status) |

## 2. Pass 1: `Type == 6` is the gate

```
01026898  CALL GetAdaptersInfo            ; size probe, must return 0x6F BUFFER_OVERFLOW
0102689D  CMP  EAX, 0x6F
010268B2  CALL operator new[]             ; buffer for the reported size
010268CD  CALL GetAdaptersInfo            ; real call, must return 0
```

Then, per `IP_ADAPTER_INFO` node, the fields are copied out. Offsets are confirmed by the
`AddressLength`/`Address[8]` pair falling exactly where `MAX_ADAPTER_DESCRIPTION_LENGTH +
4` puts them:

| offset | field | used as |
|---|---|---|
| `+0x190` | `AddressLength` | stored (record `+0x1c`) |
| `+0x194` | `Address[8]` | 8-byte copy (record `+0x20`) — MAC |
| `+0x19C` | `Index` | stored (record `+0x14`), also the map key |
| **`+0x1A0`** | **`Type`** | **`CMP [ECX+0x1a0], 6` — adapters that fail this are dropped** |
| `+0x1A4` | `DhcpEnabled` | `0` or the DHCP server string |
| `+0x1B0` | `IpAddressList.IpAddress.String` | parsed to a packed IPv4 |
| `+0x1C0` | `IpAddressList.IpMask.String` | parsed to a packed IPv4 |
| `+0x1D4` | `GatewayList.IpAddress.String` | parsed into a vector |

`0x010268F0` is `CMP dword ptr [ECX + 0x1a0], 0x6` / `JNZ skip`.

`Type == 6` is `MIB_IF_TYPE_ETHERNET`. There is **no other acceptance test** in this pass:
no speed, no `OperStatus`, no address-family check (`GetAdaptersInfo` is IPv4-only by
construction), no name matching.

## 3. Pass 2 does not add adapters, only completes them

This is the part that decides whether a rejected NIC can sneak back in. It cannot.

```
01026a50  MOV EAX, [ESI+0x04]      ; adapter->IfIndex
01026a61  CALL map.lower_bound / equal_range
01026a6F  CALL distance(begin, end)
01026a79  JZ   0x01026b00          ; not found -> skip this adapter
...
01026b00  MOV ESI, [ESI+0x08]      ; ESI = adapter->Next  (advance, no insert)
01026b08  JNZ  0x01026a50
```

`0x01026a79` skips straight to the "advance to `Next`" block. The pass is keyed on the
`IfIndex` the first pass already recorded, so an adapter that failed the `Type == 6` gate
is never enriched and never appears in the result.

What it does add, for adapters already present:

- `OperStatus` from `IP_ADAPTER_ADDRESSES +0x44`, normalised by `FUN_010266f0` to `0..7`
  (`1` = `IfOperStatusUp`);
- **every** unicast IPv4 address, by walking `FirstUnicastAddress` (`+0x1c`) and running
  `getnameinfo(..., NI_NUMERICHOST)` on each — a multi-address NIC yields several
  entries, which `GetAdaptersInfo`'s single `IpAddressList` cannot express.

## 4. Pass 3 and ordering

`GetIfTable` rows are matched to records by `dwIndex`, then the vector is sorted with
comparator `FUN_01026640`, which compares the record's first dword — the `IfIndex`.
So the result is ordered **ascending by interface index**.

## 5. Measured on this host

`tests/probe_adapter_table.cpp` reproduces passes 1–2 against the live stack:

| Idx | Type | Description | IP | verdict |
|---|---|---|---|---|
| 20 | 6 | Red Hat VirtIO Ethernet Adapter #2 | 169.254.158.1 | **ACCEPT** |
| 10 | 6 | Red Hat VirtIO Ethernet Adapter #5 | 172.16.10.235 | **ACCEPT** |
| 18 | 53 | TAP-Windows Adapter V9 | 0.0.0.0 | reject |
| 7 | 53 | Tailscale Tunnel | 100.76.171.50 | reject |

Two things fall out immediately:

- **Virtual NICs are rejected by the game itself.** `IF_TYPE_PROP_VIRTUAL` is 53, so TAP,
  Tailscale, WireGuard-style tunnels never enter the list. This hazard was overestimated
  and needs no hook-side work.
- **Two physical Ethernet NICs both qualify.** The game does not disambiguate beyond
  "lowest `IfIndex` first". On this host that is index 10 (`172.16.10.235`), not the
  APIPA adapter at index 20.

## 6. What this means for `[netenv]`

`references/segatools/common/platform/netenv.c` fakes exactly this pipeline, and its
constants are not arbitrary:

| game requirement | netenv value |
|---|---|
| `GetAdaptersInfo` reports one adapter | single synthetic `netenv` struct |
| `Type == 6` | `ai->Type = MIB_IF_TYPE_ETHERNET` (line 411) |
| `IfIndex` consistent across all three passes | `Index = 1` (411), `head.IfIndex = 1` (253), `dwIndex = 1` (478) |
| `AddressLength` / MAC | `= 6`, `01:02:03:04:05:06` |
| IP / mask / gateway strings | `subnet|addrSuffix`, `255.255.255.0`, `subnet|254` |
| `GetAdaptersAddresses` `IfType` | `IF_TYPE_ETHERNET_CSMACD` (266) |
| `OperStatus` | `IfOperStatusUp` (267) |
| `GetIfTable` row present | one row, `dwIndex = 1` (472–478) |

So netenv is not "an ideal LAN" in the abstract — it is a faithful stand-in for a NIC the
game would otherwise refuse.

**Conclusion, split by host:**

| host LAN NIC | `[netenv] enable=0` |
|---|---|
| **Ethernet (`Type == 6`)** | **Safe.** The game enumerates real adapters natively. Nothing else in this function rejects them. |
| **Wi-Fi (`IF_TYPE_IEEE80211` = 71)** | **Not safe.** The NIC fails `Type == 6` at the first pass and never reaches pass 2. The game sees zero adapters. |
| Ethernet + a second Ethernet NIC | Works, but the choice is "lowest `IfIndex`", which is not the same as "the one on the game LAN". This is what the hook exists to override. |

The Wi-Fi row is read from the documented `MIB_IF_TYPE_*` / `IF_TYPE_*` values, not
measured here: this host has no wireless NIC. It is the one claim in this document that
still wants a physical machine to confirm.

## 7. amdaemon uses a different, more permissive filter

`amdaemon.exe` (x64) reaches the same APIs from another direction, and its acceptance rule
is **not** the game's. `FUN_1402f7400` (`amyNetworkGetInterfaceInfo`) calls
`GetAdaptersInfo` into a fixed `0x3000` buffer and hands the chain to `FUN_1402f6470`
(`amyNetworkAnalyzeInterfaceInfo`), which decides per adapter:

```c
iVar1 = *(int *)(adapter + 0x1a4);                       /* Type */
if (iVar1 != 0x18 && iVar1 != 1 && *(int *)(adapter + 0x194) == 6)   /* and MAC length 6 */
```

The offsets only make sense once the pointer-size shift is applied — `Next` is 8 bytes on
x64, which moves every following field by 4 relative to the x86 table in §2:

| field | x86 (chusanApp) | x64 (amdaemon) |
|---|---|---|
| `AddressLength` | `0x190` | `0x194` |
| `Address` | `0x194` | `0x198` |
| `Index` | `0x19C` | `0x1A0` |
| `Type` | `0x1A0` | `0x1A4` |
| `DhcpEnabled` | `0x1A4` | `0x1A8` |

Measured with `tests/probe_struct_offsets.cpp` on both architectures. The `0x194 == 6` test
is therefore `AddressLength == 6` (MAC length), and `0x1A4` is `Type` — not the Wi-Fi/link
field it first resembles.

The two thresholds are real `MIB_IF_TYPE` values:

| value | constant | amdaemon | chusanApp |
|---|---|---|---|
| 1 | `MIB_IF_TYPE_OTHER` | reject | reject |
| 6 | `MIB_IF_TYPE_ETHERNET` | accept | **accept (only)** |
| 24 | `IF_TYPE_SOFTWARE_LOOPBACK` | reject | reject |
| 71 | `IF_TYPE_IEEE80211` | **accept**, with a larger slot budget (`0x400` vs `4`) | reject |

So the daemon tolerates Wi-Fi and the game does not. netenv's single synthetic adapter
(`Type = 6`) satisfies both; that is why the two processes can share it.

## 8. Consequences for the hook

1. On a wired host, turning netenv off removes the need for the `IfIndex` workaround in
   `netenv.c` §2.1 entirely — the hook reads the real index and `IP_UNICAST_IF` works on
   the real stack. `tests/probe_unicast_if.cpp` pins interface 10 and the broadcast egress
   source moves `169.254.158.1` → `172.16.10.235`; pinning interface 20 moves it back to
   `169.254.158.1`. The round trip is what rules out the change being a coincidence with
   the unpinned baseline, which already happened to be index 20's address.
2. On a Wi-Fi host the hook must take over netenv's job rather than "disable" it: fake
   `GetAdaptersInfo`/`GetAdaptersAddresses` with `Type = IfType = 6`, the real IPv4, the
   real `IfIndex`, and pass it through to `IP_UNICAST_IF`.
3. Either way the keychip `[keychip] subnet` must equal the real LAN /24, because the
   game advertises the address it enumerates and `bind()` to an address no NIC owns fails
   with `10049 WSAEADDRNOTAVAIL` (measured, `tests/probe_unicast_if.cpp`).

## 9. Reproducing

```bat
cl /nologo /std:c++17 /O2 /MT /W4 tests\probe_adapter_table.cpp ^
  /link /SUBSYSTEM:CONSOLE /OUT:build\probe_adapter_table.exe ws2_32.lib iphlpapi.lib
build\probe_adapter_table.exe
```

Ghidra side: `allnet_enumerate_adapters` @ `0x01026820`, single caller `0x0044dcc5`.

## 10. DNS: what netenv controls, and what it does not

This was checked because it decides whether dropping netenv changes how the game resolves
names. It does change one thing, and not the one that first suggests itself.

### netenv does not touch name resolution

`netenv.c` hooks exactly five import groups — `GetAdaptersAddresses`, `GetAdaptersInfo`,
`GetBestRoute`, `GetIfTable`, `IcmpSendEcho2` and `ws2_32!sendto`. It never patches
`dnsapi.dll`, `getaddrinfo`, `GetAddrInfoW`, `DnsQuery_*` or `WinHttpConnect`.

Name redirection lives in a separate segatools component,
`common/hooklib/dns.c`, driven by `common/platform/dns.c`. It is enabled by the `[dns]`
section, whose `enable` defaults to **1** (`config.c:92`) and is independent of
`[netenv] enable` (default **0**). `platform_hook_init` initialises the two siblings in
sequence (`platform.c:44` then `platform.c:62`); neither owns the other.

So with `[netenv] enable=0` the domain table still applies: `naominet.jp`,
`*.sys-all.net`, `tenporouter.loc` and the rest keep resolving to the `[dns]` targets.

### But netenv does fabricate the adapter's DNS server list

`chusanApp` reads `IP_ADAPTER_ADDRESSES.FirstDnsServerAddress` while enumerating.
`allnet_enumerate_adapters` @ `0x01026820` walks it:

```c
uVar1 = puVar9[7];                       /* +0x1c = FirstDnsServerAddress */
for (; uVar1 != 0; uVar1 = *(uint *)(uVar1 + 8)) {   /* Next at +0x08 */
    getnameinfo(*(uint *)(uVar1 + 0x0c),             /* Address.lpSockaddr */
                *(uint *)(uVar1 + 0x10),             /* Address.iSockaddrLength */
                local_40c, 0x401, 0, 0, 2);
    ...
}
```

The offsets line up with the SDK layout, measured by `tests/probe_struct_offsets.cpp`:
`FirstUnicastAddress` 0x10, `FirstAnycastAddress` 0x14, `FirstMulticastAddress` 0x18,
**`FirstDnsServerAddress` 0x1c**. `puVar9[2]` is `Next` at 0x08 and `puVar9[1]` is
`IfIndex` at 0x04, which confirms `puVar9` really is the adapter pointer.

netenv supplies that list — `netenv.c:256` sets `FirstDnsServerAddress = &env->dns`, and
`netenv.c:326` sets it to `netenv_ip_router`, i.e. `subnet | routerSuffix` (default
`.254`).

Note the asymmetry: netenv's `hook_GetAdaptersInfo` never assigns `DnsServerList`, so that
API reports an empty list. The game does not read it there — the `GetAdaptersInfo` pass
only parses IP, mask and gateway (`0x1B0`, `0x1C0`, `0x1D4`) — so the inconsistency is
invisible in practice.

### Consequence for this hook

Presenting the real adapter therefore changes the DNS list the game sees, from netenv's
constant `a.b.c.254` to whatever the adapter actually has. That is more correct, but it
is a behaviour change on a host whose adapter has **no** DNS server (static address, no
DHCP): the game would enumerate an empty list, a state netenv never produced.

`hook_GetAdaptersAddresses` therefore keeps the real list when one exists and falls back
to `[netenv] routerSuffix` when the adapter has none, which reproduces the only value
netenv ever reported. The fallback is reported on start-up rather than applied silently.

**Not verified:** an adapter that genuinely reports no DNS server. This host's chosen
adapter has two, so the fallback branch never ran; only the "keep the real list" branch is
measured.

### A collision worth knowing about

`common/hooklib/dns.c` can also patch `ws2_32!send` (`http_hook_init`, for `Host:`
rewriting) and `ws2_32!connect` (port remapping). Both are off by default —
`[dns] replaceHost`, `startupPort`, `billingPort` and `aimedbPort` all default to 0
(`config.c:142-145`). If they are enabled, those patches coexist with this hook's own
`send`/`connect` hooks because they are applied later (at `platform_hook_init`, which runs
after this DLL's `DllMain`) and therefore chain in front: `dns.c` -> this hook -> real.
No arbitration is needed, but the ordering is what makes it work.
## 11. The gateway check: first hypothesis (superseded by 13)

**Superseded.** §13 shows the gateway item is decided without any `IcmpSendEcho2` call, so
the reasoning below is wrong about the cause. It is kept because the measurements are real
and the `GetBestRoute` finding still holds.

Measured on a ZeroTier-only host, with the takeover active:

| configuration | IP ADDRESS | GATEWAY |
| --- | --- | --- |
| `[netenv] enable=1`, hook idle (baseline) | GOOD | **GOOD** |
| `[netenv] enable=0`, takeover active | GOOD | **BAD** |
| `[netenv] enable=0`, hook idle (control) | BAD, error 8002 | - |

The interesting row is the first. The baseline ran on the *same* router-less ZeroTier
segment as the second, so "the adapter has no route to the internet" cannot explain the
difference between them. What differs is that netenv answers every ICMP echo as a success
(`netenv.c:490-559`) without transmitting anything.

amdaemon's gateway probe is exactly that:

```c
/* FUN_1403f0b00, altrIcmpSendEcho */
DVar1 = IcmpSendEcho2(handle, event, NULL, NULL, *(IPAddr *)(param_1 + 0xc), NULL, 0,
                      &options, reply, reply_size, timeout);
if ((DVar1 == 0) && (DVar1 = GetLastError(), DVar1 != 0x3E5)) { /* failure -> returns 2 */ }
else { /* success */ }
```

`0x3E5` is `ERROR_IO_PENDING`, which is precisely what netenv reports: it calls
`SetEvent(event)` and sets `ERROR_IO_PENDING` when an event is supplied. So under netenv
the gateway check passes on a segment that has no router at all.

The control row explains the other direction: with no shaping, `chusanApp` sees the full
real adapter list and picks an unacceptable one, so even the address check fails with 8002.
That is the failure the takeover fixes.

`hook_IcmpSendEcho2` therefore answers echoes as successes, in the same async shape netenv
used. The default scope is **every destination**, because a second item needs it - see
§15. `virtualizeIcmp=0` disables it, at the cost of both the gateway check and the hop
count failing on any segment without a reachable router.
## 12. The two egress paths, and why they must stay separate

A host doing remote head-to-head over a virtual L2 network (ZeroTier, Tailscale, a
TAP bridge) has two network roles that must not share one interface:

| role | destinations | must use |
| --- | --- | --- |
| LAN peer | UDP 40112, TCP 40110, UDP/TCP 50200-50202 | the LAN adapter, possibly a virtual one |
| internet client | the game server, `[dns] default` | whatever the default route says |

Pinning everything to the LAN adapter would leave the game unable to reach a server that
lives on the public internet, which is the normal deployment. The implementation therefore
scopes pinning **by port**, not by process:

- `ensure_broadcast_interface` is reached only from `hook_sendto` / `hook_wsasendto`, and
  those call it only when `relevant(port)` holds, i.e. ports 40110, 40112, 50200-50202.
- `ensure_tcp_source` is reached only from `hook_connect` / `hook_wsaconnect`, again only
  under `relevant(port)`.

Every other socket in the process - WinHTTP, DNS, the keychip layer - is untouched, so it
keeps the system's normal source-address selection and default route.

Adapter presentation does not change that either. It patches `GetAdaptersInfo`,
`GetAdaptersAddresses` and `GetIfTable`; the server path runs through WinHTTP and
`DnsQuery`, neither of which consults those. `amdaemon` imports 18 WinHTTP entry points and
does its server I/O there, so hiding the other adapters cannot redirect it.

### It is checked at start-up, not assumed

`report_server_route()` reads `[dns] default` and asks `GetBestRoute2` which interface the
system would use, then says so. Three measured cases:

```
# server on the public internet, default route shared with the LAN adapter
INFO  Server traffic to 8.8.8.8 leaves through the same interface as the game LAN
      (index 10). That only works if that interface really reaches the server.

# LAN pinned to one adapter, server reached through another
INFO  Server traffic to 100.76.171.50 leaves through interface 7, not the pinned LAN
      interface (index 10). The game LAN and the server therefore take different paths,
      which is what a LAN-only virtual adapter such as ZeroTier needs.

# [dns] default is a hostname, so the route is decided at connect time
INFO  Server target from [dns] default is "game.example.net" (a hostname); its egress
      interface is decided at connect time by the system resolver, not by this hook.
```

The first line is the one that matters for the hybrid case: when it appears with two
different indices, the LAN is pinned and the server still has its own way out.

### What this does not do

It reports; it does not reroute. If the LAN adapter is the only one with a default route
and it cannot reach the server, the hook says so and stops there - fixing that is a
routing or server-placement decision, not something an adapter hook should silently paper
over.
### 11.1 A gateway has to exist before it can be probed

The first field report after the ICMP work still showed GATEWAY BAD, with
`[iphlpapi] installed 3 hook slot(s)`. The 3 is correct for `amdaemon`: it imports
`GetAdaptersInfo`, `GetAdaptersAddresses` and `IcmpSendEcho2`, but **not** `GetIfTable`,
so the three slots were the two enumeration APIs plus the ICMP hook. The ICMP hook was
live.

What was missing is the address to probe. ZeroTier is a flat L2 segment: it reports no
gateway at all, so `FirstGatewayAddress` is null, and the check fails before
`IcmpSendEcho2` is ever called. Virtualising the echo cannot help a probe that is never
made.

netenv never had this problem because it supplied `subnet | routerSuffix` as the gateway
unconditionally (`netenv.c:269`, `netenv.c:322-323`). The hook now does the same, but only
when the adapter reports none, on both APIs:

- `FirstGatewayAddress` for `GetAdaptersAddresses`;
- `GatewayList` for `GetAdaptersInfo`, whose x86 pass reads it at `+0x1d4`.

Measured on an adapter that, like ZeroTier, reports no gateway:

```
INFO  Adapter ... reports no gateway; presenting 172.16.10.254 so the gateway check
      has an address to probe.
  gw: 172.16.10.254  dns: 100.127.129.129 211.136.17.107
  172.16.10.254  count=0 error=997/IO_PENDING status=IP_SUCCESS (virtualized)
```

With the gateway present, the ICMP hook answers it and the chain closes.
## 13. What the network test screen actually is, and what it eliminates

The screen (IP ADDRESS / GATEWAY / DNS(LAN) / NUMBER OF HOP / LINE TYPE / ALL.Net
AUTHENTICATION / Aime SERVER / E-MONEY / TITLE SERVER / MATCHING SERVER) is rendered by
`chusanApp` - the labels `IP ADDRESS` exist there (`chusanApp.exe` `0x0177d37c`) and the
item names also exist in `amdaemon`. `chusanApp` imports no ICMP entry point at all
(`IcmpCreateFile` and `IcmpSendEcho2` are not in its 606 imports), so the verdicts are
computed by `amdaemon` and handed over.

That plus one field observation eliminates the ICMP explanation:

> After the ICMP hook was added, a network-test run produced `injected DNS server` lines
> and **no `IcmpSendEcho2` line whatsoever**.

`hook_IcmpSendEcho2` logs every call it receives, up to eight. No line means the gateway
item is decided without an echo. netenv's always-successful `IcmpSendEcho2` therefore
cannot be the reason the baseline showed GATEWAY GOOD, which also means the ICMP work done
earlier in this investigation, while harmless, was not the fix.

The remaining inputs `amdaemon` has for that item are the adapter's gateway field
(`IP_ADAPTER_ADDRESSES` `+0xd0`, read in `FUN_1402f76f0`) and `GetBestRoute`
(`FUN_1403bbbc0`). netenv faked both; before this round the hook faked the first only when
the field was absent, and the second only for destinations inside the presented subnet.

### The shape of the answer now enforced

netenv's synthetic adapter was self-consistent by construction and a real adapter is not.
The presentation now enforces the same consistency:

| property | rule |
| --- | --- |
| gateway | kept only if it lies inside the presented subnet; otherwise replaced with `subnet \| routerSuffix` |
| `GetBestRoute` | returns the presented interface and that same next hop, for every destination, as netenv did |
| DHCP flag | `IP_ADAPTER_DHCP_ENABLED` set, because `config_common.json` ships `"dhcp": true` and `FUN_1402f76f0` reads that bit |
| DNS | kept when present, else `subnet \| routerSuffix` |

The first row is the one that matters: a gateway outside the adapter's own subnet is not a
usable default gateway for it, and netenv never produced one.

**Not yet verified:** whether this changes the screen. The reasoning above narrows the
cause to the adapter/route answer, but the confirmation requires a run, and the last
observed run predates these changes.
### 13.1 Deciding it in one run

The remaining candidates are the adapter gateway field and `GetBestRoute`. Both now report
the same value, and both are logged. One run settles it:

| what the log shows | conclusion |
| --- | --- |
| `patched IcmpSendEcho2` is **absent** | the ICMP hook never installed, and the earlier elimination in §13 was based on a hook that was not active |
| `patched GetAdaptersInfo` / `GetAdaptersAddresses` absent | the adapter hooks are not reaching the process that computes the verdict |
| `injected gateway for if_index N` and the screen turns GOOD | the gateway field was the cause; the on-segment rule fixed it |
| `injected gateway ...` and the screen stays BAD | the verdict does not come from that field either; the next step is the networktest `ItemChecker` chain (`am::networktest::ItemCheckerBase`, vftable `0x1406d5660`, methods `0x140297010`, `0x140295ac0`, `0x1402955f0`) |
| `GetBestRoute #N` lines appear and the screen turns GOOD | `GetBestRoute` was the cause |
| no `ADAPTER_HOOK` lines at all during the test | the verdict is computed without any of the hooked APIs, so it comes from state cached at start-up |

The vftable pointers are recorded here because the RTTI type descriptor for
`am::networktest::GatewayChecker` (`0x1408ac208`) is reached only through the complete
object locator at `0x140793140`, which has no direct code reference and is therefore easy
to lose.
### 13.2 The invariant the presentation now guarantees

The whole difference between this hook and netenv, stated as one sentence: **netenv's
adapter was internally consistent because everything in it came from one invented
subnet, and a real adapter is not consistent in that sense.** Every field a consumer can
cross-check - address against mask, gateway against subnet, route next hop against the
gateway field, the two enumeration APIs against each other - agreed for netenv for free.

The presentation therefore enforces these now, rather than passing reality through:

| pair | rule |
| --- | --- |
| address / mask / prefix | taken from the same unicast entry |
| gateway vs subnet | gateway kept only if inside `address & mask`, else `subnet \| routerSuffix` |
| `GetBestRoute` next hop vs gateway field | one `gateway_effective` feeds both |
| `GetAdaptersInfo.GatewayList` vs `GetAdaptersAddresses.FirstGatewayAddress` | both written from that same value; `"0.0.0.0"` counts as absent |
| `IfIndex` | real, so `GetIfEntry` and `IP_UNICAST_IF` stay valid |

The one field that deliberately stays real is `IfIndex`, because faking it is what broke
`IP_UNICAST_IF` and `bind()` in the first place. netenv used `1`, which also happens to be
the loopback index; that it still worked is evidence the verdict does not cross-check the
index, so keeping the real one costs nothing.

The presented record is dumped once per process, so a run that still fails reports every
field rather than requiring another round of guessing:

```
ADAPTER_HOOK  presented: if_index=10 if_type=6 oper=1 flags=0x3E5 mtu=1500
              ip=172.16.10.235 gw=172.16.10.254 dns=100.127.129.129 exclusive=1
```
## 14. The cause, confirmed

`FUN_1403c0270` is `alwAuthPhaseGateway`, the gateway phase of the ALL.Net authentication
state machine (its log tag is `alwAuthPhaseGateway`). In its first phase it performs a
comparison and fails immediately:

```c
puVar8 = FUN_1403b0f20();          /* the network state block */
if ((*(int *)(puVar8 + 7) == 0) &&
    ((*(uint *)((longlong)puVar8 + 0xcc) & *(uint *)(puVar8 + 0x19)) !=   /* gateway & mask */
     (*(uint *)((longlong)puVar8 + 0xc4) & *(uint *)(puVar8 + 0x19)))) {  /* address & mask */
    FUN_1403c74a0(0xfffffffe, 0x1f42);                                    /* 0x1F42 = 8002 */
    ...
```

`puVar8` is `undefined8 *`, so the three offsets are bytes: `+0xc4` the interface
address, `+0xc8` the mask, `+0xcc` the gateway. The test is:

> **`(gateway & mask) != (address & mask)` -> fail with 8002.**

That is a pure integer comparison. It sends nothing, which is why the gateway item turns
BAD immediately and why the field log contained no `IcmpSendEcho2` line at all, and it is
the same `0x1F42` seen in the control run ("IP ADDRESS BAD then error 8002").

### Why netenv never failed it

netenv reported `subnet | routerSuffix` as the gateway and `subnet | addrSuffix` as the
address. Both are inside the `/24` it also reported, so `gateway & mask == address & mask`
held trivially. It did not have to send a packet either - it simply never had a gateway
outside its own subnet, because it invented both numbers from the same subnet.

A real adapter carries no such guarantee. A flat L2 segment such as ZeroTier can report a
gateway on a different prefix, and the check then fails on the arithmetic alone.

### Why every earlier attempt missed it

- The ICMP hook was written for a probe that this code path never reaches; the observed
  absence of `IcmpSendEcho2` calls is consistent with the comparison above.
- Filling in a gateway only when the field was *absent* left the case that actually
  occurs - a gateway present but outside the prefix - completely untouched.
- `GetBestRoute` feeds `alwAuthPhaseDefaultGateway` (a different phase, `FUN_1403c00d0`),
  not this one, so changing it could not have fixed the gateway verdict.

### The rule the hook now applies

The gateway presented to the game is kept only when it satisfies exactly the condition
this phase checks:

```
(ntohl(gateway) & mask) == (ntohl(interface_address) & mask)
```

Otherwise it is replaced with `subnet | routerSuffix`, which satisfies it by construction,
and the same value is used for the route next hop and for both enumeration APIs. The
replacement is reported at start-up, naming the address that was rejected and why.

## 15. NUMBER OF HOP: why it read 1 under netenv, and why it hung at CHECKING

This item is a **traceroute result**, not a ping. It is the TTL the trace needed to reach
the ALL.Net authentication server.

### The chain

```
am::networktest::HopsChecker                 RTTI 0x1408ac288, vftable 0x1406d56c8
  update              0x140296230
  -> FUN_1402471c0(network::Manager)  "has LocationRouterChecker finished?"
       reads Manager+0x1138
         == LocationRouterChecker+0x148
            <- written by FUN_140294c80 from HopsCounter+0x1e4
                 <- am::network::HopsCounter::update 0x1402aafe0
                      -> altrGetResultTtl 0x1403b9ff0
                           -> the ALL.Net traceroute state in DAT_1409d1890
```

`LocationRouterChecker` sits at `Manager+0xff0`, so `0xff0 - 0x320 + 0xe18 = 0x1138`
resolves the offset the item reads. The trace itself is owned by
`alwAuthPhaseTraceroute` (`0x1403c1a00`), which calls `altrStartTraceroute`
(`0x1403ba570`); `altrGetStatus` (`0x1403ba260`) drives it, and
`altrServerMain` (`0x1403d7d30`) sends the probes.

### Why the answer was always exactly 1

The trace starts at TTL 1: `FUN_1403ba120` sets the state word to 1, and `FUN_1403d7a60`
gives the first `n` probes TTL 1 (three, in the default 10-timeout / 3-round setup).
`FUN_1403f0b00` forwards that value as `RequestOptions->Ttl`:

```c
local_28.Ttl = *param_1;              // the probe's TTL, i.e. 1 on the first round
IcmpSendEcho2(h, event, NULL, NULL, dest, NULL, 0, &local_28, ...);
if (sent == 0 && GetLastError() != 0x3E5) { /* real failure */ }
```

netenv's `hook_IcmpSendEcho2` (`netenv.c:490-559`) never reads `RequestOptions` and never
transmits anything. It fills `pong->Status = IP_SUCCESS` and signals the event for **every**
destination. So the very first TTL=1 probe is indistinguishable from a probe that reached
the server, `FUN_1403d7850` marks the probe done, `FUN_1403d75c0` sees a completed probe
with status 0 and ends the trace, and `FUN_1403b9ff0` reports `ttls = 1`.

The 1 was therefore never a measurement. It is a constant produced by answering the first
probe of a trace that never ran.

### Why the takeover left it at CHECKING

Our hook scoped virtualisation to the presented subnet, on the reasoning that a real
failure outside the LAN should still be visible. The trace's target is the ALL.Net
authentication server, a public address, so those probes were passed through to the real
network. When that path does not answer - ICMP filtered, target unreachable, or the
presented interface pinned as the egress - the item never leaves CHECKING, and the network
test never finishes, which keeps the game from starting.

### What it now does

`icmpScope=all` (default) answers every destination, which reproduces netenv exactly:
NUMBER OF HOP reads 1 and the test completes. `icmpScope=subnet` keeps the strict behaviour
for anyone who wants a real measurement and can tolerate the stall, and start-up says so.

This is deliberately not an attempt to measure the real hop count. Reproducing a real
traceroute would mean answering TTL-expired probes on behalf of the routers in between,
which no hook can do faithfully without knowing the topology. Reporting the same 1 netenv
reported keeps the item's only consumer - a pass/fail line on the test screen - honest
about what it is.

Evidence: `tests/probe_icmp_scope.cpp` drives `hook_IcmpSendEcho2` directly for both
scopes, at TTL 1 and TTL 7, and asserts the async contract (`0` returned,
`ERROR_IO_PENDING` set, event signalled, `IP_SUCCESS` in the reply).