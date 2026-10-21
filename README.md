# chusan Network Hook

Two injection DLLs that take over the local-network behaviour of `chusan` from segatools'
`[netenv]`, so that in-store LAN play works with the stock `segatools.ini` unchanged.

- chooses one network interface and presents it to the game the way `[netenv]` did, without
  inventing an address;
- pins the game's LAN broadcasts to that interface, including the directed subnet broadcast
  the game actually uses;
- binds outgoing game TCP connections to the same address;
- answers the network-test items that otherwise fail on a segment with no router;
- optionally virtualises LAN Install so UDP 40112 and TCP 40110 never reach the network.

See [`docs/adapter-selection.md`](docs/adapter-selection.md) for the disassembly and
measurements behind all of it.

## Version support

Tested with SDHD 2.50. Other versions have not been tested.

## Build

From an MSVC Developer Command Prompt, or any prompt on a machine with Visual Studio Build
Tools:

```bat
build.bat
```

That produces:

- `build\chusan_network_hook_x64.dll` for `amdaemon.exe`;
- `build\chusan_network_hook_x86.dll` for `chusanApp.exe`;
- x64 and x86 smoke-test executables;
- `build\probe_icmp_x64.exe`, which exercises the ICMP behaviour directly;
- a copy of `network_hook.ini` beside the DLLs.

```bat
build\network_hook_smoketest_x64.exe build\chusan_network_hook_x64.dll
build\network_hook_smoketest_x86.exe build\chusan_network_hook_x86.dll
build\probe_icmp_x64.exe
```

## Injection

Load the matching DLL as an additional `capnhook` module. `amdaemon.exe` is the 64-bit
process and owns LAN Install ports 40110/40112; `chusanApp.exe` is the 32-bit process and
owns Party/Setting/Advertise on 50200-50202. Loading only one leaves the other unmodified.

```bat
start "AM Daemon" /min inject_x64 -d -k chusanhook_x64.dll -k chusan_network_hook_x64.dll amdaemon.exe -c config_common.json config_server.json config_client.json config_cvt.json config_sp.json config_hook.json
inject_x86 -d -k chusanhook_x86.dll -k chusan_network_hook_x86.dll chusanApp.exe
```

Both `-k` names are resolved against the working directory, which is the game's `bin`
directory (that is what `pushd %~dp0` in `launch.bat` establishes), so the two hook DLLs have
to be there. Copy them in from the build output before launching:

```bat
copy build\chusan_network_hook_x64.dll bin\
copy build\chusan_network_hook_x86.dll bin\
```

Place `network_hook.ini` in the same directory as each injected DLL. Both processes may
share one configuration when both DLLs are stored together.

## Configuration

The supplied file enables everything with automatic interface choice. All Boolean fields
use `0` and `1`.

```ini
[network]
enable=1
interface=
mode=auto
exclusive=1
allowLoopback=0
forceDirectedBroadcast=1
forceLimitedBroadcast=1
virtualizeIcmp=1
overrideBestRoute=1
forceTcpSource=1
strict=1

[lanInstall]
enable=1

[segatools]
path=

[log]
enable=1
detailed=0
writeFile=0
```

### Choosing the interface

`[network] interface` accepts an IPv4 address, an adapter friendly name, or a numeric
interface index. Left empty, the hook decides:

1. the address implied by `segatools.ini` — `[keychip] subnet` with `[netenv] addrSuffix` —
   **if a real adapter owns it**. This is the common case and what makes the stock file
   work;
2. the only acceptable adapter inside `[keychip] subnet`;
3. the only acceptable adapter with a routable IPv4.

A name that does not match is a hard error, never a silent fall-through to the automatic
order. A non-ASCII friendly name requires `network_hook.ini` to be saved as UTF-16, because
the Windows profile API reads an ANSI file as the system code page; the numeric index always
works and needs no encoding.

"Acceptable" means a link type the game can use: Ethernet, or wireless (rewritten to
Ethernet). TAP, Tailscale and similar adapters report a link type the game rejects anyway,
so they are not counted, which keeps them from making the choice look ambiguous.

`mode=compat` additionally reproduces netenv's synthetic adapter when nothing real
qualifies. It is off by default because that fake address is owned by no adapter, so
`bind()` to it fails with `10049 WSAEADDRNOTAVAIL` unless it happens to be real. With
`mode=auto` nothing is fabricated: the hook says what it could not find and leaves the real
list alone.

### How the adapter is presented

The hook rewrites **only the fields the game refuses** and keeps the real identity:

- `chusanApp.exe` accepts `IP_ADAPTER_INFO.Type == 6` and nothing else, so a wireless
  adapter is reported as Ethernet. Ethernet needs no rewrite at all.
- `IfIndex`, the IPv4 address and the prefix stay real. That is what makes `bind()` and
  `IP_UNICAST_IF` work on the real stack, and what keeps `amdaemon`, which looks adapters up
  by index through a second API, consistent.
- `exclusive=1` presents only the chosen adapter, so a lower-index adapter cannot win by
  accident — the game takes the lowest index, which may be the wrong NIC.

The gateway and the DNS server list are the two substituted values. Both must be usable on
the presented segment, so the hook keeps a real gateway only when it lies inside
`address & mask` and otherwise supplies the segment router — `[keychip] subnet` with
`[netenv] routerSuffix`, which is the address netenv invented, and only when that address
really falls inside the presented subnet. When the configured router is outside the selected
adapter's subnet — or `segatools.ini` is absent — the fallback is the **last usable host of
the presented subnet** (`(network | ~mask) - 1`, e.g. `172.16.63.254` on a `/18`). That one
value is used consistently for the presented gateway, the adapter field, the
`GetAdaptersInfo` string and the route next hop, because the game cross-checks them.

That last point is not decoration: `chusanApp` reads the gateway from `GetAdaptersInfo`
during enumeration, so an out-of-subnet gateway left in that API while the other one was
corrected is exactly the inconsistency that makes the item fail. An empty DNS list,
likewise, is a state netenv never produced.

`[netenv] enable=1` in `segatools.ini` takes precedence: segatools patches the same three
functions at the executable entry point and would overwrite these hooks, so the hook does not
fight it. It reports the conflict, naming the file to edit. Set `[netenv] enable=0` to hand
adapter presentation to this hook.

### Interface pinning

`forceLimitedBroadcast` covers `255.255.255.255`; `forceDirectedBroadcast` covers the subnet
broadcast the game actually addresses, e.g. `192.168.139.255`. Both apply `IP_UNICAST_IF`
with the **real** interface index before the packet is sent, leaving destination and payload
untouched. The scope is UDP 50200 for Party, 50201 for Setting, 50202 for Advertise, and UDP
40112 when LAN Install virtualization is disabled.

`forceTcpSource=1` binds an unbound client socket to the interface address before connecting
to TCP 40110 or 50200-50202. Connections to `127.0.0.0/8` are left alone so the game's local
Join Party path can reach itself. Listener sockets are never restricted.

`overrideBestRoute=1` answers `GetBestRoute` from the presented adapter for every
destination, as netenv did. It is a query only: real egress still follows the routing table,
so the game server keeps its own path.

`strict=1` decides what happens when an operation needs an interface and does not have one.
It only ever applies to a **misconfigured** interface — one the user named that cannot be
resolved: there the affected operation fails instead of silently using a different adapter,
and `strict=0` lets it fall back to Windows routing. An *absent* configuration is not a
misconfiguration: if `[network] interface` is empty and no automatic candidate qualifies, the
hook reports that once and leaves traffic unpinned, and `strict` does not change that, in
either setting. So `strict=0` relaxes the explicit-name case only.

### ICMP and the network-test items

`virtualizeIcmp=1` answers every ICMP echo as a success, in the same asynchronous form
`netenv` used (`IP_SUCCESS` in the reply, `ERROR_IO_PENDING` returned, the caller's event
signalled). Two items depend on it:

- **GATEWAY** echoes the presented gateway. On a segment with no router — ZeroTier and other
  flat L2 networks — this fails without it, because the item has no address to compare
  against.
- **NUMBER OF HOP** is a traceroute to the ALL.Net authentication server. Answering every
  probe holds it at **1**, which is exactly what it has always read under netenv: the trace
  starts at TTL 1 and terminates on its first answered probe. That number is not a
  measurement of the real path, and the game only compares it against zero.

Answering every destination is not cosmetic for the second item. Scoping the answer to the
presented subnet sends the traceroute's probes to a public address out on the real network;
when that path does not answer, the item stays at `CHECKING`, the network test never
finishes, and the game does not start. `virtualizeIcmp=0` is available for a host whose real
ICMP path is known to work, and the hook warns at start-up that both items then depend on it.

### Preflight diagnostics

Every decision is reported before the game starts: which `segatools.ini` was found, the
subnet and suffix read from it, the resolved adapter with its address, mask, prefix and
index, whether any field had to be rewritten, and every problem as an explicit `ERROR` line
with the fix. Notable checks:

- the chosen address is not inside `[keychip] subnet`;
- several interfaces could each carry the LAN;
- no interface qualifies, naming what was looked for;
- `[netenv] enable=1` would take adapter presentation back.

### LAN Install virtualization

`[lanInstall] enable=1` keeps LAN Install off the network entirely:

- `bind` for ports 40110 and 40112 reports success without binding the socket;
- TCP 40110 `listen`, `connect`, `accept` and the related WSA calls are simulated locally;
- UDP 40112 sends report success without transmitting;
- LAN Install receives report `WSAEWOULDBLOCK` without reading network data;
- the known x64 `amdaemon.exe` duplicate-server check is patched to return `false` after its
  prologue is verified.

Set `enable=0` to pass real 40110/40112 traffic through WinSock. The duplicate-server patch
is then not installed, and the `[network]` settings can pin real LAN Install traffic to the
configured adapter.

This does not fabricate a remote server, transfer installation data, or complete an
`amdaemon` state machine that requires a valid received beacon.

### Logging

`[log] enable=0` silences everything except one `STATUS` line, always printed to `stderr` and
`OutputDebugStringA`. That line is the proof the DLL loaded: it names the process, the
architecture, whether the WinSock and LAN Install hooks installed, whether adapter
presentation is active, and which interface was chosen.

With `enable=1` and `detailed=0` there are three lines at start-up — the status, the chosen
interface, and any decision that changed what the game will see. Failures print as `ERROR`
with the operation, the service, the address and the fix.

`detailed=1` adds the diagnostic stream: every hook installation and its coverage, adapter
tables, route lookups, socket lifecycle, endpoints, byte counters, hexadecimal payload
summaries, TCP stream framing and UDP frame parsing for 50200-50202, and AES-128-ECB prefix
decoding with known message names where the packet format matches.

`writeFile=1` writes the same output to:

```text
network_hook_logs\network_hook_YYYYMMDD_HHMMSS_pidNNNN.log
```

The directory is created beside the injected DLL. Each line is flushed, so evidence survives
an unexpected exit.

## How this differs from `[netenv]`

| | netenv | this hook |
|---|---|---|
| adapter identity | invented: `subnet \| addrSuffix`, mask `/24`, `IfIndex = 1`, MAC `01:02:03:04:05:06` | the real adapter: real address, mask, prefix, `IfIndex`, MAC |
| acceptance by the game | fakes the whole enumeration | rewrites only `Type`/`IfType` when the link type is not Ethernet |
| `IP_UNICAST_IF` | `1`, a hardcoded index that pins nothing (`netenv.c:253`) | the real index, so the egress actually moves |
| directed broadcast | rewritten to `255.255.255.255` (`redirectBroadcast`), hiding a subnet mismatch | sent as the game addressed it, pinned to the real interface |
| `bind()` | only safe when the fake address happens to equal a real one; otherwise `10049 WSAEADDRNOTAVAIL` | always safe, because the address is owned |
| `GetBestRoute` | fixed row, `IfIndex 1` | presented interface, next hop consistent with the adapter |
| gateway | always `subnet \| routerSuffix` | the real one when it is on the presented segment, else the same fallback |
| DNS server list | always `subnet \| routerSuffix` | the real list when present, else the same fallback |
| ICMP | every echo `IP_SUCCESS`, TTL ignored | same, deliberately |
| configuration | `[netenv]` must be edited per host | reads `segatools.ini` and works with it unmodified |
| conflicts | patches process-wide, including over other hooks | reports a `[netenv] enable=1` conflict instead of fighting it |
| failures | silent until the game cannot start | a start-up `ERROR` naming the operation and the fix |

In one sentence: **netenv made an adapter that was internally consistent by inventing all of
it; this hook keeps the real adapter and enforces the same consistency on the two fields the
game cross-checks.**

## Limitations

| Symptom | Protocol and port | Possible causes |
| --- | --- | --- |
| LAN Install cannot find a server | UDP 40112, TCP 40110 | `lanInstall.enable`, duplicate-server filtering, firewall rules, adapter selection, or a network that does not pass the beacon |
| Setting does not complete | UDP/TCP 50201 | the broadcast used the wrong adapter, or the host address in its payload is not reachable |
| Recruitment is not visible | UDP 50200 | wrong broadcast interface, firewall rules, VLAN isolation, router broadcast handling, or VPN limitations |
| An invitation is visible but clicking it does nothing | TCP 50200 | the advertised host address is unreachable, TCP uses the wrong source interface, or the peer connection is blocked |
| Advertise state does not synchronize | UDP 50202 | wrong interface, firewall rules, or broadcast isolation |
| The game reports no usable network adapter | adapter enumeration | every adapter was refused: on Wi-Fi, `[netenv] enable=1` is still in control |
| Startup prints `[netenv] enable=1 ... leaving it alone` | adapter enumeration | segatools owns adapter presentation; set `[netenv] enable=0` so this hook can take over |
| `Setting` bind fails with `10013 WSAEACCES` | TCP 50201 | the port falls inside a Windows excluded range, not that it is occupied. Exclusion ranges are per protocol. Remove the range or stop `winnat` |

## License

[2-Clause BSD License](LICENSE)
