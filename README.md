# chusan Network Hook

An experimental pair of injection DLLs for controlling and diagnosing the local network behavior of `chusan`.

The project provides four related features:

- choose one network interface and present it to the game the way segatools' `[netenv]`
  did, without inventing an address;
- pin the game's LAN broadcasts to that interface, including the directed subnet
  broadcast the game actually uses;
- bind outgoing game TCP connections to the same local IPv4 address;
- optionally virtualize LAN Install so that UDP 40112 and TCP 40110 never reach the network.

With no configuration at all, the hook reads `segatools.ini` and reuses the address
segatools already tells the game to expect. See
[`docs/netenv-takeover.md`](docs/netenv-takeover.md) for the design and
[`docs/adapter-selection.md`](docs/adapter-selection.md) for the evidence behind it.

## Version support

Tested with:

- SDHD 2.50

Other versions have not been tested.

## Build

Run the build script from an MSVC Developer Command Prompt, or from a regular command prompt on a machine with Visual Studio Build Tools installed:

```bat
build.bat
```

The script builds:

- `build\chusan_network_hook_x64.dll` for `amdaemon.exe`;
- `build\chusan_network_hook_x86.dll` for `chusanApp.exe`;
- x64 and x86 smoke-test executables;
- a copy of `network_hook.ini` beside the DLLs.

Run the smoke tests with:

```bat
build\network_hook_smoketest_x64.exe build\chusan_network_hook_x64.dll
build\network_hook_smoketest_x86.exe build\chusan_network_hook_x86.dll
```

## Injection

Load the matching DLL as an additional `capnhook` module:

```bat
inject_x64 -d -k chusanhook_x64.dll -k chusan_network_hook_x64.dll amdaemon.exe ...
inject_x86 -d -k chusanhook_x86.dll -k chusan_network_hook_x86.dll chusanApp.exe
```

Place `network_hook.ini` in the same directory as each injected DLL. Both processes may share one configuration when both DLLs are stored together.

For a normal `chusan` launch, load both architecture-specific DLLs. `amdaemon.exe` is a 64-bit process and owns LAN Install ports 40110 and 40112. `chusanApp.exe` is a 32-bit process and owns the Party, Setting, and Advertise traffic on ports 50200-50202. Loading only one DLL leaves the other process unmodified. If LAN Install virtualization is disabled and only Party/Setting/Advertise traffic is being tested, the x86 DLL is the relevant network hook, while the standard `chusanhook_x64.dll` is still required for the normal `amdaemon.exe` startup.

A matching `launch.bat` therefore contains both injections:

```bat
start "AM Daemon" /min inject_x64 -d -k chusanhook_x64.dll -k chusan_network_hook_x64.dll amdaemon.exe -c config_common.json config_server.json config_client.json config_cvt.json config_sp.json config_hook.json
inject_x86 -d -k chusanhook_x86.dll -k chusan_network_hook_x86.dll chusanApp.exe
```

## Configuration

The supplied configuration enables interface selection with automatic choice, LAN Install
virtualization, and concise console logging.

```ini
[network]
enable=1
interface=
mode=auto
exclusive=1
allowLoopback=0
forceDirectedBroadcast=1
forceLimitedBroadcast=1
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

All Boolean fields use `0` for disabled and `1` for enabled.

### Choosing the interface

`[network] interface` accepts an IPv4 address, an adapter friendly name, or a numeric
interface index. Leave it empty to let the hook decide:

1. the address implied by `segatools.ini` — `[keychip] subnet` combined with
   `[netenv] addrSuffix` — **if a real adapter owns it**;
2. the only acceptable adapter inside `[keychip] subnet`;
3. the only acceptable adapter with a routable IPv4.

"Acceptable" means a link type the game can use: Ethernet, or wireless (rewritten to
Ethernet). TAP, Tailscale and similar virtual adapters report a link type the game
rejects anyway, so they are not counted — which prevents them from making the choice
look ambiguous.

`mode` selects the policy when nothing real qualifies:

| value | behaviour |
| --- | --- |
| `auto` | the order above; if nothing qualifies, no adapter is presented and the hook says so |
| `native` | never synthesise; fail loudly |
| `compat` | reproduce netenv's synthetic adapter, for hosts where nothing real qualifies |

### How the adapter is presented

The hook rewrites **only the fields the game refuses**, and keeps the real identity:

- `chusanApp.exe` accepts `IP_ADAPTER_INFO.Type == 6` and nothing else, so a wireless
  adapter is reported as Ethernet. Ethernet needs no rewrite at all.
- `IfIndex`, the IPv4 address and the prefix stay real. That is what makes
  `bind()` and `IP_UNICAST_IF` work on the real stack, and what keeps `amdaemon`, which
  looks adapters up by index through a second API, consistent.
- `exclusive=1` presents only the chosen adapter, so a lower-index adapter cannot win by
  accident.

The adapter's DNS server list is preserved when it has one, and falls back to the
`[netenv] routerSuffix` address when it does not, because `chusanApp` reads
`FirstDnsServerAddress` during enumeration. Name resolution itself is untouched: that is
segatools' separate `[dns]` component and stays active regardless of `[netenv] enable`.

`[netenv] enable=1` in `segatools.ini` takes precedence: segatools patches the same three
functions at the executable entry point and would overwrite these hooks, so the hook does
not fight it. It reports the conflict instead, naming the file to edit. Set
`[netenv] enable=0` to hand adapter presentation to this hook.

### Interface pinning

`forceLimitedBroadcast` covers `255.255.255.255`; `forceDirectedBroadcast` covers the
subnet broadcast the game actually addresses, e.g. `192.168.139.255`. Both apply
`IP_UNICAST_IF` with the **real** interface index before the packet is sent, leaving the
destination and payload untouched. The scope is UDP 50200 for Party, 50201 for Setting,
50202 for Advertise, and UDP 40112 when LAN Install virtualization is disabled.

`virtualizeIcmp=1` answers ICMP echoes as successes, in the same asynchronous form
segatools' netenv used. Two network-test items depend on it: GATEWAY, which echoes the
presented gateway, and NUMBER OF HOP, whose traceroute targets the ALL.Net authentication
server. On a segment with no router - ZeroTier and other flat L2 networks - the gateway
check fails without it.

`icmpScope=all` (default) answers every destination, as netenv did: NUMBER OF HOP reads 1,
which is what it has always read under netenv. `icmpScope=subnet` answers only inside the
presented subnet, which leaves the hop traceroute running against the real network; if
that path does not answer, the item stays at CHECKING and the network test never finishes,
so the game does not start.

`forceTcpSource=1` binds an unbound client socket to the interface address before
connecting to TCP 40110 or 50200-50202. Connections to `127.0.0.0/8` are left alone so the
game's local Join Party path can reach itself. Listener sockets are never restricted.

`strict=1` turns a **misconfigured** interface into a hard block: if `interface` names
something that cannot be resolved, the affected operation fails instead of silently using
a different adapter. A hook that simply has not worked out an interface is reported once
and left unpinned rather than blocked — an absent configuration is not a misconfiguration.

### Preflight diagnostics

Every decision is reported before the game starts: which `segatools.ini` was found, the
subnet and suffix read from it, the resolved adapter with its address, mask, prefix and
index, whether any field had to be rewritten, and every problem as an explicit `ERROR`
line with the fix. Notable checks:

- the chosen address is not inside `[keychip] subnet`;
- several interfaces could each carry the LAN;
- no interface qualifies, naming what was looked for;
- `[netenv] enable=1` would take adapter presentation back.

### LAN Install virtualization

`[lanInstall] enable=1` preserves the existing isolated LAN Install behavior:

- `bind` for ports 40110 and 40112 reports success without binding the socket;
- TCP 40110 `listen`, `connect`, `accept`, and related WSA calls are simulated locally;
- UDP 40112 sends report success without transmitting a packet;
- LAN Install receives report `WSAEWOULDBLOCK` without reading network data;
- the known x64 `amdaemon.exe` duplicate-server check is patched to return `false` after its prologue is verified.

Set `enable=0` to pass real 40110 and 40112 traffic through WinSock. In that case the duplicate-server patch is not installed, and the `[network]` settings can pin real LAN Install traffic to the configured adapter.

LAN Install virtualization does not fabricate a remote server, transfer installation data, or complete an `amdaemon` state machine that requires a valid received beacon.

### Logging

`[log] enable=0` disables all hook logging.

Two `STATUS` lines are always printed to `stderr` and `OutputDebugStringA`, even when `log.enable=0`. The first line shows the configuration path and the loaded Boolean values. The second line reports the process architecture, IAT hook result, LAN Install hook result, and network-interface state. These lines are intended to confirm that the DLL loaded and which settings it applied.

With `enable=1` and `detailed=0`, the DLL prints concise English messages for startup, configuration, selected interfaces, forced routes, and actionable failures. Messages are sent to both `OutputDebugStringA` and `stderr`, so they are visible in an `inject -d` console.

Set `detailed=1` to enable the diagnostic logger ported from `chusan_netdiag`. Detailed output includes:

- adapter addresses, metrics, interface indexes, and route selection;
- socket lifecycle and WinSock return values;
- local, remote, and target endpoints;
- byte counters and hexadecimal payload summaries;
- TCP stream framing and UDP frame parsing for ports 50200-50202;
- AES-128-ECB prefix decoding with known message names when the packet format matches the recovered game protocol.

`writeFile=1` additionally writes the same output to:

```text
network_hook_logs\network_hook_YYYYMMDD_HHMMSS_pidNNNN.log
```

The directory is created beside the injected DLL. File output is flushed after every line to preserve evidence if the process exits unexpectedly.

## Limitations

This project cannot guarantee connectivity under all circumstances. If you are still unable to connect, please check the following:

| Symptom | Protocol and port | Possible causes |
| --- | --- | --- |
| LAN Install cannot find a server | UDP 40112, TCP 40110 | `lanInstall.enable`, duplicate-server filtering, firewall rules, adapter selection, or a network that does not pass the beacon |
| Setting does not complete | UDP/TCP 50201 | The limited broadcast used the wrong adapter, or the host address in the broadcast payload is not reachable |
| Recruitment is not visible | UDP 50200 | Wrong broadcast interface, firewall rules, VLAN isolation, router broadcast handling, or VPN limitations |
| An invitation is visible but clicking it does nothing | TCP 50200 | The advertised host address is unreachable, TCP uses the wrong source interface, or the peer connection is blocked |
| Advertise state does not synchronize | UDP 50202 | Wrong interface, firewall rules, or broadcast isolation |
| The game reports no usable network adapter | adapter enumeration | Every adapter was refused: on Wi-Fi, [netenv] enable=1 in segatools.ini |
| Startup prints [netenv] enable=1 ... leaving it alone | adapter enumeration | segatools owns adapter presentation; set [netenv] enable=0 so this hook can take over |

## License

[2-Clause BSD License](LICENSE)
