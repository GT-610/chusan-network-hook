# chusan Network Hook

An experimental pair of injection DLLs for controlling and diagnosing the local network behavior of `chusan`.

The project currently provides three related features:

- pin the game's limited broadcasts to a configured Windows network interface;
- bind outgoing game TCP connections to the same local IPv4 address;
- optionally virtualize LAN Install so that UDP 40112 and TCP 40110 never reach the network.

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

The supplied configuration is conservative: interface forcing is disabled, LAN Install virtualization is enabled, concise console logging is enabled, and file logging is disabled.

```ini
[network]
enable=0
interfaceAddress=192.168.139.10
forceLimitedBroadcast=1
forceTcpSource=1
strict=1

[lanInstall]
enable=1

[log]
enable=1
detailed=0
writeFile=0
```

All Boolean fields use `0` for disabled and `1` for enabled.

### Network interface control

`[network] enable=1` activates interface selection. `interfaceAddress` must be an IPv4 address currently assigned to an active Windows adapter. Using the address instead of an interface index avoids relying on an index that may change after adapter installation or reboot.

`forceLimitedBroadcast=1` applies `IP_UNICAST_IF` before relevant UDP packets are sent to `255.255.255.255`. The destination address and packet payload are not changed. The current scope is:

- UDP 40112, when LAN Install virtualization is disabled;
- UDP 50200 for Party;
- UDP 50201 for Setting;
- UDP 50202 for Advertise.

`forceTcpSource=1` binds an unbound client socket to `interfaceAddress` before connecting to TCP 40110 or 50200-50202. Connections to `127.0.0.0/8` are left on the loopback interface so the game's local Join Party path can connect to itself. Listener sockets are not restricted and may continue to listen on `0.0.0.0`.

`strict=1` blocks the affected operation when the configured address is missing, the adapter is down, or Windows rejects the interface selection. This prevents a silent fallback to an unintended adapter. With `strict=0`, the hook reports the problem and lets Windows use its normal routing rules.

Interface forcing controls the local socket path. It does not rewrite an IPv4 address already serialized inside a game packet. The host address advertised by the game must still be reachable through the selected interface.

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
- AES-128-ECB prefix decoding with known message names when the packet format matches the recovered game protocol;
- in `chusanApp.exe`, the per-credit BONUS TRACK decision: the track limit and the three predicates that gate its "force four tracks" branch, logged with the in-store matching flag at `UserDataManager::Impl+0x14E8`.

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

## License

[2-Clause BSD License](LICENSE)
