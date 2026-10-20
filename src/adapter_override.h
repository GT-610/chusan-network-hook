// Presents one chosen interface to the game through the three adapter-enumeration
// APIs, in place, without inventing an identity.
//
// Rationale and evidence: docs/adapter-selection.md.
// In short:
//   * chusanApp accepts only IP_ADAPTER_INFO.Type == 6;
//   * amdaemon additionally rejects Type 1 and 24, and looks adapters up by IfIndex
//     through GetAdaptersAddresses, so the index must stay real;
//   * bind() to an address no adapter owns fails with WSAEADDRNOTAVAIL, so the
//     address must stay real.
//
// Therefore the normal path rewrites only the fields the game refuses and filters
// the rest of the chain. Fabrication (netenv's approach) is kept solely as the
// legacy path for hosts where no acceptable adapter exists at all.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr ULONG kEthernetType = 6;      // MIB_IF_TYPE_ETHERNET / IF_TYPE_ETHERNET_CSMACD
constexpr ULONG kWirelessType = 71;     // IF_TYPE_IEEE80211
constexpr ULONG kLoopbackType = 24;     // IF_TYPE_SOFTWARE_LOOPBACK
// The MAC length netenv presented, and the value amdaemon's GetAdaptersInfo filter tests
// (`+0x194 == 6`). IP_ADAPTER_INFO.Address and IP_ADAPTER_ADDRESSES.PhysicalAddress both
// hold it; the latter has room for 8, which is not permission to report 8.
constexpr ULONG kMacLength = 6;

// A chain of IP_ADAPTER_*_ADDRESS entries counts as usable only if some node really
// carries an AF_INET address that is not 0.0.0.0. Testing the head pointer alone is not
// enough: Windows hands back a placeholder node for an adapter whose gateway is
// unspecified, and treating that as "the adapter has a gateway" skips the fallback and
// leaves the game probing 0.0.0.0, which fails immediately rather than timing out.
//
// Offsets come from offsetof rather than being written out: Next and Address both shift
// with the pointer size, and a hard-coded x64 offset reads iSockaddrLength on x86 and
// dereferences it as a pointer.
inline bool chain_has_ipv4(const void *head) {
    for (const unsigned char *node = reinterpret_cast<const unsigned char *>(head);
         node != nullptr;
         node = *reinterpret_cast<const unsigned char *const *>(
             node + offsetof(IP_ADAPTER_DNS_SERVER_ADDRESS, Next))) {
        const SOCKET_ADDRESS *address = reinterpret_cast<const SOCKET_ADDRESS *>(
            node + offsetof(IP_ADAPTER_DNS_SERVER_ADDRESS, Address));
        if (address->lpSockaddr == nullptr) continue;
        if (address->lpSockaddr->sa_family != AF_INET) continue;
        if (address->iSockaddrLength < (INT)sizeof(sockaddr_in)) continue;
        const sockaddr_in *v4 = reinterpret_cast<const sockaddr_in *>(address->lpSockaddr);
        if (v4->sin_addr.s_addr == 0) continue;
        return true;
    }
    return false;
}


struct AdapterPresentation {
    bool present = false;       // install any shaping at all
    bool exclusive = true;      // hide adapters other than the chosen one
    bool fabricate = false;     // no acceptable real adapter: synthesise one
    bool forced_type = false;   // Type/IfType had to be rewritten to Ethernet

    // Real adapter, used when !fabricate.
    ULONG if_index = 0;
    in_addr address = {};
    in_addr mask = {};
    ULONG prefix_length = 24;
    unsigned char mac[8] = {};
    ULONG mac_length = 6;

    // Fabrication parameters, used when fabricate (netenv-compatible).
    in_addr synthetic_address = {};
    in_addr synthetic_mask = {};
    in_addr synthetic_gateway = {};

    // chusanApp reads IP_ADAPTER_ADDRESSES.FirstDnsServerAddress (+0x1c) while it
    // enumerates (allnet_enumerate_adapters), so the list has to be non-empty even
    // when the real adapter has no DNS server configured. netenv always reported the
    // router here; this keeps that behaviour only as the fallback.
    bool dns_fallback_enabled = true;
    in_addr dns_fallback = {};

    // ZeroTier and similar flat L2 segments report no gateway at all. netenv always
    // supplied subnet|routerSuffix, and the gateway check has nothing to compare when the
    // list is empty, so it reports BAD before anything is sent. One address serves both
    // enumeration APIs and the route next hop, because the game cross-checks them, and the
    // two APIs disagree in practice: the addresses API returns a node list, while
    // IP_ADAPTER_INFO signals "no gateway" with the literal string "0.0.0.0".
    bool gateway_fallback_enabled = false;
    in_addr gateway_fallback = {};

    // GetBestRoute rewrite: keeps route lookups pointing at the presented interface when
    // the real lookup would send the packet somewhere else.
    bool route_override_enabled = false;
    DWORD route_next_hop = 0;

    // amdaemon answers two network-test items with IcmpSendEcho2:
    //   - GATEWAY,        alwAuthPhaseGateway    0x1403c0270, echo to the presented gateway;
    //   - NUMBER OF HOP,  alwAuthPhaseTraceroute 0x1403c1a00, TTL probes to the ALL.Net
    //                     authentication server, counted by altrGetResultTtl.
    // netenv answered every echo of every destination with IP_SUCCESS, ignoring TTL
    // (netenv.c:490-559), so the first TTL=1 probe looked like it had reached the server
    // and the item read 1 for the whole segatools era. That number was a constant, not a
    // measurement, and the game only compares it against zero.
    //
    // Answering every destination reproduces exactly that, and is also the only shape that
    // lets the network test finish: the traceroute target is a public address, so anything
    // narrower would send those probes out on the real network, and when that path does
    // not answer the item never leaves CHECKING and the test - hence the game start -
    // hangs on it. virtualize_icmp=false disables the answer entirely, for a host where
    // the real ICMP path is known to work.
    bool virtualize_icmp = true;
};

namespace adapter_override {

inline AdapterPresentation &state() {
    static AdapterPresentation presentation;
    return presentation;
}

// Sink installed by the host translation unit, so the hooks can report what they actually
// did to the game's view instead of the outcome being inferred from a screenshot. A sink
// rather than an extern function because the host's logger lives in an anonymous
// namespace.
//
// Two sinks, because two kinds of message: `log_sink` carries a decision the user may
// have to act on and is always shown; `trace_sink` carries per-call detail and belongs to
// the detailed log only. Keeping them apart is what stops a working run from printing a
// dozen lines about calls that all did the expected thing.
using adapter_log_sink = void (*)(const char *message);

// Call counters: the difference between "the game never asked" and "we answered and it
// still failed" is not visible in the network test screen, only in the log.
inline volatile LONG g_info_calls = 0;
inline volatile LONG g_addresses_calls = 0;
inline volatile LONG g_icmp_calls = 0;
inline volatile LONG g_route_calls = 0;

inline adapter_log_sink &log_sink() {
    static adapter_log_sink sink = nullptr;
    return sink;
}

inline adapter_log_sink &trace_sink() {
    static adapter_log_sink sink = nullptr;
    return sink;
}

inline void emit(adapter_log_sink sink, const char *format, va_list args) {
    if (sink == nullptr) return;
    char message[512] = {};
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    sink(message);
}

inline void adapter_hook_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    emit(log_sink(), format, args);
    va_end(args);
}

inline void adapter_hook_trace(const char *format, ...) {
    va_list args;
    va_start(args, format);
    emit(trace_sink(), format, args);
    va_end(args);
}


using get_adapters_info_fn = ULONG (WINAPI *)(PIP_ADAPTER_INFO, PULONG);
using get_adapters_addresses_fn = ULONG (WINAPI *)(ULONG, ULONG, PVOID,
                                                   PIP_ADAPTER_ADDRESSES, PULONG);
using get_if_table_fn = ULONG (WINAPI *)(PMIB_IFTABLE, PULONG, BOOL);
using get_best_route_fn = DWORD (WINAPI *)(DWORD, DWORD, PMIB_IPFORWARDROW);
using icmp_send_echo2_fn = ULONG (WINAPI *)(HANDLE, HANDLE, void *, PVOID, IPAddr,
                                            LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID,
                                            DWORD, DWORD);

inline get_adapters_info_fn &next_info() {
    static get_adapters_info_fn fn = nullptr;
    return fn;
}
inline get_adapters_addresses_fn &next_addresses() {
    static get_adapters_addresses_fn fn = nullptr;
    return fn;
}
inline get_if_table_fn &next_table() {
    static get_if_table_fn fn = nullptr;
    return fn;
}
inline get_best_route_fn &next_best_route() {
    static get_best_route_fn fn = nullptr;
    return fn;
}
inline icmp_send_echo2_fn &next_icmp() {
    static icmp_send_echo2_fn fn = nullptr;
    return fn;
}

// Formats an address the way IP_ADAPTER_INFO stores it, dotted quad in a fixed buffer.
inline void adapter_gateway_string(const in_addr address, char *out, size_t out_size) {
    const uint32_t host = ntohl(address.s_addr);
    _snprintf_s(out, out_size, _TRUNCATE, "%u.%u.%u.%u",
        (host >> 24) & 255, (host >> 16) & 255, (host >> 8) & 255, host & 255);
}

// Storage for a DNS server entry that has no home in the caller's buffer when the real
// adapter reports none. A single static entry is enough: the game copies the address out
// during enumeration, exactly as it does for netenv's static struct.
struct DnsFallbackEntry {
    IP_ADAPTER_DNS_SERVER_ADDRESS entry;
    sockaddr_in address;
};

inline DnsFallbackEntry &dns_fallback_entry() {
    static DnsFallbackEntry storage;
    return storage;
}

// Same idea for the gateway: one static entry, used only when the real adapter reports
// none. The game copies the address out during enumeration.
struct GatewayFallbackEntry {
    IP_ADAPTER_GATEWAY_ADDRESS entry;
    sockaddr_in address;
};

inline GatewayFallbackEntry &gateway_fallback_entry() {
    static GatewayFallbackEntry storage;
    return storage;
}

// ---------------------------------------------------------------------------
// Fabricated adapter, layout mirrors netenv.c:25-39 so the game sees the same
// shape it has always seen on a netenv host.
// ---------------------------------------------------------------------------
struct Fabricated {
    IP_ADAPTER_ADDRESSES head;
    char name[64];
    wchar_t dns_suffix[64];
    wchar_t description[64];
    wchar_t friendly_name[64];
    IP_ADAPTER_PREFIX prefix;
    IP_ADAPTER_UNICAST_ADDRESS iface;
    IP_ADAPTER_GATEWAY_ADDRESS router;
    IP_ADAPTER_DNS_SERVER_ADDRESS dns;
    sockaddr_in prefix_sa;
    sockaddr_in iface_sa;
    sockaddr_in router_sa;
    sockaddr_in dns_sa;
};

inline void build_fabricated(const AdapterPresentation &p, Fabricated *env) {
    memset(env, 0, sizeof(*env));

    env->head.Length = sizeof(env->head);
    env->head.IfIndex = 1;
    env->head.AdapterName = env->name;
    env->head.FirstUnicastAddress = &env->iface;
    env->head.FirstDnsServerAddress = &env->dns;
    env->head.DnsSuffix = env->dns_suffix;
    env->head.Description = env->description;
    env->head.FriendlyName = env->friendly_name;
    // sizeof(p.mac) is 8 - the array is oversized so GetAdaptersAddresses has somewhere
    // to write - and copying that many bytes would report a MAC length of 8 while
    // hook_GetAdaptersInfo reports AddressLength 6 for the same adapter. amdaemon tests
    // that length (`+0x194 == 6`) before accepting anything, so the two APIs have to
    // agree on 6, which is also what netenv presented (netenv.c:260-263).
    const ULONG mac_length =
        p.mac_length != 0 && p.mac_length < kMacLength ? p.mac_length : kMacLength;
    memcpy(env->head.PhysicalAddress, p.mac, mac_length);
    env->head.PhysicalAddressLength = mac_length;
    env->head.Flags = IP_ADAPTER_DHCP_ENABLED | IP_ADAPTER_IPV4_ENABLED;
    env->head.Mtu = 4200;
    env->head.IfType = kEthernetType;
    env->head.OperStatus = IfOperStatusUp;
    env->head.FirstPrefix = &env->prefix;
    env->head.FirstGatewayAddress = &env->router;

    strcpy_s(env->name, _countof(env->name), "{00000000-0000-0000-0000-000000000000}");
    wcscpy_s(env->dns_suffix, _countof(env->dns_suffix), L"local");
    wcscpy_s(env->description, _countof(env->description), L"Interface Description");
    wcscpy_s(env->friendly_name, _countof(env->friendly_name), L"Fake Ethernet");

    env->iface.Length = sizeof(env->iface);
    env->iface.Flags = 0;
    env->iface.Address.lpSockaddr = (struct sockaddr *)&env->iface_sa;
    env->iface.Address.iSockaddrLength = sizeof(env->iface_sa);
    env->iface.PrefixOrigin = IpPrefixOriginDhcp;
    env->iface.SuffixOrigin = IpSuffixOriginDhcp;
    env->iface.DadState = IpDadStatePreferred;
    env->iface.ValidLifetime = UINT32_MAX;
    env->iface.PreferredLifetime = UINT32_MAX;
    env->iface.LeaseLifetime = 86400;
    env->iface.OnLinkPrefixLength = 24;

    env->prefix.Length = sizeof(env->prefix);
    env->prefix.Address.lpSockaddr = (struct sockaddr *)&env->prefix_sa;
    env->prefix.Address.iSockaddrLength = sizeof(env->prefix_sa);
    env->prefix.PrefixLength = 24;

    env->router.Length = sizeof(env->router);
    env->router.Address.lpSockaddr = (struct sockaddr *)&env->router_sa;
    env->router.Address.iSockaddrLength = sizeof(env->router_sa);

    env->dns.Length = sizeof(env->dns);
    env->dns.Address.lpSockaddr = (struct sockaddr *)&env->dns_sa;
    env->dns.Address.iSockaddrLength = sizeof(env->dns_sa);

    env->prefix_sa.sin_family = AF_INET;
    env->prefix_sa.sin_addr = p.synthetic_address;
    env->iface_sa.sin_family = AF_INET;
    env->iface_sa.sin_addr = p.synthetic_address;
    env->router_sa.sin_family = AF_INET;
    env->router_sa.sin_addr = p.synthetic_gateway;
    env->dns_sa.sin_family = AF_INET;
    env->dns_sa.sin_addr = p.synthetic_gateway;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

inline ULONG WINAPI hook_GetAdaptersInfo(PIP_ADAPTER_INFO info, PULONG size) {
    const AdapterPresentation &p = state();
    if (!p.present) {
        return next_info() ? next_info()(info, size) : ERROR_INVALID_PARAMETER;
    }

    if (p.fabricate) {
        if (info == nullptr || size == nullptr || *size < sizeof(IP_ADAPTER_INFO)) {
            if (size != nullptr) *size = sizeof(IP_ADAPTER_INFO);
            return ERROR_BUFFER_OVERFLOW;
        }
        PIP_ADAPTER_INFO entry = info;
        memset(entry, 0, sizeof(*entry));
        strcpy_s(entry->AdapterName, _countof(entry->AdapterName), "Fake Ethernet");
        strcpy_s(entry->Description, _countof(entry->Description), "Adapter Description");
        entry->AddressLength = kMacLength;
        memcpy(entry->Address, p.mac, kMacLength);
        entry->Index = 1;
        entry->Type = kEthernetType;
        entry->DhcpEnabled = 1;
        _snprintf_s(entry->IpAddressList.IpAddress.String,
            sizeof(entry->IpAddressList.IpAddress.String), _TRUNCATE, "%u.%u.%u.%u",
            (ntohl(p.synthetic_address.s_addr) >> 24) & 255,
            (ntohl(p.synthetic_address.s_addr) >> 16) & 255,
            (ntohl(p.synthetic_address.s_addr) >> 8) & 255,
            ntohl(p.synthetic_address.s_addr) & 255);
        strcpy_s(entry->IpAddressList.IpMask.String,
            sizeof(entry->IpAddressList.IpMask.String), "255.255.255.0");
        _snprintf_s(entry->GatewayList.IpAddress.String,
            sizeof(entry->GatewayList.IpAddress.String), _TRUNCATE, "%u.%u.%u.%u",
            (ntohl(p.synthetic_gateway.s_addr) >> 24) & 255,
            (ntohl(p.synthetic_gateway.s_addr) >> 16) & 255,
            (ntohl(p.synthetic_gateway.s_addr) >> 8) & 255,
            ntohl(p.synthetic_gateway.s_addr) & 255);
        strcpy_s(entry->GatewayList.IpMask.String,
            sizeof(entry->GatewayList.IpMask.String), "255.255.255.0");
        entry->LeaseObtained = (UINT32)time(nullptr) - 3600;
        entry->LeaseExpires = (UINT32)time(nullptr) + 86400;
        *size = sizeof(IP_ADAPTER_INFO);
        return ERROR_SUCCESS;
    }

    const ULONG result = next_info()(info, size);
    if (result != ERROR_SUCCESS || info == nullptr) return result;

    // Keep the chosen adapter, optionally drop the rest, and make the chosen one
    // acceptable to chusanApp. Everything else is left exactly as reported.
    PIP_ADAPTER_INFO keep = nullptr;
    for (PIP_ADAPTER_INFO entry = info; entry != nullptr; entry = entry->Next) {
        if (entry->Index == p.if_index) { keep = entry; break; }
    }
    if (keep == nullptr) {
        const LONG call = InterlockedIncrement(&g_info_calls);
        if (call <= 4)
            adapter_hook_trace("GetAdaptersInfo #%ld: if_index %lu is not in the returned "
                "list, nothing rewritten", call, p.if_index);
        return result; // adapter vanished; do not lie
    }

    if (p.forced_type) keep->Type = kEthernetType;
    keep->DhcpEnabled = 1;

    // chusanApp's GetAdaptersInfo pass reads GatewayList (+0x1d4 in the x86 layout), so
    // this is the value the game actually uses for the gateway item. It must be the same
    // one GetAdaptersAddresses and GetBestRoute report, or the answer depends on which API
    // happened to be asked.
    //
    // Overwrite unconditionally rather than only when the field is empty. `gateway_fallback`
    // already holds the value to present - the adapter's own gateway when that one is on the
    // presented segment, the segment router otherwise - so a field that is merely non-empty
    // can still be the wrong address. Leaving an out-of-subnet gateway here while replacing
    // it on the other API is precisely the inconsistency this hook exists to remove.
    if (p.gateway_fallback_enabled) {
        adapter_gateway_string(p.gateway_fallback, keep->GatewayList.IpAddress.String,
            sizeof(keep->GatewayList.IpAddress.String));
        strcpy_s(keep->GatewayList.IpMask.String,
            sizeof(keep->GatewayList.IpMask.String), "255.255.255.0");
        keep->GatewayList.Next = nullptr;
    }

    if (p.exclusive && keep != info) {
        // The caller owns the head pointer, so the only way to drop the adapters
        // ahead of ours is to move ours to the front of the caller's buffer.
        // IP_ADAPTER_INFO keeps its strings inline, so a plain move is safe.
        memmove(info, keep, sizeof(*info));
        info->Next = nullptr;
    } else if (p.exclusive) {
        info->Next = nullptr;
    }
    return result;
}

inline ULONG WINAPI hook_GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved,
                                              PIP_ADAPTER_ADDRESSES addresses, PULONG size) {
    const AdapterPresentation &p = state();
    if (!p.present) {
        return next_addresses() ? next_addresses()(family, flags, reserved, addresses, size)
                                : ERROR_INVALID_PARAMETER;
    }

    if (p.fabricate) {
        if (reserved != nullptr || size == nullptr) return ERROR_INVALID_PARAMETER;
        const ULONG available = *size;
        *size = sizeof(Fabricated);
        if (addresses == nullptr || available < sizeof(Fabricated)) return ERROR_BUFFER_OVERFLOW;
        Fabricated env = {};
        build_fabricated(p, &env);
        memcpy(addresses, &env, sizeof(env));
        // Re-point the internal pointers at the copy actually handed to the caller.
        PIP_ADAPTER_ADDRESSES head = addresses;
        const Fabricated *original = &env;
        auto relocate = [&](PVOID pointer) -> PVOID {
            if (pointer == nullptr) return nullptr;
            const uintptr_t offset = (uintptr_t)pointer - (uintptr_t)original;
            return (PVOID)((uintptr_t)head + offset);
        };
        head->AdapterName = (PCHAR)relocate(head->AdapterName);
        head->DnsSuffix = (PWCHAR)relocate(head->DnsSuffix);
        head->Description = (PWCHAR)relocate(head->Description);
        head->FriendlyName = (PWCHAR)relocate(head->FriendlyName);
        head->FirstUnicastAddress = (PIP_ADAPTER_UNICAST_ADDRESS)relocate(head->FirstUnicastAddress);
        head->FirstPrefix = (PIP_ADAPTER_PREFIX)relocate(head->FirstPrefix);
        head->FirstGatewayAddress =
            (PIP_ADAPTER_GATEWAY_ADDRESS)relocate(head->FirstGatewayAddress);
        head->FirstDnsServerAddress =
            (PIP_ADAPTER_DNS_SERVER_ADDRESS)relocate(head->FirstDnsServerAddress);
        head->FirstUnicastAddress->Address.lpSockaddr =
            (struct sockaddr *)relocate(head->FirstUnicastAddress->Address.lpSockaddr);
        head->FirstPrefix->Address.lpSockaddr =
            (struct sockaddr *)relocate(head->FirstPrefix->Address.lpSockaddr);
        head->FirstGatewayAddress->Address.lpSockaddr =
            (struct sockaddr *)relocate(head->FirstGatewayAddress->Address.lpSockaddr);
        head->FirstDnsServerAddress->Address.lpSockaddr =
            (struct sockaddr *)relocate(head->FirstDnsServerAddress->Address.lpSockaddr);

        // The chain walked by the game must terminate. netenv's struct leaves these
        // at zero, which is fine for netenv's own copy but not for a chain a caller
        // may follow, so they are set explicitly here.
        head->FirstUnicastAddress->Next = nullptr;
        head->FirstPrefix->Next = nullptr;
        head->FirstGatewayAddress->Next = nullptr;
        head->FirstDnsServerAddress->Next = nullptr;
        return ERROR_SUCCESS;
    }

    const ULONG result = next_addresses()(family, flags, reserved, addresses, size);
    if (result != ERROR_SUCCESS || addresses == nullptr) return result;

    PIP_ADAPTER_ADDRESSES keep = nullptr;
    for (PIP_ADAPTER_ADDRESSES entry = addresses; entry != nullptr; entry = entry->Next) {
        if (entry->IfIndex == p.if_index) { keep = entry; break; }
    }
    if (keep == nullptr) {
        const LONG call = InterlockedIncrement(&g_addresses_calls);
        if (call <= 4)
            adapter_hook_trace("GetAdaptersAddresses #%ld: if_index %lu is not in the "
                "returned list, nothing rewritten", call, p.if_index);
        return result;
    }

    // amdaemon reads IP_ADAPTER_DHCP_ENABLED out of Flags (FUN_1402f76f0:
    // `*(uint *)(adapter + 0x5c) >> 2 & 1`) and the shipped config_common.json asks for
    // "dhcp": true. netenv always set the flag; a real adapter frequently does not.
    if ((keep->Flags & IP_ADAPTER_DHCP_ENABLED) == 0) {
        keep->Flags |= IP_ADAPTER_DHCP_ENABLED;
        static volatile LONG reported = 0;
        if (InterlockedExchange(&reported, 1) == 0)
            adapter_hook_log("Adapter %lu does not report DHCP; presenting it as "
                "DHCP-enabled, which is what config_common.json asks for.", p.if_index);
    }

    if (p.forced_type) {
        keep->IfType = kEthernetType;
        // The game treats anything but "up" as unusable; a rewritten adapter that
        // reports down would be worse than not rewriting at all.
        if (keep->OperStatus != IfOperStatusUp) keep->OperStatus = IfOperStatusUp;
    }

    // chusanApp walks FirstDnsServerAddress during enumeration. A chosen adapter that
    // legitimately has no DNS server (static IP, no DHCP) would hand the game an empty
    // list, which is a state netenv never produced. Fall back to the gateway, which is
    // what netenv reported unconditionally.
    if (p.dns_fallback_enabled && !chain_has_ipv4(keep->FirstDnsServerAddress)) {
        DnsFallbackEntry &fallback = dns_fallback_entry();
        memset(&fallback, 0, sizeof(fallback));
        fallback.entry.Length = sizeof(fallback.entry);
        fallback.entry.Address.lpSockaddr = (struct sockaddr *)&fallback.address;
        fallback.entry.Address.iSockaddrLength = sizeof(fallback.address);
        fallback.address.sin_family = AF_INET;
        fallback.address.sin_addr = p.dns_fallback;
        keep->FirstDnsServerAddress = &fallback.entry;
        static volatile LONG reported = 0;
        if (InterlockedExchange(&reported, 1) == 0) {
            char text[INET_ADDRSTRLEN] = "-";
            InetNtopA(AF_INET, &p.dns_fallback, text, sizeof(text));
            adapter_hook_log("Adapter %lu reports no DNS server; presenting %s so the game "
                "does not enumerate an empty list.", p.if_index, text);
        }
    }

    // A flat L2 segment reports no gateway. The gateway check then has nothing to compare
    // and reports BAD without sending anything, which no amount of ICMP virtualisation can
    // fix. Supply one, as netenv did - and supply the same one GetAdaptersInfo and
    // GetBestRoute report, because the game cross-checks them.
    //
    // Unconditional for the same reason as the GatewayList write above: `gateway_fallback`
    // is the address to present, not merely a fallback for an empty field, so a real gateway
    // that sits outside the presented subnet has to be replaced here too.
    if (p.gateway_fallback_enabled) {
        // Report only a real substitution: compare the address the adapter actually
        // carries against the one being presented. `chain_has_ipv4` alone cannot tell
        // them apart, because when the adapter's own gateway is already the right one the
        // value is rewritten with itself.
        in_addr previous = {};
        bool had_previous = false;
        if (keep->FirstGatewayAddress != nullptr &&
            keep->FirstGatewayAddress->Address.lpSockaddr != nullptr &&
            keep->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET) {
            previous = reinterpret_cast<const sockaddr_in *>(
                keep->FirstGatewayAddress->Address.lpSockaddr)->sin_addr;
            had_previous = previous.s_addr != 0;
        }
        const bool substituted = !had_previous || previous.s_addr != p.gateway_fallback.s_addr;

        GatewayFallbackEntry &fallback = gateway_fallback_entry();
        memset(&fallback, 0, sizeof(fallback));
        fallback.entry.Length = sizeof(fallback.entry);
        fallback.entry.Address.lpSockaddr = (struct sockaddr *)&fallback.address;
        fallback.entry.Address.iSockaddrLength = sizeof(fallback.address);
        fallback.address.sin_family = AF_INET;
        fallback.address.sin_addr = p.gateway_fallback;
        keep->FirstGatewayAddress = &fallback.entry;

        static volatile LONG reported = 0;
        if (substituted && InterlockedExchange(&reported, 1) == 0) {
            char text[INET_ADDRSTRLEN] = "-";
            char was[INET_ADDRSTRLEN] = "-";
            InetNtopA(AF_INET, &p.gateway_fallback, text, sizeof(text));
            if (had_previous) InetNtopA(AF_INET, &previous, was, sizeof(was));
            adapter_hook_log("Adapter %lu %s; presenting %s as the gateway and the route "
                "next hop instead.", p.if_index,
                had_previous
                    ? "reports a gateway that is not on the presented segment"
                    : "reports no gateway",
                text);
            if (had_previous) {
                adapter_hook_trace("replaced gateway %s with %s for if_index %lu", was, text,
                    p.if_index);
            }
        }
    }

    // Dump the record once, after shaping. If the game still rejects it, this is the
    // only place that shows every field it was actually given.
    {
        static volatile LONG dumped = 0;
        if (InterlockedExchange(&dumped, 1) == 0 && log_sink() != nullptr) {
            char unicast[INET_ADDRSTRLEN] = "-";
            char gateway[INET_ADDRSTRLEN] = "-";
            char dns[INET_ADDRSTRLEN] = "-";
            for (PIP_ADAPTER_UNICAST_ADDRESS u = keep->FirstUnicastAddress; u != nullptr;
                 u = u->Next) {
                if (u->Address.lpSockaddr != nullptr && u->Address.lpSockaddr->sa_family == AF_INET) {
                    InetNtopA(AF_INET,
                        &reinterpret_cast<const sockaddr_in *>(u->Address.lpSockaddr)->sin_addr,
                        unicast, sizeof(unicast));
                    break;
                }
            }
            if (keep->FirstGatewayAddress != nullptr &&
                keep->FirstGatewayAddress->Address.lpSockaddr != nullptr &&
                keep->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET) {
                InetNtopA(AF_INET, &reinterpret_cast<const sockaddr_in *>(
                    keep->FirstGatewayAddress->Address.lpSockaddr)->sin_addr,
                    gateway, sizeof(gateway));
            }
            if (keep->FirstDnsServerAddress != nullptr &&
                keep->FirstDnsServerAddress->Address.lpSockaddr != nullptr &&
                keep->FirstDnsServerAddress->Address.lpSockaddr->sa_family == AF_INET) {
                InetNtopA(AF_INET, &reinterpret_cast<const sockaddr_in *>(
                    keep->FirstDnsServerAddress->Address.lpSockaddr)->sin_addr,
                    dns, sizeof(dns));
            }
            adapter_hook_log("presented: if_index=%lu if_type=%lu oper=%u flags=0x%lX mtu=%lu "
                "ip=%s gw=%s dns=%s exclusive=%d",
                keep->IfIndex, keep->IfType, (unsigned)keep->OperStatus,
                (unsigned long)keep->Flags, (unsigned long)keep->Mtu,
                unicast, gateway, dns, p.exclusive ? 1 : 0);
        }
    }

    if (p.exclusive) {
        // Only the fixed-size header moves. Its internal pointers address data
        // elsewhere in the same caller-owned buffer, so they stay valid as-is; only
        // Next has to be cleared. The caller keeps the base pointer, so promoting the
        // chosen adapter to the front is the only way to drop the ones ahead of it.
        if (keep != addresses) memmove(addresses, keep, sizeof(*addresses));
        addresses->Next = nullptr;
    }
    return result;
}

inline ULONG WINAPI hook_GetIfTable(PMIB_IFTABLE table, PULONG size, BOOL order) {
    const AdapterPresentation &p = state();
    if (!p.present) {
        return next_table() ? next_table()(table, size, order) : ERROR_INVALID_PARAMETER;
    }

    if (p.fabricate) {
        const ULONG needed = sizeof(DWORD) + sizeof(MIB_IFROW);
        if (table == nullptr || size == nullptr || *size < needed) {
            if (size != nullptr) *size = needed;
            return ERROR_INSUFFICIENT_BUFFER;
        }
        table->dwNumEntries = 1;
        MIB_IFROW *row = table->table;
        memset(row, 0, sizeof(*row));
        wcscpy_s(row->wszName, _countof(row->wszName), L"Fake Ethernet");
        row->dwIndex = 1;
        row->dwType = kEthernetType;
        row->dwMtu = 4200;
        row->dwSpeed = 1000000000;
        row->dwPhysAddrLen = 6;
        memcpy(row->bPhysAddr, p.mac, 6);
        row->dwAdminStatus = 1;
        row->dwOperStatus = IF_OPER_STATUS_OPERATIONAL;
        *size = needed;
        return ERROR_SUCCESS;
    }

    const ULONG result = next_table()(table, size, order);
    if (result != ERROR_SUCCESS || table == nullptr) return result;

    // Rows are fixed-size and shifted in place, exactly as the API documents the
    // table layout, so the caller's buffer capacity is unaffected.
    DWORD kept = 0;
    const DWORD reported = table->dwNumEntries;
    for (DWORD i = 0; i < reported; ++i) {
        MIB_IFROW row = table->table[i];
        const bool chosen = row.dwIndex == p.if_index;
        if (chosen && p.forced_type) row.dwType = kEthernetType;
        if (!p.exclusive || chosen) {
            table->table[kept] = row;
            ++kept;
        }
    }
    table->dwNumEntries = kept;
    return result;
}

// amdaemon resolves the gateway for its own checks through GetBestRoute
// (FUN_1403bbbc0: GetBestRoute(0, dest, &row)). netenv hooked this and always reported
// subnet|routerSuffix with IfIndex 1, which is why the baseline never had to care what
// the adapter itself said. Reporting the presented interface keeps the two consistent.
inline DWORD WINAPI hook_GetBestRoute(DWORD source, DWORD destination,
                                      PMIB_IPFORWARDROW route) {
    const AdapterPresentation &p = state();
    if (!p.present || route == nullptr || !p.route_override_enabled) {
        return next_best_route() ? next_best_route()(source, destination, route)
                                 : ERROR_NOT_SUPPORTED;
    }

    {
        const LONG call = InterlockedIncrement(&g_route_calls);
        if (call <= 8) {
            const uint32_t target = ntohl(destination);
            adapter_hook_trace("GetBestRoute #%ld: dest=%lu.%lu.%lu.%lu",
                call, (target >> 24) & 255, (target >> 16) & 255, (target >> 8) & 255,
                target & 255);
        }
    }

    // Matches netenv: report the presented interface as the route for every destination,
    // not just the ones inside the presented subnet. netenv.c:422-451 fills in a fixed
    // row, because amdaemon treats "GetBestRoute succeeded" as evidence that a default
    // gateway exists. Scoping by destination was a plausible-sounding refinement, but it
    // made the answer depend on which address amdaemon happened to ask about, and the
    // observed failure was on a lookup the scoped version did not cover.
    //
    // The real lookup is not consulted: every field of the answer is defined here, and
    // all of them come from the same presented adapter. Real packet egress is unaffected,
    // because GetBestRoute is a query and the game's server I/O goes through WinHTTP,
    // which resolves routes inside the HTTP stack.
    (void)source;
    memset(route, 0, sizeof(*route));
    route->dwForwardDest = 0;
    route->dwForwardMask = 0xFFFFFFFF;
    route->dwForwardNextHop = p.route_next_hop;
    route->dwForwardIfIndex = p.if_index;
    route->dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
    route->dwForwardProto = MIB_IPPROTO_NETMGMT;
    return NO_ERROR;
}

// amdaemon answers two network-test items with ICMP: GATEWAY, an echo to the presented
// gateway, and NUMBER OF HOP, the traceroute described above. Both are decided by this
// one function, and answering every destination is what keeps the second from stalling.
inline ULONG WINAPI hook_IcmpSendEcho2(HANDLE icmp, HANDLE event, void *apc,
                                       PVOID apc_context, IPAddr destination,
                                       LPVOID request_data, WORD request_size,
                                       PIP_OPTION_INFORMATION request_options,
                                       LPVOID reply_buffer, DWORD reply_size, DWORD timeout) {
    const AdapterPresentation &p = state();
    if (!p.present || !p.virtualize_icmp) {
        return next_icmp() ? next_icmp()(icmp, event, apc, apc_context, destination,
            request_data, request_size, request_options, reply_buffer, reply_size, timeout)
            : 0;
    }

    const uint32_t host = ntohl((uint32_t)destination);
    {
        const LONG call = InterlockedIncrement(&g_icmp_calls);
        if (call <= 8) {
            const unsigned long ttl = request_options != nullptr ? request_options->Ttl : 0;
            adapter_hook_trace("IcmpSendEcho2 #%ld: destination %lu.%lu.%lu.%lu ttl=%lu",
                call, (host >> 24) & 255, (host >> 16) & 255, (host >> 8) & 255, host & 255,
                ttl);
        }
    }

    if (apc != nullptr || reply_buffer == nullptr || reply_size < sizeof(ICMP_ECHO_REPLY)) {
        // Fall through for anything this hook cannot answer faithfully.
        return next_icmp() ? next_icmp()(icmp, event, apc, apc_context, destination,
            request_data, request_size, request_options, reply_buffer, reply_size, timeout)
            : 0;
    }

    ICMP_ECHO_REPLY *reply = reinterpret_cast<ICMP_ECHO_REPLY *>(reply_buffer);
    memset(reply, 0, sizeof(*reply));
    reply->Address = destination;
    reply->Status = IP_SUCCESS;
    reply->RoundTripTime = 1;
    reply->DataSize = 0;
    reply->Reserved = 1;

    if (event != nullptr) {
        // Async form: the caller waits on the event, exactly as netenv presented it.
        SetLastError(ERROR_IO_PENDING);
        SetEvent(event);
        return 0;
    }
    SetLastError(ERROR_SUCCESS);
    return 1;
}

} // namespace adapter_override
