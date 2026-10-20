// Presents one chosen interface to the game through the three adapter-enumeration
// APIs, in place, without inventing an identity.
//
// Rationale and evidence: docs/adapter-selection.md and docs/netenv-takeover.md.
// In short:
//   * chusanApp accepts only IP_ADAPTER_INFO.Type == 6;
//   * amdaemon additionally rejects Type 1 and 24, and looks adapters up by IfIndex
//     through GetAdaptersAddresses, so the index must stay real;
//   * bind() to an address no adapter owns fails with WSAEADDRNOTAVAIL, so the
//     address must stay real.
//
// Therefore the normal path rewrites only the fields the game refuses and filters
// the rest of the chain. Fabrication (netenv's approach) is kept solely as the
// legacpath for hosts where no acceptable adapter exists at all.
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
    bool allow_loopback = false;

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
    // supplied subnet|routerSuffix, and the gateway check has nothing to probe when the
    // list is empty, so it reports BAD before any ICMP is sent. Synthesise one only when
    // the adapter genuinely has none.
    bool gateway_fallback_enabled = false;
    in_addr gateway_fallback = {};

    // amdaemon's gateway check is an ICMP echo (altrIcmpSendEcho @ 0x1403f0b00 ->
    // IcmpSendEcho2), and netenv made every echo succeed. Without that, a host whose
    // presented interface has no reachable router fails the check even though the LAN
    // is fine -- which is exactly what ZeroTier does, since it is a flat L2 network
    // with no router. Scope: destinations inside the presented subnet.
    bool virtualize_icmp = true;
    in_addr presented_network = {};
    in_addr presented_mask = {};
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
using adapter_log_sink = void (*)(const char *message);

// Call counters: the difference between "the game never asked" and "we answered and it
// still failed" is not visible in the network test screen, only in the log.
inline volatile LONG g_info_calls = 0;
inline volatile LONG g_addresses_calls = 0;
inline volatile LONG g_icmp_calls = 0;

inline adapter_log_sink &log_sink() {
    static adapter_log_sink sink = nullptr;
    return sink;
}

inline void adapter_hook_log(const char *format, ...) {
    if (log_sink() == nullptr) return;
    char message[512] = {};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    va_end(args);
    log_sink()(message);
}


using get_adapters_info_fn = ULONG (WINAPI *)(PIP_ADAPTER_INFO, PULONG);
using get_adapters_addresses_fn = ULONG (WINAPI *)(ULONG, ULONG, PVOID,
                                                   PIP_ADAPTER_ADDRESSES, PULONG);
using get_if_table_fn = ULONG (WINAPI *)(PMIB_IFTABLE, PULONG, BOOL);
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
inline icmp_send_echo2_fn &next_icmp() {
    static icmp_send_echo2_fn fn = nullptr;
    return fn;
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
    memcpy(env->head.PhysicalAddress, p.mac, sizeof(p.mac));
    env->head.PhysicalAddressLength = (ULONG)sizeof(p.mac);
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
        entry->AddressLength = 6;
        memcpy(entry->Address, p.mac, 6);
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
        if (size) *size = sizeof(IP_ADAPTER_INFO);
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
            adapter_hook_log("GetAdaptersInfo #%ld: presented if_index %lu not in the "
                "returned list, nothing rewritten", call, p.if_index);
        return result; // adapter vanished; do not lie
    }

    if (p.forced_type) keep->Type = kEthernetType;

    // chusanApp's GetAdaptersInfo pass reads GatewayList (+0x1d4 in the x86 layout), so
    // the same empty-gateway problem exists on this API. Fill it with the same address
    // the addresses API is given.
    if (p.gateway_fallback_enabled && keep->GatewayList.IpAddress.String[0] == 0) {
        _snprintf_s(keep->GatewayList.IpAddress.String,
            sizeof(keep->GatewayList.IpAddress.String), _TRUNCATE, "%u.%u.%u.%u",
            (ntohl(p.gateway_fallback.s_addr) >> 24) & 255,
            (ntohl(p.gateway_fallback.s_addr) >> 16) & 255,
            (ntohl(p.gateway_fallback.s_addr) >> 8) & 255,
            ntohl(p.gateway_fallback.s_addr) & 255);
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
            adapter_hook_log("GetAdaptersAddresses #%ld: presented if_index %lu not in the "
                "returned list, nothing rewritten", call, p.if_index);
        return result;
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
        adapter_hook_log("GetAdaptersAddresses: injected DNS server for if_index %lu",
            p.if_index);
    }

    // A flat L2 segment reports no gateway. The gateway check then has nothing to probe
    // and reports BAD without sending a packet, which no amount of ICMP virtualisation
    // can fix. Supply one, as netenv did.
    if (!chain_has_ipv4(keep->FirstGatewayAddress)) {
        adapter_hook_log("GetAdaptersAddresses: adapter if_index %lu reports no usable "
            "gateway; fallback %s", p.if_index,
            p.gateway_fallback_enabled ? "applied" : "NOT applied");
    }
    if (p.gateway_fallback_enabled && !chain_has_ipv4(keep->FirstGatewayAddress)) {
        GatewayFallbackEntry &fallback = gateway_fallback_entry();
        memset(&fallback, 0, sizeof(fallback));
        fallback.entry.Length = sizeof(fallback.entry);
        fallback.entry.Address.lpSockaddr = (struct sockaddr *)&fallback.address;
        fallback.entry.Address.iSockaddrLength = sizeof(fallback.address);
        fallback.address.sin_family = AF_INET;
        fallback.address.sin_addr = p.gateway_fallback;
        keep->FirstGatewayAddress = &fallback.entry;
        adapter_hook_log("GetAdaptersAddresses: injected gateway for if_index %lu", p.if_index);
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

// amdaemon measures the gateway with an ICMP echo:
//   altrIcmpSendEcho @ 0x1403f0b00 -> IcmpSendEcho2(h, Event, NULL, NULL, dest, ...)
// and treats getlastError() == 0x3E5 (ERROR_IO_PENDING) as success. netenv answered
// every echo as a success without transmitting anything, so on a host whose presented
// interface has no router -- ZeroTier is a flat L2 network with none -- the check passed
// under netenv and fails without it.
//
// Only destinations inside the presented subnet are answered, so a genuine failure to
// reach something outside the LAN is still reported as a failure.
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
    const uint32_t mask = ntohl(p.presented_mask.s_addr);
    const uint32_t network = ntohl(p.presented_network.s_addr) & mask;
    const bool inside = mask != 0 && mask != 0xFFFFFFFFu && (host & mask) == network;
    if (!inside) {
        return next_icmp() ? next_icmp()(icmp, event, apc, apc_context, destination,
            request_data, request_size, request_options, reply_buffer, reply_size, timeout)
            : 0;
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
