// Probe: load the hook DLL, then report the adapter list exactly as the game would
// see it through the three enumeration APIs.
//
// Usage: probe_presentation <hook.dll>
//
// The DLL reads network_hook.ini from its own directory, so place a copy of the DLL
// and a crafted ini in a scratch directory to exercise a particular configuration.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static const char *type_name(ULONG type) {
    switch (type) {
    case 1: return "OTHER";
    case 6: return "ETHERNET";        // what chusanApp requires
    case 24: return "LOOPBACK";
    case 53: return "PROP_VIRTUAL";
    case 71: return "IEEE80211";
    default: return "?";
    }
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        fwprintf(stderr, L"usage: %s <hook.dll>\n", argv[0]);
        return 2;
    }

    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    HMODULE hook = LoadLibraryW(argv[1]);
    if (hook == nullptr) {
        printf("LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    Sleep(400); // let the logging thread finish its start-up diagnostics

    /* ---- GetAdaptersInfo: the gate chusanApp applies ---- */
    ULONG size = 0;
    DWORD result = GetAdaptersInfo(NULL, &size);
    if (result != ERROR_BUFFER_OVERFLOW || size == 0) {
        printf("GetAdaptersInfo sizing returned %lu (size=%lu)\n", result, size);
    } else {
        IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)calloc(1, size);
        result = GetAdaptersInfo(info, &size);
        printf("=== GetAdaptersInfo (result=%lu, buffer=%lu) ===\n", result, size);
        int accepted = 0;
        for (IP_ADAPTER_INFO *a = info; a != NULL; a = a->Next) {
            const bool ok = a->Type == 6;
            if (ok) ++accepted;
            // The gateway column matters: chusanApp's pass 1 parses GatewayList (+0x1d4)
            // and this is the value the gateway item is actually decided on. It has to
            // agree with the GetAdaptersAddresses output below.
            printf("  idx=%-3lu type=%-2lu %-13s %-16s gw=%-16s macLen=%lu  %s\n",
                a->Index, a->Type, type_name(a->Type),
                a->IpAddressList.IpAddress.String,
                a->GatewayList.IpAddress.String[0] ? a->GatewayList.IpAddress.String : "-",
                a->AddressLength, ok ? "ACCEPT" : "reject");
        }
        printf("  -> chusanApp would accept %d adapter(s)\n", accepted);
        free(info);
    }

    /* ---- GetAdaptersAddresses: what chusanApp uses for enrichment ---- */
    ULONG gaa = 0;
    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &gaa);
    if (result == ERROR_BUFFER_OVERFLOW && gaa != 0) {
        IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES *)calloc(1, gaa);
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &gaa);
        printf("=== GetAdaptersAddresses (result=%lu) ===\n", result);
        if (result == NO_ERROR) {
            for (IP_ADAPTER_ADDRESSES *a = addresses; a != NULL; a = a->Next) {
                printf("  if_index=%-3lu if_type=%-2lu %-13s oper=%u unicast:",
                    a->IfIndex, (unsigned long)a->IfType, type_name(a->IfType),
                    (unsigned)a->OperStatus);
                printf(" gw:");
                for (IP_ADAPTER_GATEWAY_ADDRESS *g = a->FirstGatewayAddress; g; g = g->Next) {
                    char gtext[INET6_ADDRSTRLEN] = {};
                    if (g->Address.lpSockaddr && getnameinfo(g->Address.lpSockaddr,
                            g->Address.iSockaddrLength, gtext, sizeof(gtext), NULL, 0,
                            NI_NUMERICHOST) == 0)
                        printf(" %s", gtext);
                }
                printf(" dns:");
                for (IP_ADAPTER_DNS_SERVER_ADDRESS *d = a->FirstDnsServerAddress; d; d = d->Next) {
                    char dtext[INET6_ADDRSTRLEN] = {};
                    if (d->Address.lpSockaddr && getnameinfo(d->Address.lpSockaddr,
                            d->Address.iSockaddrLength, dtext, sizeof(dtext), NULL, 0,
                            NI_NUMERICHOST) == 0)
                        printf(" %s", dtext);
                }
                printf(" unicast:");
                for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
                    char text[INET6_ADDRSTRLEN] = {};
                    if (getnameinfo(u->Address.lpSockaddr, u->Address.iSockaddrLength,
                            text, sizeof(text), NULL, 0, NI_NUMERICHOST) == 0)
                        printf(" %s", text);
                }
                printf("\n");
            }
        }
        free(addresses);
    }

    /* ---- GetIfTable: the third pass ---- */
    ULONG table_size = 0;
    result = GetIfTable(NULL, &table_size, FALSE);
    if (table_size != 0) {
        MIB_IFTABLE *table = (MIB_IFTABLE *)calloc(1, table_size);
        result = GetIfTable(table, &table_size, FALSE);
        printf("=== GetIfTable (result=%lu, rows=%lu) ===\n", result,
            result == NO_ERROR ? table->dwNumEntries : 0);
        if (result == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                printf("  dwIndex=%-3lu dwType=%-2lu %s\n", table->table[i].dwIndex,
                    table->table[i].dwType, type_name(table->table[i].dwType));
            }
        }
        free(table);
    }

    /* ---- IcmpSendEcho2: the gateway probe amdaemon runs ---- */
    HANDLE icmp = IcmpCreateFile();
    if (icmp != INVALID_HANDLE_VALUE) {
        struct { ICMP_ECHO_REPLY reply; unsigned char data[64]; } buffer = {};
        HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
        const char *targets[] = { "172.16.10.254", "8.8.8.8" };
        printf("=== IcmpSendEcho2 (async form, as amdaemon calls it) ===\n");
        for (int i = 0; i < 2; ++i) {
            IPAddr destination = inet_addr(targets[i]);
            ResetEvent(event);
            SetLastError(0);
            const DWORD count = IcmpSendEcho2(icmp, event, NULL, NULL, destination,
                NULL, 0, NULL, &buffer, sizeof(buffer), 500);
            const DWORD error = GetLastError();
            printf("  %-14s count=%lu error=%lu/%s status=%s\n", targets[i], count, error,
                error == ERROR_IO_PENDING ? "IO_PENDING" : (error == 0 ? "OK" : "other"),
                count == 0 && error == ERROR_IO_PENDING
                    ? (buffer.reply.Status == IP_SUCCESS ? "IP_SUCCESS (virtualized)" : "?")
                    : (count > 0 ? "real reply" : "real failure"));
        }
        CloseHandle(event);
        IcmpCloseHandle(icmp);
    }

    WSACleanup();
    return 0;
}
