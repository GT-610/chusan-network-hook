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
            printf("  idx=%-3lu type=%-2lu %-13s %-16s macLen=%lu  %s\n",
                a->Index, a->Type, type_name(a->Type),
                a->IpAddressList.IpAddress.String, a->AddressLength,
                ok ? "ACCEPT" : "reject");
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

    WSACleanup();
    return 0;
}
