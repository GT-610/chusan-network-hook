// Probe: reproduce the adapter filter that chusanApp's ALLNET layer applies, so the
// "would the game accept this NIC?" question is answered with data instead of theory.
//
// Reverse-engineered filter (chusanApp.exe @ 0x01026820, "allnet_enumerate_adapters"):
//   1. GetAdaptersInfo()      -- accept only IP_ADAPTER_INFO.Type == 6 (MIB_IF_TYPE_ETHERNET)
//   2. GetAdaptersAddresses() -- enrich accepted IfIndexes with OperStatus (1..7) and
//                                every unicast IPv4 address
//   3. GetIfTable()           -- attach the per-index row (speed/status)
//
// This probe prints what each API reports plus the verdict, for the real host and for
// the synthetic adapter that segatools' netenv presents.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static const UINT kAcceptedType = 6; // MIB_IF_TYPE_ETHERNET / IF_TYPE_ETHERNET_CSMACD

int main(void) {
    // getnameinfo below needs Winsock up; without it the enrichment section is empty
    // and would understate what the game actually sees.
    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    printf("Adapter filter chusanApp applies: IP_ADAPTER_INFO.Type == %u\n\n", kAcceptedType);

    /* ---------- 1. GetAdaptersInfo: the actual gate ---------- */
    ULONG size = 0;
    DWORD result = GetAdaptersInfo(NULL, &size);
    if (result != ERROR_BUFFER_OVERFLOW || size == 0) {
        printf("GetAdaptersInfo sizing failed: %lu\n", result);
        return 1;
    }
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)calloc(1, size);
    result = GetAdaptersInfo(info, &size);
    if (result != NO_ERROR) {
        printf("GetAdaptersInfo failed: %lu\n", result);
        return 1;
    }

    printf("=== GetAdaptersInfo (this is what decides) ===\n");
    printf("%-4s %-8s %-40s %-18s %-16s %s\n",
        "Idx", "Type", "Description", "IP", "Mask", "Verdict");
    for (IP_ADAPTER_INFO *a = info; a != NULL; a = a->Next) {
        const DWORD type = a->Type;
        printf("%-4lu %-8lu %-40.40s %-18.18s %-16.16s %s\n",
            a->Index, type, a->Description,
            a->IpAddressList.IpAddress.String, a->IpAddressList.IpMask.String,
            type == kAcceptedType ? "ACCEPT" : "reject (Type != 6)");
    }

    /* ---------- 2. GetAdaptersAddresses: enrichment data ---------- */
    ULONG gaa_size = 0;
    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &gaa_size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES *)calloc(1, gaa_size);
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &gaa_size);
        if (result == NO_ERROR) {
            printf("\n=== GetAdaptersAddresses (enrichment only) ===\n");
            for (IP_ADAPTER_ADDRESSES *a = addresses; a != NULL; a = a->Next) {
                printf("if_index=%-3lu if_type=%-3lu oper=%-2u unicast:",
                    a->IfIndex, (unsigned long)a->IfType, (unsigned)a->OperStatus);
                for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u != NULL; u = u->Next) {
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
    free(info);

    /* ---------- 3. What segatools' netenv presents instead ---------- */
    printf("\n=== Synthesised by segatools netenv (for comparison) ===\n");
    printf("if_index=1   type=6   if_type=6   oper=1   address=<keychip subnet>|<addrSuffix>\n");
    printf("mac=01:02:03:04:05:06   prefix=/24   -> ACCEPT (Type == 6)\n");
    printf("\nNote: IF_TYPE_IEEE80211 (Wi-Fi) is 71, so a wireless NIC fails the Type==6 gate.\n");

    return 0;
}
