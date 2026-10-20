// Prints the IP_ADAPTER_INFO / IP_ADAPTER_ADDRESSES field offsets for the current
// build, so the constants hard-coded in chusanApp/amdaemon can be mapped to fields
// instead of guessed.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <stddef.h>

int main(void) {
    printf("sizeof(void*)        = %zu\n", sizeof(void *));
    printf("sizeof(IP_ADAPTER_INFO) = %zu\n\n", sizeof(IP_ADAPTER_INFO));

    printf("--- IP_ADAPTER_INFO ---\n");
    printf("Next            +0x%03zx\n", offsetof(IP_ADAPTER_INFO, Next));
    printf("ComboIndex      +0x%03zx\n", offsetof(IP_ADAPTER_INFO, ComboIndex));
    printf("AdapterName     +0x%03zx\n", offsetof(IP_ADAPTER_INFO, AdapterName));
    printf("Description     +0x%03zx\n", offsetof(IP_ADAPTER_INFO, Description));
    printf("AddressLength   +0x%03zx\n", offsetof(IP_ADAPTER_INFO, AddressLength));
    printf("Address         +0x%03zx\n", offsetof(IP_ADAPTER_INFO, Address));
    printf("Index           +0x%03zx\n", offsetof(IP_ADAPTER_INFO, Index));
    printf("Type            +0x%03zx\n", offsetof(IP_ADAPTER_INFO, Type));
    printf("DhcpEnabled     +0x%03zx\n", offsetof(IP_ADAPTER_INFO, DhcpEnabled));
    printf("CurrentIpAddress+0x%03zx\n", offsetof(IP_ADAPTER_INFO, CurrentIpAddress));
    printf("IpAddressList   +0x%03zx\n", offsetof(IP_ADAPTER_INFO, IpAddressList));
    printf("GatewayList     +0x%03zx\n", offsetof(IP_ADAPTER_INFO, GatewayList));
    printf("DhcpServer      +0x%03zx\n", offsetof(IP_ADAPTER_INFO, DhcpServer));
    printf("HaveWins        +0x%03zx\n", offsetof(IP_ADAPTER_INFO, HaveWins));
    printf("PrimaryWinsServer +0x%03zx\n", offsetof(IP_ADAPTER_INFO, PrimaryWinsServer));
    printf("SecondaryWinsServer +0x%03zx\n", offsetof(IP_ADAPTER_INFO, SecondaryWinsServer));
    printf("LeaseObtained   +0x%03zx\n", offsetof(IP_ADAPTER_INFO, LeaseObtained));
    printf("LeaseExpires    +0x%03zx\n", offsetof(IP_ADAPTER_INFO, LeaseExpires));

    printf("\n--- IP_ADAPTER_ADDRESSES ---\n");
    printf("IfIndex         +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, IfIndex));
    printf("IfType          +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, IfType));
    printf("OperStatus      +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, OperStatus));
    printf("FirstUnicastAddress +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, FirstUnicastAddress));
    printf("FirstAnycastAddress +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, FirstAnycastAddress));
    printf("FirstMulticastAddress +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, FirstMulticastAddress));
    printf("FirstDnsServerAddress +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, FirstDnsServerAddress));
    printf("FriendlyName    +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, FriendlyName));
    printf("Ipv4Metric      +0x%03zx\n", offsetof(IP_ADAPTER_ADDRESSES, Ipv4Metric));

    printf("\n--- MIB_IFROW (GetIfTable) ---\n");
    printf("dwIndex         +0x%03zx\n", offsetof(MIB_IFROW, dwIndex));
    printf("dwType          +0x%03zx\n", offsetof(MIB_IFROW, dwType));
    printf("sizeof(MIB_IFROW) = %zu, row stride in MIB_IFTABLE = 0x%zx\n",
        sizeof(MIB_IFROW), sizeof(MIB_IFROW));

    printf("\n--- MIB_IF_TYPE constants ---\n");
    printf("MIB_IF_TYPE_OTHER        = %d\n", MIB_IF_TYPE_OTHER);
    printf("MIB_IF_TYPE_ETHERNET     = %d\n", MIB_IF_TYPE_ETHERNET);
    printf("IF_TYPE_SOFTWARE_LOOPBACK= %d\n", IF_TYPE_SOFTWARE_LOOPBACK);
#ifdef IF_TYPE_IEEE80211
    printf("IF_TYPE_IEEE80211        = %d\n", IF_TYPE_IEEE80211);
#endif
    return 0;
}
