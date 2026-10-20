// Probe: does IP_UNICAST_IF affect the egress interface of a limited broadcast,
// and can Windows bind() to an address that no adapter owns?
//
// Both questions decide whether chusan_network_hook's pinning mechanism can work.
//   * If IP_UNICAST_IF is ignored for broadcast, hook_sendto's approach is inert.
//   * If bind() accepts a non-local address, the "advertise a fake IP" model that
//     segatools' netenv produces is viable on its own.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static const unsigned short kPort = 46001;

// Returns 0 and fills `out` on success.
static int bind_probe(const char *text, int *out_error) {
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    InetPtonA(AF_INET, text, &address.sin_addr);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { *out_error = WSAGetLastError(); return -1; }
    const int result = bind(s, reinterpret_cast<const sockaddr *>(&address), sizeof(address));
    *out_error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    closesocket(s);
    return result;
}

// Sends a broadcast with an optional IP_UNICAST_IF pin and reports the source
// address the packet actually carried, as observed by a local receiver.
static void broadcast_probe(const char *label, int pin_index, const char *bind_to) {
    SOCKET receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver == INVALID_SOCKET) { printf("%s: receiver socket failed\n", label); return; }
    BOOL reuse = TRUE;
    setsockopt(receiver, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    sockaddr_in local = {};
    local.sin_family = AF_INET;
    local.sin_port = htons(kPort);
    local.sin_addr.s_addr = INADDR_ANY;
    if (bind(receiver, (const sockaddr *)&local, sizeof(local)) == SOCKET_ERROR) {
        printf("%s: receiver bind failed %d\n", label, WSAGetLastError());
        closesocket(receiver);
        return;
    }
    u_long nonblocking = 1;
    ioctlsocket(receiver, FIONBIO, &nonblocking);

    SOCKET sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sender == INVALID_SOCKET) { printf("%s: sender socket failed\n", label); closesocket(receiver); return; }
    BOOL broadcast = TRUE;
    setsockopt(sender, SOL_SOCKET, SO_BROADCAST, (const char *)&broadcast, sizeof(broadcast));

    const char *bind_note = "none";
    if (bind_to != nullptr && bind_to[0] != 0) {
        sockaddr_in source = {};
        source.sin_family = AF_INET;
        InetPtonA(AF_INET, bind_to, &source.sin_addr);
        if (bind(sender, (const sockaddr *)&source, sizeof(source)) == 0) {
            bind_note = bind_to;
        } else {
            bind_note = "BIND_FAILED";
        }
    }
    if (pin_index > 0) {
        // IP_UNICAST_IF wants the interface index in network byte order.
        const DWORD index = htonl((u_long)pin_index);
        setsockopt(sender, IPPROTO_IP, IP_UNICAST_IF, (const char *)&index, sizeof(index));
    }

    sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons(kPort);
    target.sin_addr.s_addr = INADDR_BROADCAST;
    const char payload[] = "probe";
    sendto(sender, payload, sizeof(payload), 0, (const sockaddr *)&target, sizeof(target));

    // A broadcast is delivered to local listeners as well, so a short poll is
    // enough; the answer is the source address it was stamped with.
    char buffer[64];
    sockaddr_in from = {};
    int from_length = sizeof(from);
    int received = -1;
    for (int i = 0; i < 60; ++i) {
        received = recvfrom(receiver, buffer, sizeof(buffer), 0, (sockaddr *)&from, &from_length);
        if (received > 0) break;
        Sleep(10);
    }
    if (received > 0) {
        const unsigned long ip = ntohl(from.sin_addr.s_addr);
        printf("%-34s pin_if=%-4s bind=%-16s -> source=%lu.%lu.%lu.%lu\n", label,
            pin_index > 0 ? "yes" : "no", bind_note,
            (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    } else {
        printf("%-34s pin_if=%-4s bind=%-16s -> no loopback delivery (error=%d)\n", label,
            pin_index > 0 ? "yes" : "no", bind_note, WSAGetLastError());
    }
    closesocket(sender);
    closesocket(receiver);
}

int main(int argc, char **argv) {
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    printf("=== bind() to addresses the host does (and does not) own ===\n");
    const char *candidates[] = {"0.0.0.0", "127.0.0.1", "172.16.10.235", "192.168.139.17",
                                "192.168.139.11", "10.99.99.99"};
    for (const char *candidate : candidates) {
        int error = 0;
        const int result = bind_probe(candidate, &error);
        printf("bind(%-16s) = %s%s%d%s\n", candidate,
            result == 0 ? "OK" : "FAIL",
            result == 0 ? "" : " ", error,
            result == 0 ? "" : " (WSAEADDRNOTAVAIL=10049 WSAEADDRINUSE=10048)");
    }

    printf("\n=== egress of 255.255.255.255, as observed by a local receiver ===\n");
    if (argc >= 2) {
        // Usage: probe_unicast_if <ifindexA> [ifindexB] [addrA] [addrB]
        const int a = atoi(argv[1]);
        const int b = argc >= 3 ? atoi(argv[2]) : 0;
        broadcast_probe("baseline (no pin)", 0, nullptr);
        broadcast_probe("pinned to first interface", a, nullptr);
        if (b > 0) broadcast_probe("pinned to second interface", b, nullptr);
        if (argc >= 4) broadcast_probe("bound to first address", 0, argv[3]);
        if (argc >= 5) broadcast_probe("bound to second address", 0, argv[4]);
    } else {
        broadcast_probe("baseline (no pin)", 0, nullptr);
    }

    WSACleanup();
    return 0;
}
