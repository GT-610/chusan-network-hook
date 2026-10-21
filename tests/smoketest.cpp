#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

static int fail(const char *step, int error) {
    fprintf(stderr, "FAIL: %s (%d)\n", step, error);
    return 1;
}

static int fail_bound(const char *step, unsigned port) {
    fprintf(stderr, "FAIL: %s (the call reached the stack: port %u is live)\n", step, port);
    return 1;
}

// The two LAN Install checks below assert that a call left the socket exactly as it was:
// unbound. That is the property the game depends on, and unlike a return value it cannot
// be produced by a real call that happens to succeed.
//
// Windows does not report an unbound socket as 0.0.0.0:0 -- getsockname fails with
// WSAEINVAL -- so that error means "nothing reached the stack", any successful answer
// means the socket picked up a port, and any other error is a real failure.
static int bound_port(SOCKET socket) {
    sockaddr_in address = {};
    int length = (int)sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr *>(&address), &length) == 0)
        return (int)ntohs(address.sin_port);
    return WSAGetLastError() == WSAEINVAL ? 0 : SOCKET_ERROR;
}

static int check_still_unbound(const char *step, SOCKET socket) {
    const int port = bound_port(socket);
    if (port == SOCKET_ERROR) return fail(step, WSAGetLastError());
    if (port != 0) return fail_bound(step, (unsigned)port);
    return 0;
}

static int test_party_loopback() {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return fail("party loopback listener socket", WSAGetLastError());

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(50200);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR)
        return fail("party loopback bind", WSAGetLastError());
    if (listen(listener, 2) == SOCKET_ERROR)
        return fail("party loopback listen", WSAGetLastError());

    for (int use_wsa_connect = 0; use_wsa_connect < 2; ++use_wsa_connect) {
        SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client == INVALID_SOCKET) return fail("party loopback client socket", WSAGetLastError());
        const int result = use_wsa_connect
            ? WSAConnect(client, reinterpret_cast<const sockaddr *>(&address), sizeof(address),
                nullptr, nullptr, nullptr, nullptr)
            : connect(client, reinterpret_cast<const sockaddr *>(&address), sizeof(address));
        if (result == SOCKET_ERROR)
            return fail(use_wsa_connect ? "party loopback WSAConnect" : "party loopback connect",
                WSAGetLastError());
        SOCKET accepted = accept(listener, nullptr, nullptr);
        if (accepted == INVALID_SOCKET) return fail("party loopback accept", WSAGetLastError());
        closesocket(accepted);
        closesocket(client);
    }

    closesocket(listener);
    return 0;
}

// UDP 40112: the LAN Install beacon must not leave the process.
//
// sendto's return value alone cannot tell the two cases apart on a host where the send
// would be allowed anyway, so the sender is inspected instead: a real sendto implicitly
// binds it to an ephemeral port, while the virtualised path returns before Winsock is
// called and leaves it unbound. On an unmodified stack this send also fails outright with
// WSAEACCES, because the socket never asked for SO_BROADCAST -- either symptom fails here.
static int test_lan_beacon_suppressed() {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) return fail("beacon socket", WSAGetLastError());

    sockaddr_in beacon = {};
    beacon.sin_family = AF_INET;
    beacon.sin_port = htons(40112);
    beacon.sin_addr.s_addr = INADDR_BROADCAST;
    const char payload[] = "virtual beacon";
    const int sent = sendto(udp, payload, (int)sizeof(payload), 0,
        reinterpret_cast<const sockaddr *>(&beacon), sizeof(beacon));
    const int send_error = WSAGetLastError();
    if (sent != (int)sizeof(payload)) {
        closesocket(udp);
        return fail("virtual UDP beacon", send_error);
    }

    const int result = check_still_unbound("virtual UDP beacon", udp);
    closesocket(udp);
    return result;
}

// TCP 40110: bind() and listen() report success so amdaemon's state machine advances, but
// no listener may exist underneath, which the socket staying unbound proves.
//
// accept() is then called on a non-blocking socket: if this virtualization ever regresses
// the socket really is listening and a blocking accept() would wait for a connection that
// never comes, turning a test failure into a hung job.
static int test_lan_sync_suppressed() {
    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp == INVALID_SOCKET) return fail("sync socket", WSAGetLastError());

    sockaddr_in sync = {};
    sync.sin_family = AF_INET;
    sync.sin_port = htons(40110);
    sync.sin_addr.s_addr = INADDR_ANY;
    if (bind(tcp, reinterpret_cast<const sockaddr *>(&sync), sizeof(sync)) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(tcp);
        return fail("virtual TCP bind", error);
    }
    if (listen(tcp, 4) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(tcp);
        return fail("virtual TCP listen", error);
    }

    const int unbound = check_still_unbound("virtual TCP bind", tcp);
    if (unbound != 0) {
        closesocket(tcp);
        return unbound;
    }

    u_long nonblocking = 1;
    if (ioctlsocket(tcp, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(tcp);
        return fail("sync non-blocking", error);
    }
    const SOCKET accepted = accept(tcp, nullptr, nullptr);
    const int accept_error = WSAGetLastError();
    if (accepted != INVALID_SOCKET) closesocket(accepted);
    closesocket(tcp);
    if (accepted != INVALID_SOCKET || accept_error != WSAEWOULDBLOCK)
        return fail("virtual TCP accept", accept_error);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
        fwprintf(stderr, L"Usage: %s <hook.dll>\n", argv[0]);
        return 2;
    }
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return fail("WSAStartup", WSAGetLastError());
    HMODULE hook = LoadLibraryW(argv[1]);
    if (hook == nullptr) return fail("LoadLibraryW", GetLastError());
    Sleep(300);

    if (test_party_loopback() != 0) return 1;
    if (test_lan_beacon_suppressed() != 0) return 1;
    if (test_lan_sync_suppressed() != 0) return 1;

    WSACleanup();
    puts("PASS: loopback Party and LAN Install virtualization smoke tests");
    return 0;
}
