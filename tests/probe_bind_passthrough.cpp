// Decides whether the hook changes bind() behaviour, by actually binding.
//
// This is a functional test, not a static one. The IAT probe proved both builds
// patch all 24 ws2_32 slots identically, so any remaining difference is runtime
// behaviour -- and the only runtime behaviour that can matter is what the hook
// does when a real call passes through it.
//
// Run three times, same binary:
//   probe_bind_passthrough.exe                 (no DLL  -- baseline)
//   probe_bind_passthrough.exe <local dll>
//   probe_bind_passthrough.exe <ci dll>
//
// If the baseline binds and a DLL run does not, the hook is the cause and the
// report will say which call failed. If all three bind, the hook does not break
// bind and the game-side explanation must be sought elsewhere.
//
// Build (x86, because chusanApp.exe is x86):
//   cl /nologo /std:c++17 /O2 /MT /W4 probe_bind_passthrough.cpp /link ws2_32.lib

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// Kept alive so the linker emits real imports for every hooked function; the
// hook can only patch slots the host actually imports.
typedef void *vp;
vp volatile g_force[] = {
    (vp)&bind, (vp)&socket, (vp)&setsockopt, (vp)&getsockopt, (vp)&closesocket,
    (vp)&sendto, (vp)&recvfrom, (vp)&listen, (vp)&connect, (vp)&select,
    (vp)&shutdown, (vp)&ioctlsocket, (vp)&accept, (vp)&send, (vp)&recv,
    (vp)&WSAAccept, (vp)&WSAConnect, (vp)&WSAEnumNetworkEvents, (vp)&WSAEventSelect,
    (vp)&WSARecv, (vp)&WSARecvFrom, (vp)&WSASend, (vp)&WSASendTo, (vp)&WSASocketW,
};

static const char *err_name(int e) {
    switch (e) {
    case 0: return "OK";
    case WSAEADDRINUSE: return "WSAEADDRINUSE";
    case WSAEADDRNOTAVAIL: return "WSAEADDRNOTAVAIL";
    case WSAEACCES: return "WSAEACCES";
    case WSAEINVAL: return "WSAEINVAL";
    case WSAENOTSOCK: return "WSAENOTSOCK";
    case WSANOTINITIALISED: return "WSANOTINITIALISED";
    default: return "?";
    }
}

static void one_attempt(const char *label, const char *ip, unsigned short port) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        printf("  %-28s socket FAILED err=%d/%s\n", label, WSAGetLastError(),
               err_name(WSAGetLastError()));
        return;
    }

    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = (ip == NULL) ? INADDR_ANY : inet_addr(ip);

    int r = bind(s, (const sockaddr *)&a, sizeof(a));
    int e = (r == SOCKET_ERROR) ? WSAGetLastError() : 0;
    printf("  %-28s socket=%llu bind=%s err=%d/%s\n", label,
           (unsigned long long)s, (r == 0) ? "ok" : "FAIL", e, err_name(e));

    // Prove the socket is genuinely usable, not just "bind returned 0".
    if (r == 0) {
        sockaddr_in got = {};
        int gl = sizeof(got);
        if (getsockname(s, (sockaddr *)&got, &gl) == 0) {
            printf("  %-28s getsockname -> %s:%u\n", "", inet_ntoa(got.sin_addr),
                   ntohs(got.sin_port));
        }
    }
    closesocket(s);
}

int main(int argc, char **argv) {
    printf("=== probe_bind_passthrough ===\n");
    if (argc >= 2) {
        HMODULE d = LoadLibraryA(argv[1]);
        printf("LoadLibrary(\"%s\") = %p (err=%lu)\n", argv[1], (void *)d, GetLastError());
        if (d == NULL) return 1;
        // The hook installs from a thread created in DllMain.
        Sleep(3000);
    } else {
        printf("no DLL loaded (baseline)\n");
    }

    WSADATA w = {};
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    printf("\n-- bind attempts --\n");
    one_attempt("any:50201 (SETTING)", NULL, 50201);
    one_attempt("any:50201 again", NULL, 50201);
    one_attempt("any:50202 (ADVERTISE)", NULL, 50202);
    one_attempt("any:50200 (PARTY)", NULL, 50200);
    one_attempt("any:40110 (LAN_SYNC)", NULL, 40110);
    one_attempt("any:40112 (LAN_BEACON)", NULL, 40112);
    one_attempt("any:50203 (not watched)", NULL, 50203);

    printf("\n-- does the host's IAT still point at us? --\n");
    fflush(stdout);
    printf("(the hook's own log records whether it patched this host)\n");

    WSACleanup();
    return 0;
}
