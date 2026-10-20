// A deliberately narrow host: imports only socket() and bind() from ws2_32.
//
// It exists to prove that the hook's new IAT coverage report actually detects a
// gap. Against a full host the report says "candidates=24 patched=24"; against
// this one it must say "candidates=2" and list the other 22 as not_present.
// If it cannot report a gap it cannot answer "did every slot get patched?".
//
// Build (x86):
//   cl /nologo /std:c++17 /O2 /MT /W4 probe_narrow_host.cpp /link ws2_32.lib
// Usage:
//   probe_narrow_host.exe <hook dll>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

typedef void *vp;
// Only these two are imported; everything else in the hook table must be
// reported as not_present.
vp volatile g_force[] = { (vp)&socket, (vp)&bind };

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hook dll>\n", argv[0]);
        return 2;
    }
    WSADATA w = {};
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;

    HMODULE d = LoadLibraryA(argv[1]);
    printf("LoadLibrary = %p (err=%lu)\n", (void *)d, GetLastError());
    if (d == NULL) return 1;

    // Let the hook's initialize thread finish patching.
    Sleep(3000);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(50201);
    a.sin_addr.s_addr = INADDR_ANY;
    int r = bind(s, (const sockaddr *)&a, sizeof(a));
    printf("bind(50201) = %d err=%d\n", r, (r == SOCKET_ERROR) ? WSAGetLastError() : 0);
    if (r == 0) closesocket(s);

    WSACleanup();
    return 0;
}
