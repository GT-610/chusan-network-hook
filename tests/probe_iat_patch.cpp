// Measures exactly which ws2_32 IAT slots a hook DLL rewrites in its host, WITHOUT
// launching the game.
//
// Why this exists: install_iat_hooks() returns "iat=installed" when g_hook_count != 0,
// i.e. when it patched AT LEAST ONE slot. A build that patches socket() but not bind()
// still reports iat=installed. If two builds patch different sets, a missing line in
// the log means "not intercepted", which is NOT the same as "the call failed" --
// an unpatched bind() still reaches ws2_32 and still succeeds.
//
// Method: the probe imports every function the hook table covers, snapshots its own
// IAT, loads the hook DLL (whose initialize thread patches this module's IAT),
// waits, then reports which slots changed.
//
// Build (x86, because chusanApp.exe is x86):
//   cl /nologo /std:c++17 /O2 /MT /W4 probe_iat_patch.cpp /link ws2_32.lib
// Usage:
//   probe_iat_patch.exe <path\to\chusan_network_hook_x86.dll>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// Force the linker to emit an import for every function the hook table covers.
// Without this, an unused import is dropped and cannot be tested.
typedef void *vp;
vp volatile g_force[] = {
    (vp)&accept, (vp)&bind, (vp)&closesocket, (vp)&connect, (vp)&getsockopt,
    (vp)&ioctlsocket, (vp)&listen, (vp)&recv, (vp)&recvfrom, (vp)&select,
    (vp)&send, (vp)&sendto, (vp)&setsockopt, (vp)&shutdown, (vp)&socket,
    (vp)&WSAAccept, (vp)&WSAConnect, (vp)&WSAEnumNetworkEvents, (vp)&WSAEventSelect,
    (vp)&WSARecv, (vp)&WSARecvFrom, (vp)&WSASend, (vp)&WSASendTo, (vp)&WSASocketW,
};

struct Entry {
    char name[128];
    void **slot;
    void *value;
};

static int collect(Entry *out, int cap) {
    int n = 0;
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY &dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return 0;
    IMAGE_IMPORT_DESCRIPTOR *desc =
        (IMAGE_IMPORT_DESCRIPTOR *)(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char *dll = (const char *)(base + desc->Name);
        if (_stricmp(dll, "ws2_32.dll") && _stricmp(dll, "wsock32.dll")) continue;
        if (!desc->OriginalFirstThunk) continue;
#ifdef _WIN64
        IMAGE_THUNK_DATA64 *names = (IMAGE_THUNK_DATA64 *)(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)(base + desc->FirstThunk);
#else
        IMAGE_THUNK_DATA32 *names = (IMAGE_THUNK_DATA32 *)(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA32 *iat = (IMAGE_THUNK_DATA32 *)(base + desc->FirstThunk);
#endif
        for (; names->u1.AddressOfData && n < cap; ++names, ++iat) {
#ifdef _WIN64
            bool by_ordinal = IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal) != 0;
#else
            bool by_ordinal = IMAGE_SNAP_BY_ORDINAL32(names->u1.Ordinal) != 0;
#endif
            Entry &e = out[n];
            if (by_ordinal) {
#ifdef _WIN64
                unsigned ord = (unsigned)IMAGE_ORDINAL64(names->u1.Ordinal);
#else
                unsigned ord = (unsigned)IMAGE_ORDINAL32(names->u1.Ordinal);
#endif
                _snprintf_s(e.name, sizeof(e.name), _TRUNCATE, "#%u", ord);
            } else {
                IMAGE_IMPORT_BY_NAME *ib =
                    (IMAGE_IMPORT_BY_NAME *)(base + names->u1.AddressOfData);
                _snprintf_s(e.name, sizeof(e.name), _TRUNCATE, "%s", (const char *)ib->Name);
            }
            e.slot = (void **)&iat->u1.Function;
            e.value = *e.slot;
            ++n;
        }
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hook dll>\n", argv[0]);
        return 2;
    }

    Entry before[192];
    int nb = collect(before, 192);
    printf("host imports from ws2_32: %d\n", nb);
    fflush(stdout);

    HMODULE dll = LoadLibraryA(argv[1]);
    if (dll == NULL) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }

    // The hook installs from a thread spawned in DllMain; give it time.
    Sleep(3000);

    Entry after[192];
    int na = collect(after, 192);

    int patched = 0;
    printf("\n%-26s %s\n", "function", "state");
    printf("------------------------------------------------------\n");
    for (int i = 0; i < nb && i < na; ++i) {
        bool changed = before[i].value != after[i].value;
        if (changed) ++patched;
        printf("%-26s %s\n", before[i].name, changed ? "PATCHED" : "original");
    }
    printf("\nSUMMARY dll=%s imports=%d patched=%d\n", argv[1], nb, patched);
    fflush(stdout);

    FreeLibrary(dll);
    return 0;
}
