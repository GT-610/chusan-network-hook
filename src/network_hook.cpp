#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <bcrypt.h>

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {

// LAN Install virtualization is intentionally socketless at the network boundary:
// the original bind/listen/connect/send/recv calls for ports 40110/40112 are not
// forwarded to Winsock. The valid return values only keep amdaemon's state machine
// moving while preventing any LAN Install listener or packet from being created.

constexpr uint16_t kLanSyncPort = 40110;
constexpr uint16_t kLanBeaconPort = 40112;
constexpr uint16_t kPartyPort = 50200;
constexpr uint16_t kSettingPort = 50201;
constexpr uint16_t kAdvertisePort = 50202;
constexpr size_t kSocketCapacity = 256;
constexpr size_t kHexLimit = 96;
constexpr size_t kStreamCapacity = 32768;
constexpr unsigned char kProtocolKey[16] = {
    'C', 'H', 'U', 'N', 'I', 'C', 'H', 'U', 'N', 'I', 'C', 'H', 'U', 'N', 'I', 'C'
};

struct Config {
    bool network_enable = false;
    char interface_address[INET_ADDRSTRLEN] = {};
    bool force_limited_broadcast = true;
    bool force_tcp_source = true;
    bool strict = true;
    bool lan_install_enable = true;
    bool log_enable = true;
    bool log_detailed = false;
    bool log_write_file = false;
};

HMODULE g_dll;
SRWLOCK g_log_lock = SRWLOCK_INIT;
SRWLOCK g_state_lock = SRWLOCK_INIT;
Config g_config;
HANDLE g_log_file = INVALID_HANDLE_VALUE;
volatile LONG g_hook_count;
volatile LONG g_duplicate_checks;
LARGE_INTEGER g_qpc_frequency;
LARGE_INTEGER g_qpc_start;
wchar_t g_config_path[MAX_PATH];
wchar_t g_log_path[MAX_PATH];
in_addr g_interface_address = {};
ULONG g_interface_index;
ULONG g_interface_prefix_length;
char g_interface_name[512];
bool g_network_ready;
BCRYPT_ALG_HANDLE g_aes_provider;
BCRYPT_KEY_HANDLE g_aes_key;
PUCHAR g_aes_key_object;
ULONG g_aes_key_object_length;
volatile LONG g_crypto_ready;

struct SocketState {
    bool used;
    SOCKET socket;
    uint16_t virtual_lan_port;
    bool broadcast_interface_configured;
    bool tcp_source_bound;
    bool route_logged;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    unsigned char tx_stream[kStreamCapacity];
    size_t tx_stream_length;
    unsigned char rx_stream[kStreamCapacity];
    size_t rx_stream_length;
    sockaddr_storage local;
    int local_length;
    sockaddr_storage remote;
    int remote_length;
};
SocketState g_sockets[kSocketCapacity];

using socket_fn = SOCKET (WSAAPI *)(int, int, int);
using bind_fn = int (WSAAPI *)(SOCKET, const sockaddr *, int);
using listen_fn = int (WSAAPI *)(SOCKET, int);
using connect_fn = int (WSAAPI *)(SOCKET, const sockaddr *, int);
using accept_fn = SOCKET (WSAAPI *)(SOCKET, sockaddr *, int *);
using send_fn = int (WSAAPI *)(SOCKET, const char *, int, int);
using recv_fn = int (WSAAPI *)(SOCKET, char *, int, int);
using sendto_fn = int (WSAAPI *)(SOCKET, const char *, int, int, const sockaddr *, int);
using recvfrom_fn = int (WSAAPI *)(SOCKET, char *, int, int, sockaddr *, int *);
using closesocket_fn = int (WSAAPI *)(SOCKET);
using setsockopt_fn = int (WSAAPI *)(SOCKET, int, int, const char *, int);
using getsockopt_fn = int (WSAAPI *)(SOCKET, int, int, char *, int *);
using ioctlsocket_fn = int (WSAAPI *)(SOCKET, long, u_long *);
using select_fn = int (WSAAPI *)(int, fd_set *, fd_set *, fd_set *, const timeval *);
using shutdown_fn = int (WSAAPI *)(SOCKET, int);
using wsasocketw_fn = SOCKET (WSAAPI *)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
using wsaconnect_fn = int (WSAAPI *)(SOCKET, const sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using wsasendto_fn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr *, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using wsarecvfrom_fn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr *, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using wsasend_fn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using wsarecv_fn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using wsaaccept_fn = SOCKET (WSAAPI *)(SOCKET, sockaddr *, LPINT, LPCONDITIONPROC, DWORD_PTR);
using wsaeventselect_fn = int (WSAAPI *)(SOCKET, WSAEVENT, long);
using wsaenumnetworkevents_fn = int (WSAAPI *)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);

socket_fn g_next_socket;
bind_fn g_next_bind;
listen_fn g_next_listen;
connect_fn g_next_connect;
accept_fn g_next_accept;
send_fn g_next_send;
recv_fn g_next_recv;
sendto_fn g_next_sendto;
recvfrom_fn g_next_recvfrom;
closesocket_fn g_next_closesocket;
setsockopt_fn g_next_setsockopt;
getsockopt_fn g_next_getsockopt;
ioctlsocket_fn g_next_ioctlsocket;
select_fn g_next_select;
shutdown_fn g_next_shutdown;
wsasocketw_fn g_next_wsasocketw;
wsaconnect_fn g_next_wsaconnect;
wsasendto_fn g_next_wsasendto;
wsarecvfrom_fn g_next_wsarecvfrom;
wsasend_fn g_next_wsasend;
wsarecv_fn g_next_wsarecv;
wsaaccept_fn g_next_wsaaccept;
wsaeventselect_fn g_next_wsaeventselect;
wsaenumnetworkevents_fn g_next_wsaenumnetworkevents;

uint16_t port_of(const sockaddr *address, int length) {
    if (address == nullptr) return 0;
    if (address->sa_family == AF_INET && length >= (int)sizeof(sockaddr_in))
        return ntohs(reinterpret_cast<const sockaddr_in *>(address)->sin_port);
    if (address->sa_family == AF_INET6 && length >= (int)sizeof(sockaddr_in6))
        return ntohs(reinterpret_cast<const sockaddr_in6 *>(address)->sin6_port);
    return 0;
}

bool loopback_target(const sockaddr *address, int length) {
    if (address == nullptr) return false;
    if (address->sa_family == AF_INET && length >= (int)sizeof(sockaddr_in)) {
        const uint32_t ip = ntohl(
            reinterpret_cast<const sockaddr_in *>(address)->sin_addr.s_addr);
        return (ip & 0xFF000000u) == 0x7F000000u;
    }
    if (address->sa_family == AF_INET6 && length >= (int)sizeof(sockaddr_in6)) {
        return IN6_IS_ADDR_LOOPBACK(
            &reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr) != 0;
    }
    return false;
}

bool relevant(uint16_t port) {
    return port == kLanSyncPort || port == kLanBeaconPort || port == kPartyPort ||
        port == kSettingPort || port == kAdvertisePort;
}

bool lan_install_port(uint16_t port) {
    return port == kLanSyncPort || port == kLanBeaconPort;
}


const char *service(uint16_t port) {
    switch (port) {
    case kLanSyncPort: return "LAN_SYNC";
    case kLanBeaconPort: return "LAN_BEACON";
    case kPartyPort: return "PARTY";
    case kSettingPort: return "SETTING";
    case kAdvertisePort: return "ADVERTISE";
    default: return "OTHER";
    }
}

const char *wsa_name(int error) {
    switch (error) {
    case 0: return "OK";
    case WSAEWOULDBLOCK: return "WSAEWOULDBLOCK";
    case WSAEINPROGRESS: return "WSAEINPROGRESS";
    case WSAEALREADY: return "WSAEALREADY";
    case WSAEADDRINUSE: return "WSAEADDRINUSE";
    case WSAEADDRNOTAVAIL: return "WSAEADDRNOTAVAIL";
    case WSAENETDOWN: return "WSAENETDOWN";
    case WSAENETUNREACH: return "WSAENETUNREACH";
    case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH";
    case WSAECONNRESET: return "WSAECONNRESET";
    case WSAECONNREFUSED: return "WSAECONNREFUSED";
    case WSAETIMEDOUT: return "WSAETIMEDOUT";
    case WSAENOTSOCK: return "WSAENOTSOCK";
    case WSAEINVAL: return "WSAEINVAL";
    case WSAEACCES: return "WSAEACCES";
    default: return "WSA_UNKNOWN";
    }
}

void endpoint(const sockaddr *address, int length, char *out, size_t out_size) {
    if (out_size == 0) return;
    out[0] = 0;
    if (address == nullptr) { strcpy_s(out, out_size, "-"); return; }
    if (address->sa_family == AF_INET && length >= (int)sizeof(sockaddr_in)) {
        const sockaddr_in *v = reinterpret_cast<const sockaddr_in *>(address);
        const uint32_t ip = ntohl(v->sin_addr.s_addr);
        _snprintf_s(out, out_size, _TRUNCATE, "%u.%u.%u.%u:%u",
            (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255,
            ntohs(v->sin_port));
        return;
    }
    if (address->sa_family == AF_INET6 && length >= (int)sizeof(sockaddr_in6)) {
        char ip[INET6_ADDRSTRLEN] = {};
        const sockaddr_in6 *v = reinterpret_cast<const sockaddr_in6 *>(address);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR *>(&v->sin6_addr), ip, sizeof(ip)))
            _snprintf_s(out, out_size, _TRUNCATE, "[%s]:%u", ip, ntohs(v->sin6_port));
        return;
    }
    _snprintf_s(out, out_size, _TRUNCATE, "af=%d", address->sa_family);
}

void hex_dump(const char *data, int length, char *out, size_t out_size) {
    static const char digits[] = "0123456789ABCDEF";
    if (out_size == 0) return;
    size_t count = length > 0 ? (size_t)length : 0;
    if (count > kHexLimit) count = kHexLimit;
    size_t cursor = 0;
    for (size_t i = 0; i < count && cursor + 3 < out_size; ++i) {
        if (i) out[cursor++] = ' ';
        const unsigned char c = (unsigned char)data[i];
        out[cursor++] = digits[c >> 4];
        out[cursor++] = digits[c & 15];
    }
    out[cursor] = 0;
}

bool config_bool(const wchar_t *section, const wchar_t *key, bool fallback) {
    return GetPrivateProfileIntW(section, key, fallback ? 1 : 0, g_config_path) != 0;
}

void configure_paths() {
    wchar_t module_path[MAX_PATH] = {};
    GetModuleFileNameW(g_dll, module_path, MAX_PATH);
    wchar_t *separator = wcsrchr(module_path, L'\\');
    if (separator != nullptr) {
        *separator = L'\0';
    } else {
        GetCurrentDirectoryW(MAX_PATH, module_path);
    }
    _snwprintf_s(g_config_path, MAX_PATH, _TRUNCATE,
        L"%s\\network_hook.ini", module_path);

    wchar_t log_directory[MAX_PATH] = {};
    _snwprintf_s(log_directory, MAX_PATH, _TRUNCATE,
        L"%s\\network_hook_logs", module_path);
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    _snwprintf_s(g_log_path, MAX_PATH, _TRUNCATE,
        L"%s\\network_hook_%04u%02u%02u_%02u%02u%02u_pid%lu.log",
        log_directory, now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
        now.wSecond, GetCurrentProcessId());
}

void load_config() {
    g_config.network_enable = config_bool(L"network", L"enable", false);
    wchar_t interface_address[INET_ADDRSTRLEN] = {};
    GetPrivateProfileStringW(L"network", L"interfaceAddress", L"",
        interface_address, (DWORD)(sizeof(interface_address) / sizeof(interface_address[0])),
        g_config_path);
    WideCharToMultiByte(CP_UTF8, 0, interface_address, -1,
        g_config.interface_address, sizeof(g_config.interface_address), nullptr, nullptr);
    g_config.force_limited_broadcast =
        config_bool(L"network", L"forceLimitedBroadcast", true);
    g_config.force_tcp_source = config_bool(L"network", L"forceTcpSource", true);
    g_config.strict = config_bool(L"network", L"strict", true);
    g_config.lan_install_enable = config_bool(L"lanInstall", L"enable", true);
    g_config.log_enable = config_bool(L"log", L"enable", true);
    g_config.log_detailed = config_bool(L"log", L"detailed", false);
    g_config.log_write_file = config_bool(L"log", L"writeFile", false);
}

void open_log_file() {
    if (!g_config.log_enable || !g_config.log_write_file) return;
    wchar_t log_directory[MAX_PATH] = {};
    wcsncpy_s(log_directory, g_log_path, _TRUNCATE);
    wchar_t *separator = wcsrchr(log_directory, L'\\');
    if (separator != nullptr) {
        *separator = L'\0';
        CreateDirectoryW(log_directory, nullptr);
    }
    g_log_file = CreateFileW(g_log_path, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
}

void write_log_v(bool detailed, const char *category, const char *format, va_list args) {
    const int saved_wsa_error = WSAGetLastError();
    if (!g_config.log_enable || (detailed && !g_config.log_detailed)) {
        WSASetLastError(saved_wsa_error);
        return;
    }
    char message[3584] = {};
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    LARGE_INTEGER qpc = {};
    QueryPerformanceCounter(&qpc);
    double elapsed = 0.0;
    if (g_qpc_frequency.QuadPart) {
        elapsed = (double)(qpc.QuadPart - g_qpc_start.QuadPart) * 1000.0 /
            (double)g_qpc_frequency.QuadPart;
    }
    char line[4096] = {};
    const int length = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u\t+%.3fms\tpid=%lu\ttid=%lu\t%s\t%s\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
        now.wMilliseconds, elapsed, GetCurrentProcessId(), GetCurrentThreadId(),
        category, message);
    if (length <= 0) {
        WSASetLastError(saved_wsa_error);
        return;
    }
    AcquireSRWLockExclusive(&g_log_lock);
    if (g_log_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_log_file, line, (DWORD)length, &written, nullptr);
        FlushFileBuffers(g_log_file);
    }
    OutputDebugStringA(line);
    fputs(line, stderr);
    fflush(stderr);
    ReleaseSRWLockExclusive(&g_log_lock);
    WSASetLastError(saved_wsa_error);
}

void log_line(const char *category, const char *format, ...) {
    va_list args;
    va_start(args, format);
    write_log_v(true, category, format, args);
    va_end(args);
}

void human_line(const char *category, const char *format, ...) {
    va_list args;
    va_start(args, format);
    write_log_v(false, category, format, args);
    va_end(args);
}

void status_line(const char *format, ...) {
    char message[2048] = {};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    va_end(args);
    char line[2304] = {};
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[network_hook] STATUS pid=%lu %s\n", GetCurrentProcessId(), message);
    AcquireSRWLockExclusive(&g_log_lock);
    OutputDebugStringA(line);
    fputs(line, stderr);
    fflush(stderr);
    ReleaseSRWLockExclusive(&g_log_lock);
}

void save_address(SocketState *state, const sockaddr *address, int length, bool remote) {
    if (address == nullptr || length <= 0) return;
    int copy = length;
    if (copy > (int)sizeof(sockaddr_storage)) copy = sizeof(sockaddr_storage);
    sockaddr_storage *dst = remote ? &state->remote : &state->local;
    int *dst_len = remote ? &state->remote_length : &state->local_length;
    memset(dst, 0, sizeof(*dst));
    memcpy(dst, address, copy);
    *dst_len = copy;
}

SocketState *state_for(SOCKET socket, bool create) {
    if (!create) {
        AcquireSRWLockShared(&g_state_lock);
        for (size_t i = 0; i < kSocketCapacity; ++i) {
            if (g_sockets[i].used && g_sockets[i].socket == socket) {
                SocketState *state = &g_sockets[i];
                ReleaseSRWLockShared(&g_state_lock);
                return state;
            }
        }
        ReleaseSRWLockShared(&g_state_lock);
        return nullptr;
    }

    AcquireSRWLockExclusive(&g_state_lock);
    SocketState *free_slot = nullptr;
    for (size_t i = 0; i < kSocketCapacity; ++i) {
        if (g_sockets[i].used && g_sockets[i].socket == socket) {
            ReleaseSRWLockExclusive(&g_state_lock);
            return &g_sockets[i];
        }
        if (!g_sockets[i].used && free_slot == nullptr) free_slot = &g_sockets[i];
    }
    if (create && free_slot != nullptr) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->used = true;
        free_slot->socket = socket;
    }
    ReleaseSRWLockExclusive(&g_state_lock);
    return free_slot;
}

void refresh_addresses(SocketState *state) {
    if (state == nullptr) return;
    sockaddr_storage address = {};
    int length = sizeof(address);
    if (getsockname(state->socket, reinterpret_cast<sockaddr *>(&address), &length) == 0)
        save_address(state, reinterpret_cast<const sockaddr *>(&address), length, false);
    memset(&address, 0, sizeof(address));
    length = sizeof(address);
    if (getpeername(state->socket, reinterpret_cast<sockaddr *>(&address), &length) == 0)
        save_address(state, reinterpret_cast<const sockaddr *>(&address), length, true);
}

uint16_t state_port(const SocketState *state) {
    uint16_t p = port_of(reinterpret_cast<const sockaddr *>(&state->local), state->local_length);
    if (relevant(p)) return p;
    return port_of(reinterpret_cast<const sockaddr *>(&state->remote), state->remote_length);
}

void log_io(const char *op, SOCKET socket, int result, int error,
            const sockaddr *address, int address_length, const char *data, int data_length) {
    SocketState *state = state_for(socket, false);
    char local[96] = "-", remote[96] = "-";
    uint16_t p = 0;
    if (state != nullptr) {
        endpoint(reinterpret_cast<const sockaddr *>(&state->local), state->local_length, local, sizeof(local));
        endpoint(reinterpret_cast<const sockaddr *>(&state->remote), state->remote_length, remote, sizeof(remote));
        p = state_port(state);
    }
    char target[96] = "-";
    if (address != nullptr) {
        endpoint(address, address_length, target, sizeof(target));
        const uint16_t address_port = port_of(address, address_length);
        if (address_port != 0) p = address_port;
    }
    if (!relevant(p)) return;
    char hex[3 * kHexLimit + 1] = {};
    if (data != nullptr && data_length > 0) hex_dump(data, data_length, hex, sizeof(hex));
    log_line("NET", "%s sock=%llu service=%s local=%s remote=%s target=%s result=%d error=%d/%s bytes=%d hex=%s",
        op, (unsigned long long)(uintptr_t)socket, service(p), local, remote, target,
        result, error, wsa_name(error), data_length, hex);
}

void wide_to_utf8(const wchar_t *input, char *output, size_t output_size) {
    if (output_size == 0) return;
    output[0] = '\0';
    if (input == nullptr) return;
    WideCharToMultiByte(CP_UTF8, 0, input, -1, output,
        (int)output_size, nullptr, nullptr);
}

bool resolve_network_interface() {
    g_network_ready = false;
    g_interface_index = 0;
    g_interface_prefix_length = 0;
    g_interface_name[0] = '\0';
    if (!g_config.network_enable) return true;
    if (InetPtonA(AF_INET, g_config.interface_address, &g_interface_address) != 1) {
        human_line("ERROR", "The configured interfaceAddress '%s' is not a valid IPv4 address.",
            g_config.interface_address[0] ? g_config.interface_address : "(empty)");
        return false;
    }

    ULONG size = 16 * 1024;
    IP_ADAPTER_ADDRESSES *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
    if (addresses == nullptr) {
        human_line("ERROR", "Could not enumerate network adapters: out of memory.");
        return false;
    }
    ULONG result = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER, nullptr, addresses, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, addresses);
        addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
        if (addresses != nullptr) {
            result = GetAdaptersAddresses(AF_INET,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER, nullptr, addresses, &size);
        }
    }
    if (addresses == nullptr || result != NO_ERROR) {
        human_line("ERROR", "Could not enumerate network adapters (result=%lu).", result);
        if (addresses != nullptr) HeapFree(GetProcessHeap(), 0, addresses);
        return false;
    }

    for (IP_ADAPTER_ADDRESSES *adapter = addresses;
         adapter != nullptr && !g_network_ready; adapter = adapter->Next) {
        for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
             unicast != nullptr; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == nullptr ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) continue;
            const sockaddr_in *address = reinterpret_cast<const sockaddr_in *>(
                unicast->Address.lpSockaddr);
            if (address->sin_addr.s_addr != g_interface_address.s_addr) continue;
            g_interface_index = adapter->IfIndex;
            g_interface_prefix_length = unicast->OnLinkPrefixLength;
            wide_to_utf8(adapter->FriendlyName, g_interface_name, sizeof(g_interface_name));
            g_network_ready = adapter->OperStatus == IfOperStatusUp;
            if (!g_network_ready) {
                human_line("ERROR", "The configured interface %s (%s) is not up.",
                    g_config.interface_address, g_interface_name);
            }
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, addresses);
    if (!g_network_ready) {
        human_line("ERROR", "No active adapter owns interfaceAddress %s.",
            g_config.interface_address);
        return false;
    }
    human_line("INFO", "Using network interface %s (%s, index %lu, prefix /%lu).",
        g_config.interface_address, g_interface_name, g_interface_index,
        g_interface_prefix_length);
    return true;
}

void log_adapters() {
    if (!g_config.log_detailed) return;
    ULONG size = 16 * 1024;
    IP_ADAPTER_ADDRESSES *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
    if (addresses == nullptr) {
        log_line("ADAPTER", "enumeration=failed reason=out_of_memory");
        return;
    }
    ULONG result = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, addresses, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, addresses);
        addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
        if (addresses != nullptr) {
            result = GetAdaptersAddresses(AF_INET,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                nullptr, addresses, &size);
        }
    }
    if (addresses == nullptr || result != NO_ERROR) {
        log_line("ADAPTER", "enumeration=failed result=%lu", result);
        if (addresses != nullptr) HeapFree(GetProcessHeap(), 0, addresses);
        return;
    }
    for (IP_ADAPTER_ADDRESSES *adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        char friendly[512] = {};
        wide_to_utf8(adapter->FriendlyName, friendly, sizeof(friendly));
        log_line("ADAPTER", "if_index=%lu metric=%lu oper_status=%u type=%u name=\"%s\"",
            adapter->IfIndex, adapter->Ipv4Metric, (unsigned)adapter->OperStatus,
            adapter->IfType, friendly);
        for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
             unicast != nullptr; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == nullptr ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) continue;
            char address[96] = {};
            endpoint(unicast->Address.lpSockaddr, unicast->Address.iSockaddrLength,
                address, sizeof(address));
            log_line("ADDRESS", "if_index=%lu address=%s prefix_len=%u dad_state=%u",
                adapter->IfIndex, address, unicast->OnLinkPrefixLength,
                (unsigned)unicast->DadState);
        }
    }
    HeapFree(GetProcessHeap(), 0, addresses);
}

void log_route_for(const sockaddr *address, int length) {
    if (!g_config.log_detailed || address == nullptr || address->sa_family != AF_INET ||
        length < (int)sizeof(sockaddr_in)) return;
    char destination[96] = {};
    endpoint(address, length, destination, sizeof(destination));
    SOCKADDR_INET destination_address = {};
    destination_address.Ipv4 = *reinterpret_cast<const sockaddr_in *>(address);
    destination_address.Ipv4.sin_port = 0;
    SOCKADDR_INET source_address = {};
    MIB_IPFORWARD_ROW2 route = {};
    const DWORD result = GetBestRoute2(nullptr, 0, nullptr, &destination_address,
        0, &route, &source_address);
    if (result == NO_ERROR) {
        char source[96] = {};
        endpoint(reinterpret_cast<const sockaddr *>(&source_address.Ipv4),
            sizeof(source_address.Ipv4), source, sizeof(source));
        log_line("ROUTE", "destination=%s result=0 best_if_index=%lu source=%s route_metric=%lu",
            destination, route.InterfaceIndex, source, route.Metric);
    } else {
        log_line("ROUTE", "destination=%s result=%lu", destination, result);
    }
}

bool limited_broadcast_target(const sockaddr *address, int length) {
    return address != nullptr && address->sa_family == AF_INET &&
        length >= (int)sizeof(sockaddr_in) &&
        reinterpret_cast<const sockaddr_in *>(address)->sin_addr.s_addr == INADDR_BROADCAST;
}

bool network_failure(const char *operation, uint16_t port, int error) {
    human_line("ERROR", "%s failed for %s (%u) on interface %s: %d/%s.%s",
        operation, service(port), port,
        g_config.interface_address[0] ? g_config.interface_address : "(not configured)",
        error, wsa_name(error),
        g_config.strict ? " The packet was blocked by strict mode." : " Falling back to Windows routing.");
    if (g_config.strict) {
        WSASetLastError(error);
        return false;
    }
    return true;
}

bool ensure_broadcast_interface(SOCKET socket, uint16_t port) {
    if (!g_config.network_enable || !g_config.force_limited_broadcast) return true;
    const int saved_error = WSAGetLastError();
    SocketState *state = state_for(socket, true);
    if (state != nullptr && state->broadcast_interface_configured) {
        WSASetLastError(saved_error);
        return true;
    }
    if (!g_network_ready) return network_failure("Selecting the broadcast interface", port, WSAENETUNREACH);
    const DWORD interface_index = htonl(g_interface_index);
    const int result = setsockopt(socket, IPPROTO_IP, IP_UNICAST_IF,
        reinterpret_cast<const char *>(&interface_index), sizeof(interface_index));
    if (result == SOCKET_ERROR) {
        return network_failure("Selecting the broadcast interface", port, WSAGetLastError());
    }
    if (state != nullptr) state->broadcast_interface_configured = true;
    human_line("INFO", "%s broadcast is pinned to %s (%s, index %lu).",
        service(port), g_config.interface_address, g_interface_name, g_interface_index);
    log_line("INTERFACE", "action=force_broadcast socket=%llu service=%s port=%u address=%s if_index=%lu result=0",
        (unsigned long long)(uintptr_t)socket, service(port), port,
        g_config.interface_address, g_interface_index);
    WSASetLastError(saved_error);
    return true;
}

bool ensure_tcp_source(SOCKET socket, uint16_t port,
                       const sockaddr *target, int target_length) {
    if (!g_config.network_enable || !g_config.force_tcp_source) return true;
    if (loopback_target(target, target_length)) {
        char destination[96] = {};
        endpoint(target, target_length, destination, sizeof(destination));
        human_line("INFO", "%s TCP loopback connection to %s keeps the loopback source.",
            service(port), destination);
        log_line("INTERFACE", "action=skip_tcp_source socket=%llu service=%s port=%u target=%s reason=loopback",
            (unsigned long long)(uintptr_t)socket, service(port), port, destination);
        return true;
    }
    const int saved_error = WSAGetLastError();
    SocketState *state = state_for(socket, true);
    if (state != nullptr && state->tcp_source_bound) {
        WSASetLastError(saved_error);
        return true;
    }
    if (!g_network_ready) return network_failure("Binding the TCP source address", port, WSAENETUNREACH);

    sockaddr_in current = {};
    int current_length = sizeof(current);
    if (getsockname(socket, reinterpret_cast<sockaddr *>(&current), &current_length) == 0 &&
        current.sin_family == AF_INET && current.sin_addr.s_addr != INADDR_ANY) {
        if (current.sin_addr.s_addr != g_interface_address.s_addr) {
            return network_failure("Binding the TCP source address", port, WSAEADDRNOTAVAIL);
        }
        if (state != nullptr) state->tcp_source_bound = true;
        WSASetLastError(saved_error);
        return true;
    }

    sockaddr_in source = {};
    source.sin_family = AF_INET;
    source.sin_addr = g_interface_address;
    source.sin_port = 0;
    if (bind(socket, reinterpret_cast<const sockaddr *>(&source), sizeof(source)) == SOCKET_ERROR) {
        return network_failure("Binding the TCP source address", port, WSAGetLastError());
    }
    if (state != nullptr) {
        state->tcp_source_bound = true;
        save_address(state, reinterpret_cast<const sockaddr *>(&source), sizeof(source), false);
    }
    human_line("INFO", "%s TCP connections are pinned to source address %s.",
        service(port), g_config.interface_address);
    log_line("INTERFACE", "action=bind_tcp_source socket=%llu service=%s port=%u address=%s result=0",
        (unsigned long long)(uintptr_t)socket, service(port), port,
        g_config.interface_address);
    WSASetLastError(saved_error);
    return true;
}

uint32_t read_le32(const unsigned char *data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
        ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

bool protocol_port(uint16_t port) {
    return port == kPartyPort || port == kSettingPort || port == kAdvertisePort;
}

const char *message_name(uint32_t id) {
    switch (id) {
    case 0x01: return "Hello";
    case 0x02: return "HeartBeatRequest";
    case 0x03: return "HeartBeatResponse";
    case 0x04: return "RequestJoin";
    case 0x05: return "CancelJoin";
    case 0x06: return "ClientPlayInfo";
    case 0x07: return "ClientState";
    case 0x08: return "UpdateUserInfo";
    case 0x09: return "ResponseMeasure";
    case 0x0A: return "FinishNews";
    case 0x0B: return "StartRecruit";
    case 0x0C: return "FinishRecruit";
    case 0x0D: return "JoinResult";
    case 0x0E: return "Kick";
    case 0x0F: return "RequestMeasure";
    case 0x10: return "StartPlay";
    case 0x11: return "PartyPlayInfo";
    case 0x12: return "PartyMemberInfo";
    case 0x13: return "PartyMemberState";
    case 0x14: return "StartClientState";
    case 0x15: return "SettingHostAddress";
    case 0x16: return "SettingRequest";
    case 0x17: return "SettingResponse";
    case 0x18: return "AdvertiseRequest";
    case 0x19: return "AdvertiseResponse";
    case 0x1A: return "AdvertiseGo";
    default: return "Unknown";
    }
}

bool initialize_crypto() {
    if (!g_config.log_detailed) return true;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&g_aes_provider,
        BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) {
        log_line("CRYPTO", "status=failed stage=open_provider ntstatus=0x%08lX",
            (unsigned long)status);
        return false;
    }
    status = BCryptSetProperty(g_aes_provider, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_ECB)),
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status < 0) return false;
    ULONG returned = 0;
    status = BCryptGetProperty(g_aes_provider, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&g_aes_key_object_length), sizeof(g_aes_key_object_length),
        &returned, 0);
    if (status < 0 || g_aes_key_object_length == 0) return false;
    g_aes_key_object = reinterpret_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_aes_key_object_length));
    if (g_aes_key_object == nullptr) return false;
    status = BCryptGenerateSymmetricKey(g_aes_provider, &g_aes_key,
        g_aes_key_object, g_aes_key_object_length,
        const_cast<PUCHAR>(kProtocolKey), sizeof(kProtocolKey), 0);
    if (status < 0) return false;
    InterlockedExchange(&g_crypto_ready, 1);
    log_line("CRYPTO", "status=ready algorithm=AES-128 mode=ECB key_source=chusanApp_fixed_key");
    return true;
}

bool decrypt_protocol_prefix(const unsigned char *ciphertext, size_t ciphertext_length,
                             unsigned char *plaintext, size_t plaintext_capacity,
                             size_t *plaintext_length) {
    if (plaintext_length != nullptr) *plaintext_length = 0;
    if (InterlockedCompareExchange(&g_crypto_ready, 0, 0) == 0 ||
        g_aes_key == nullptr || ciphertext == nullptr || plaintext == nullptr) return false;
    size_t decrypt_length = ciphertext_length;
    if (decrypt_length > plaintext_capacity) decrypt_length = plaintext_capacity;
    decrypt_length &= ~static_cast<size_t>(15);
    if (decrypt_length < 16) return false;
    ULONG written = 0;
    const NTSTATUS status = BCryptDecrypt(g_aes_key,
        const_cast<PUCHAR>(ciphertext), (ULONG)decrypt_length,
        nullptr, nullptr, 0, plaintext, (ULONG)plaintext_capacity, &written, 0);
    if (status < 0 || written != decrypt_length) return false;
    if (plaintext_length != nullptr) *plaintext_length = written;
    return true;
}

void log_packet(const SocketState *state, const char *direction, const char *transport,
                const unsigned char *frame, size_t frame_length) {
    if (!g_config.log_detailed || frame == nullptr || frame_length < 20) return;
    char local[96] = "-", remote[96] = "-";
    endpoint(reinterpret_cast<const sockaddr *>(&state->local), state->local_length,
        local, sizeof(local));
    endpoint(reinterpret_cast<const sockaddr *>(&state->remote), state->remote_length,
        remote, sizeof(remote));
    char raw_hex[3 * kHexLimit + 1] = {};
    char plain_hex[3 * kHexLimit + 1] = {};
    hex_dump(reinterpret_cast<const char *>(frame), (int)frame_length,
        raw_hex, sizeof(raw_hex));
    unsigned char plaintext[256] = {};
    size_t requested = frame_length - 4;
    if (requested > sizeof(plaintext)) requested = sizeof(plaintext);
    if (requested > kHexLimit) requested = kHexLimit;
    requested &= ~static_cast<size_t>(15);
    size_t plaintext_length = 0;
    const bool decoded = requested >= 16 && decrypt_protocol_prefix(frame + 4,
        frame_length - 4, plaintext, requested, &plaintext_length);
    const uint16_t port = state_port(state);
    if (decoded && plaintext_length >= 16) {
        hex_dump(reinterpret_cast<const char *>(plaintext), (int)plaintext_length,
            plain_hex, sizeof(plain_hex));
        const uint32_t message = read_le32(plaintext + 8);
        log_line("PACKET",
            "dir=%s transport=%s service=%s port=%u socket=%llu local=%s remote=%s "
            "frame_len=%zu decoded=1 protocol=%08X/%08X msg=0x%02X name=%s "
            "archive0=%08X plain_hex=\"%s%s\" raw_hex=\"%s%s\"",
            direction, transport, service(port), port,
            (unsigned long long)(uintptr_t)state->socket, local, remote, frame_length,
            read_le32(plaintext), read_le32(plaintext + 4), message,
            message_name(message), read_le32(plaintext + 12), plain_hex,
            plaintext_length < frame_length - 4 ? " ..." : "", raw_hex,
            frame_length > kHexLimit ? " ..." : "");
    } else {
        log_line("PACKET",
            "dir=%s transport=%s service=%s port=%u socket=%llu local=%s remote=%s "
            "frame_len=%zu decoded=0 raw_hex=\"%s%s\"",
            direction, transport, service(port), port,
            (unsigned long long)(uintptr_t)state->socket, local, remote, frame_length,
            raw_hex, frame_length > kHexLimit ? " ..." : "");
    }
}

void log_unparsed(const SocketState *state, const char *direction, const char *transport,
                  const unsigned char *data, size_t length, const char *reason) {
    if (!g_config.log_detailed) return;
    char hex[3 * kHexLimit + 1] = {};
    hex_dump(reinterpret_cast<const char *>(data), (int)length, hex, sizeof(hex));
    log_line("DATA", "dir=%s transport=%s service=%s port=%u socket=%llu bytes=%zu reason=%s hex=\"%s%s\"",
        direction, transport, service(state_port(state)), state_port(state),
        (unsigned long long)(uintptr_t)state->socket, length, reason, hex,
        length > kHexLimit ? " ..." : "");
}

void parse_datagram(SocketState *state, const char *direction,
                    const unsigned char *data, size_t length) {
    if (!g_config.log_detailed || state == nullptr || data == nullptr) return;
    size_t cursor = 0;
    while (length - cursor >= 4) {
        const uint32_t frame_length = read_le32(data + cursor);
        if (frame_length < 20 || frame_length > 1024 * 1024) {
            log_unparsed(state, direction, "UDP", data + cursor,
                length - cursor, "invalid_length_prefix");
            return;
        }
        if (frame_length > length - cursor) {
            log_unparsed(state, direction, "UDP", data + cursor,
                length - cursor, "truncated_frame");
            return;
        }
        log_packet(state, direction, "UDP", data + cursor, frame_length);
        cursor += frame_length;
    }
    if (cursor != length) {
        log_unparsed(state, direction, "UDP", data + cursor,
            length - cursor, "trailing_bytes");
    }
}

void feed_stream(SocketState *state, const char *direction,
                 const unsigned char *data, size_t length) {
    if (!g_config.log_detailed || state == nullptr || data == nullptr) return;
    unsigned char *buffer = strcmp(direction, "TX") == 0 ?
        state->tx_stream : state->rx_stream;
    size_t *buffer_length = strcmp(direction, "TX") == 0 ?
        &state->tx_stream_length : &state->rx_stream_length;
    if (length > kStreamCapacity || *buffer_length + length > kStreamCapacity) {
        log_unparsed(state, direction, "TCP", data, length, "stream_buffer_overflow_reset");
        *buffer_length = 0;
        if (length > kStreamCapacity) return;
    }
    memcpy(buffer + *buffer_length, data, length);
    *buffer_length += length;
    size_t cursor = 0;
    while (*buffer_length - cursor >= 4) {
        const uint32_t frame_length = read_le32(buffer + cursor);
        if (frame_length < 20 || frame_length > 1024 * 1024) {
            log_unparsed(state, direction, "TCP", buffer + cursor,
                *buffer_length - cursor, "invalid_length_prefix_reset");
            *buffer_length = 0;
            return;
        }
        if (frame_length > *buffer_length - cursor) break;
        log_packet(state, direction, "TCP", buffer + cursor, frame_length);
        cursor += frame_length;
    }
    if (cursor != 0) {
        memmove(buffer, buffer + cursor, *buffer_length - cursor);
        *buffer_length -= cursor;
    }
}

SOCKET WSAAPI hook_socket(int af, int type, int protocol) {
    SOCKET s = g_next_socket ? g_next_socket(af, type, protocol) : INVALID_SOCKET;
    log_line("SOCKET", "api=socket af=%d type=%d protocol=%d result=%lld error=%d/%s",
        af, type, protocol, (long long)s,
        s == INVALID_SOCKET ? WSAGetLastError() : 0,
        s == INVALID_SOCKET ? wsa_name(WSAGetLastError()) : "OK");
    return s;
}

int WSAAPI hook_bind(SOCKET s, const sockaddr *name, int namelen) {
    const uint16_t port = port_of(name, namelen);
    if (g_config.lan_install_enable && lan_install_port(port)) {
        SocketState *state = state_for(s, true);
        if (state) { state->virtual_lan_port = port; save_address(state, name, namelen, false); }
        char requested[96]; endpoint(name, namelen, requested, sizeof(requested));
        log_line("LAN_VIRT", "bind_skipped port=%u requested=%s result=0", port, requested);
        return 0;
    }
    int r = g_next_bind(s, name, namelen);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (r == 0) { SocketState *st = state_for(s, true); if (st) save_address(st, name, namelen, false); }
    log_io("bind", s, r, e, name, namelen, nullptr, 0); if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_listen(SOCKET s, int backlog) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && state->virtual_lan_port == kLanSyncPort) {
        log_line("LAN_VIRT", "listen_skipped port=%u backlog=%d result=0", kLanSyncPort, backlog);
        return 0;
    }
    int r = g_next_listen(s, backlog); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_io("listen", s, r, e, nullptr, 0, nullptr, 0); if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_connect(SOCKET s, const sockaddr *name, int namelen) {
    const uint16_t port = port_of(name, namelen);
    if (g_config.lan_install_enable && port == kLanSyncPort) {
        SocketState *st = state_for(s, true); if (st) { st->virtual_lan_port = port; save_address(st, name, namelen, true); }
        char requested[96]; endpoint(name, namelen, requested, sizeof(requested));
        log_line("LAN_VIRT", "connect_skipped port=%u requested=%s result=0", port, requested);
        return 0;
    }
    if (relevant(port) && !ensure_tcp_source(s, port, name, namelen)) return SOCKET_ERROR;
    if (relevant(port)) log_route_for(name, namelen);
    SocketState *st = state_for(s, true); if (st) save_address(st, name, namelen, true);
    int r = g_next_connect(s, name, namelen); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    refresh_addresses(st);
    log_io("connect", s, r, e, name, namelen, nullptr, 0);
    if (r == SOCKET_ERROR && e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEALREADY)
        human_line("ERROR", "%s TCP connection to the peer failed: %d/%s.", service(port), e, wsa_name(e));
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

SOCKET WSAAPI hook_accept(SOCKET s, sockaddr *addr, int *len) {
    SocketState *listener = state_for(s, false);
    if (g_config.lan_install_enable && listener && listener->virtual_lan_port == kLanSyncPort) {
        WSASetLastError(WSAEWOULDBLOCK);
        log_line("LAN_VIRT", "accept_skipped port=%u result=SOCKET_ERROR error=%d/%s", kLanSyncPort, WSAEWOULDBLOCK, wsa_name(WSAEWOULDBLOCK));
        return INVALID_SOCKET;
    }
    SOCKET r = g_next_accept(s, addr, len); int e = r == INVALID_SOCKET ? WSAGetLastError() : 0;
    if (r != INVALID_SOCKET) {
        SocketState *st = state_for(r, true);
        if (st) {
            if (listener) save_address(st, reinterpret_cast<const sockaddr *>(&listener->local), listener->local_length, false);
            if (addr && len) save_address(st, addr, *len, true);
        }
    }
    log_io("accept", s, r == INVALID_SOCKET ? SOCKET_ERROR : 0, e, addr, len ? *len : 0, nullptr, 0);
    if (r == INVALID_SOCKET) WSASetLastError(e); return r;
}

int WSAAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && state->virtual_lan_port == kLanSyncPort) {
        log_line("LAN_VIRT", "send_skipped port=%u bytes=%d result=%d", kLanSyncPort, len, len);
        return len;
    }
    int r = g_next_send(s, buf, len, flags); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (state && r > 0) {
        refresh_addresses(state);
        state->tx_bytes += r;
        if (protocol_port(state_port(state)))
            feed_stream(state, "TX", reinterpret_cast<const unsigned char *>(buf), r);
    }
    log_io("send", s, r, e, nullptr, 0, buf, r > 0 ? r : 0); if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && lan_install_port(state->virtual_lan_port)) {
        WSASetLastError(WSAEWOULDBLOCK);
        log_line("LAN_VIRT", "recv_skipped port=%u result=SOCKET_ERROR error=%d/%s", state->virtual_lan_port, WSAEWOULDBLOCK, wsa_name(WSAEWOULDBLOCK));
        return SOCKET_ERROR;
    }
    int r = g_next_recv(s, buf, len, flags); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (state && r > 0) {
        refresh_addresses(state);
        state->rx_bytes += r;
        if (protocol_port(state_port(state)))
            feed_stream(state, "RX", reinterpret_cast<const unsigned char *>(buf), r);
    }
    log_io("recv", s, r, e, nullptr, 0, buf, r > 0 ? r : 0); if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_sendto(SOCKET s, const char *buf, int len, int flags, const sockaddr *to, int tolen) {
    const uint16_t port = port_of(to, tolen);
    if (g_config.lan_install_enable && port == kLanBeaconPort) {
        log_line("LAN_VIRT", "sendto_skipped port=%u bytes=%d result=%d", port, len, len);
        return len;
    }
    SocketState *state = state_for(s, true);
    if (state) save_address(state, to, tolen, true);
    if (relevant(port) && state && !state->route_logged) {
        state->route_logged = true;
        log_route_for(to, tolen);
    }
    if (relevant(port) && limited_broadcast_target(to, tolen) &&
        !ensure_broadcast_interface(s, port)) return SOCKET_ERROR;
    int r = g_next_sendto(s, buf, len, flags, to, tolen); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (state && r > 0) {
        refresh_addresses(state);
        state->tx_bytes += r;
        if (protocol_port(port))
            parse_datagram(state, "TX", reinterpret_cast<const unsigned char *>(buf), r);
    }
    log_io("sendto", s, r, e, to, tolen, buf, r > 0 ? r : 0);
    if (r == SOCKET_ERROR) human_line("ERROR", "%s broadcast send failed: %d/%s.", service(port), e, wsa_name(e));
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_recvfrom(SOCKET s, char *buf, int len, int flags, sockaddr *from, int *fromlen) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && state->virtual_lan_port == kLanBeaconPort) {
        WSASetLastError(WSAEWOULDBLOCK);
        log_line("LAN_VIRT", "recvfrom_skipped port=%u result=SOCKET_ERROR error=%d/%s", kLanBeaconPort, WSAEWOULDBLOCK, wsa_name(WSAEWOULDBLOCK));
        return SOCKET_ERROR;
    }
    int r = g_next_recvfrom(s, buf, len, flags, from, fromlen); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (state && r > 0) {
        refresh_addresses(state);
        state->rx_bytes += r;
        if (from && fromlen) save_address(state, from, *fromlen, true);
        if (protocol_port(state_port(state)))
            parse_datagram(state, "RX", reinterpret_cast<const unsigned char *>(buf), r);
    }
    log_io("recvfrom", s, r, e, from, fromlen ? *fromlen : 0, buf, r > 0 ? r : 0); if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_setsockopt(SOCKET s, int level, int optname, const char *value, int len) {
    int r = g_next_setsockopt(s, level, optname, value, len); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (level == SOL_SOCKET && (optname == SO_BROADCAST || optname == SO_REUSEADDR))
        log_io("setsockopt", s, r, e, nullptr, 0, value, len);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_getsockopt(SOCKET s, int level, int optname, char *value, int *len) {
    int r = g_next_getsockopt(s, level, optname, value, len);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (level == SOL_SOCKET && optname == SO_ERROR) {
        int so_error = (r == 0 && value && len && *len >= (int)sizeof(int)) ? *reinterpret_cast<int *>(value) : -1;
        log_io("getsockopt", s, so_error, e, nullptr, 0, nullptr, 0);
    }
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_ioctlsocket(SOCKET s, long command, u_long *argument) {
    int r = g_next_ioctlsocket(s, command, argument);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (command == FIONBIO || command == FIOASYNC)
        log_io("ioctlsocket", s, r, e, nullptr, 0,
            reinterpret_cast<const char *>(argument), argument ? (int)sizeof(*argument) : 0);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const timeval *timeout) {
    int r = g_next_select(nfds, readfds, writefds, exceptfds, timeout);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (r == SOCKET_ERROR || r > 0)
        log_line("NET", "select nfds=%d result=%d error=%d/%s", nfds, r, e, wsa_name(e));
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_shutdown(SOCKET s, int how) {
    int r = g_next_shutdown(s, how); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_io("shutdown", s, r, e, nullptr, 0, nullptr, 0);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

SOCKET WSAAPI hook_wsasocketw(int af, int type, int protocol, LPWSAPROTOCOL_INFOW info, GROUP group, DWORD flags) {
    SOCKET s = g_next_wsasocketw ? g_next_wsasocketw(af, type, protocol, info, group, flags) : INVALID_SOCKET;
    log_line("SOCKET", "api=WSASocketW af=%d type=%d protocol=%d flags=0x%lX result=%lld error=%d/%s",
        af, type, protocol, flags, (long long)s,
        s == INVALID_SOCKET ? WSAGetLastError() : 0,
        s == INVALID_SOCKET ? wsa_name(WSAGetLastError()) : "OK");
    return s;
}

int WSAAPI hook_wsaconnect(SOCKET s, const sockaddr *name, int namelen, LPWSABUF callee_data,
                           LPWSABUF caller_data, LPQOS sqos, LPQOS gqos) {
    const uint16_t port = port_of(name, namelen);
    if (g_config.lan_install_enable && port == kLanSyncPort) {
        SocketState *st = state_for(s, true); if (st) { st->virtual_lan_port = port; save_address(st, name, namelen, true); }
        char requested[96]; endpoint(name, namelen, requested, sizeof(requested));
        log_line("LAN_VIRT", "WSAConnect_skipped port=%u requested=%s result=0", port, requested);
        return 0;
    }
    if (relevant(port) && !ensure_tcp_source(s, port, name, namelen)) return SOCKET_ERROR;
    if (relevant(port)) log_route_for(name, namelen);
    SocketState *st = state_for(s, true); if (st) save_address(st, name, namelen, true);
    int r = g_next_wsaconnect(s, name, namelen, callee_data, caller_data, sqos, gqos);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    refresh_addresses(st);
    log_io("WSAConnect", s, r, e, name, namelen, nullptr, 0);
    if (r == SOCKET_ERROR && e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEALREADY)
        human_line("ERROR", "%s TCP connection to the peer failed: %d/%s.", service(port), e, wsa_name(e));
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_wsasendto(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
                          const sockaddr *to, int tolen, LPWSAOVERLAPPED overlapped,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const uint16_t port = port_of(to, tolen);
    if (g_config.lan_install_enable && port == kLanBeaconPort) {
        const DWORD bytes = buffers && count ? buffers[0].len : 0;
        if (sent) *sent = bytes;
        log_line("LAN_VIRT", "WSASendTo_skipped port=%u bytes=%lu result=0", port, (unsigned long)bytes);
        return 0;
    }
    SocketState *state = state_for(s, true);
    if (state) save_address(state, to, tolen, true);
    if (relevant(port) && state && !state->route_logged) {
        state->route_logged = true;
        log_route_for(to, tolen);
    }
    if (relevant(port) && limited_broadcast_target(to, tolen) &&
        !ensure_broadcast_interface(s, port)) {
        if (sent) *sent = 0;
        return SOCKET_ERROR;
    }
    int r = g_next_wsasendto(s, buffers, count, sent, flags, to, tolen, overlapped, completion);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    const int bytes = (sent && r == 0) ? (int)*sent : 0;
    if (state && buffers && count && bytes > 0) {
        refresh_addresses(state);
        state->tx_bytes += bytes;
        if (protocol_port(port))
            parse_datagram(state, "TX", reinterpret_cast<const unsigned char *>(buffers[0].buf),
                bytes <= (int)buffers[0].len ? bytes : buffers[0].len);
    }
    if (buffers && count) log_io("WSASendTo", s, r, e, to, tolen, buffers[0].buf, bytes);
    if (r == SOCKET_ERROR && e != WSA_IO_PENDING)
        human_line("ERROR", "%s broadcast send failed: %d/%s.", service(port), e, wsa_name(e));
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_wsarecvfrom(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD received, LPDWORD flags,
                            sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED overlapped,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && state->virtual_lan_port == kLanBeaconPort) {
        if (received) *received = 0;
        WSASetLastError(WSAEWOULDBLOCK);
        log_line("LAN_VIRT", "WSARecvFrom_skipped port=%u result=SOCKET_ERROR error=%d/%s", kLanBeaconPort, WSAEWOULDBLOCK, wsa_name(WSAEWOULDBLOCK));
        return SOCKET_ERROR;
    }
    int r = g_next_wsarecvfrom(s, buffers, count, received, flags, from, fromlen, overlapped, completion);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    const int bytes = (received && r == 0) ? (int)*received : 0;
    if (state && buffers && count && bytes > 0) {
        refresh_addresses(state);
        state->rx_bytes += bytes;
        if (from && fromlen) save_address(state, from, *fromlen, true);
        if (protocol_port(state_port(state)))
            parse_datagram(state, "RX", reinterpret_cast<const unsigned char *>(buffers[0].buf),
                bytes <= (int)buffers[0].len ? bytes : buffers[0].len);
    }
    if (buffers && count) log_io("WSARecvFrom", s, r, e, from, fromlen ? *fromlen : 0, buffers[0].buf, bytes);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_wsasend(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
                        LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && state->virtual_lan_port == kLanSyncPort) {
        const DWORD bytes = buffers && count ? buffers[0].len : 0;
        if (sent) *sent = bytes;
        log_line("LAN_VIRT", "WSASend_skipped port=%u bytes=%lu result=0", kLanSyncPort, (unsigned long)bytes);
        return 0;
    }
    int r = g_next_wsasend(s, buffers, count, sent, flags, overlapped, completion);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    const int bytes = (sent && r == 0) ? (int)*sent : 0;
    if (state && buffers && count && bytes > 0) {
        refresh_addresses(state);
        state->tx_bytes += bytes;
        if (protocol_port(state_port(state)))
            feed_stream(state, "TX", reinterpret_cast<const unsigned char *>(buffers[0].buf),
                bytes <= (int)buffers[0].len ? bytes : buffers[0].len);
    }
    if (buffers && count) log_io("WSASend", s, r, e, nullptr, 0, buffers[0].buf, bytes);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_wsarecv(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD received, LPDWORD flags,
                        LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && state->virtual_lan_port == kLanSyncPort) {
        if (received) *received = 0;
        WSASetLastError(WSAEWOULDBLOCK);
        log_line("LAN_VIRT", "WSARecv_skipped port=%u result=SOCKET_ERROR error=%d/%s", kLanSyncPort, WSAEWOULDBLOCK, wsa_name(WSAEWOULDBLOCK));
        return SOCKET_ERROR;
    }
    int r = g_next_wsarecv(s, buffers, count, received, flags, overlapped, completion);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    const int bytes = (received && r == 0) ? (int)*received : 0;
    if (state && buffers && count && bytes > 0) {
        refresh_addresses(state);
        state->rx_bytes += bytes;
        if (protocol_port(state_port(state)))
            feed_stream(state, "RX", reinterpret_cast<const unsigned char *>(buffers[0].buf),
                bytes <= (int)buffers[0].len ? bytes : buffers[0].len);
    }
    if (buffers && count) log_io("WSARecv", s, r, e, nullptr, 0, buffers[0].buf, bytes);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_wsaeventselect(SOCKET s, WSAEVENT event, long network_events) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && lan_install_port(state->virtual_lan_port)) {
        log_line("LAN_VIRT", "WSAEventSelect_skipped port=%u events=0x%lX result=0", state->virtual_lan_port, network_events);
        return 0;
    }
    int r = g_next_wsaeventselect(s, event, network_events);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

int WSAAPI hook_wsaenumnetworkevents(SOCKET s, WSAEVENT event, LPWSANETWORKEVENTS network_events) {
    SocketState *state = state_for(s, false);
    if (g_config.lan_install_enable && state && lan_install_port(state->virtual_lan_port)) {
        if (network_events) memset(network_events, 0, sizeof(*network_events));
        log_line("LAN_VIRT", "WSAEnumNetworkEvents_skipped port=%u result=0", state->virtual_lan_port);
        return 0;
    }
    int r = g_next_wsaenumnetworkevents(s, event, network_events);
    int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

SOCKET WSAAPI hook_wsaaccept(SOCKET s, sockaddr *addr, LPINT len, LPCONDITIONPROC condition, DWORD_PTR callback) {
    SocketState *listener = state_for(s, false);
    if (g_config.lan_install_enable && listener && listener->virtual_lan_port == kLanSyncPort) {
        WSASetLastError(WSAEWOULDBLOCK);
        log_line("LAN_VIRT", "WSAAccept_skipped port=%u result=SOCKET_ERROR error=%d/%s", kLanSyncPort, WSAEWOULDBLOCK, wsa_name(WSAEWOULDBLOCK));
        return INVALID_SOCKET;
    }
    SOCKET r = g_next_wsaaccept(s, addr, len, condition, callback);
    int e = r == INVALID_SOCKET ? WSAGetLastError() : 0;
    if (r != INVALID_SOCKET) {
        SocketState *st = state_for(r, true);
        if (st) {
            if (listener) save_address(st, reinterpret_cast<const sockaddr *>(&listener->local), listener->local_length, false);
            if (addr && len) save_address(st, addr, *len, true);
        }
    }
    log_io("WSAAccept", s, r == INVALID_SOCKET ? SOCKET_ERROR : 0, e, addr, len ? *len : 0, nullptr, 0);
    if (r == INVALID_SOCKET) WSASetLastError(e); return r;
}

int WSAAPI hook_closesocket(SOCKET s) {
    SocketState *state = state_for(s, false);
    if (state && relevant(state_port(state))) {
        log_line("CLOSE", "socket=%llu service=%s tx_bytes=%llu rx_bytes=%llu",
            (unsigned long long)(uintptr_t)s, service(state_port(state)),
            (unsigned long long)state->tx_bytes, (unsigned long long)state->rx_bytes);
    }
    int r = g_next_closesocket(s); int e = r == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_io("close", s, r, e, nullptr, 0, nullptr, 0);
    AcquireSRWLockExclusive(&g_state_lock);
    for (auto &entry : g_sockets) if (entry.used && entry.socket == s) entry.used = false;
    ReleaseSRWLockExclusive(&g_state_lock);
    if (r == SOCKET_ERROR) WSASetLastError(e); return r;
}

struct HookSpec { const char *name; WORD ordinal; void *replacement; void **next; };
HookSpec g_hooks[] = {
    {"accept",1,(void *)hook_accept,(void **)&g_next_accept}, {"bind",2,(void *)hook_bind,(void **)&g_next_bind},
    {"closesocket",3,(void *)hook_closesocket,(void **)&g_next_closesocket}, {"connect",4,(void *)hook_connect,(void **)&g_next_connect},
    {"listen",13,(void *)hook_listen,(void **)&g_next_listen}, {"recv",16,(void *)hook_recv,(void **)&g_next_recv},
    {"recvfrom",17,(void *)hook_recvfrom,(void **)&g_next_recvfrom}, {"send",19,(void *)hook_send,(void **)&g_next_send},
    {"sendto",20,(void *)hook_sendto,(void **)&g_next_sendto}, {"setsockopt",21,(void *)hook_setsockopt,(void **)&g_next_setsockopt},
    {"getsockopt",7,(void *)hook_getsockopt,(void **)&g_next_getsockopt}, {"ioctlsocket",10,(void *)hook_ioctlsocket,(void **)&g_next_ioctlsocket},
    {"select",18,(void *)hook_select,(void **)&g_next_select}, {"shutdown",22,(void *)hook_shutdown,(void **)&g_next_shutdown},
    {"WSASocketW",0,(void *)hook_wsasocketw,(void **)&g_next_wsasocketw}, {"WSAConnect",0,(void *)hook_wsaconnect,(void **)&g_next_wsaconnect},
    {"WSASendTo",0,(void *)hook_wsasendto,(void **)&g_next_wsasendto}, {"WSARecvFrom",0,(void *)hook_wsarecvfrom,(void **)&g_next_wsarecvfrom},
    {"WSASend",0,(void *)hook_wsasend,(void **)&g_next_wsasend}, {"WSARecv",0,(void *)hook_wsarecv,(void **)&g_next_wsarecv},
    {"WSAEventSelect",0,(void *)hook_wsaeventselect,(void **)&g_next_wsaeventselect}, {"WSAEnumNetworkEvents",0,(void *)hook_wsaenumnetworkevents,(void **)&g_next_wsaenumnetworkevents},
    {"WSAAccept",0,(void *)hook_wsaaccept,(void **)&g_next_wsaaccept}, {"socket",23,(void *)hook_socket,(void **)&g_next_socket},
};

bool install_iat_hooks(HMODULE module) {
    if (!module) return false;
    unsigned char *base = reinterpret_cast<unsigned char *>(module);
    IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;
    IMAGE_IMPORT_DESCRIPTOR *desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char *dll = reinterpret_cast<const char *>(base + desc->Name);
        if (_stricmp(dll, "ws2_32.dll") && _stricmp(dll, "wsock32.dll")) continue;
        if (!desc->OriginalFirstThunk) continue;
#ifdef _WIN64
        IMAGE_THUNK_DATA64 *names = reinterpret_cast<IMAGE_THUNK_DATA64 *>(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA64 *iat = reinterpret_cast<IMAGE_THUNK_DATA64 *>(base + desc->FirstThunk);
#else
        IMAGE_THUNK_DATA32 *names = reinterpret_cast<IMAGE_THUNK_DATA32 *>(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA32 *iat = reinterpret_cast<IMAGE_THUNK_DATA32 *>(base + desc->FirstThunk);
#endif
        for (; names->u1.AddressOfData; ++names, ++iat) {
#ifdef _WIN64
            bool by_ordinal = IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal) != 0;
            WORD ordinal = by_ordinal ? (WORD)IMAGE_ORDINAL64(names->u1.Ordinal) : 0;
#else
            bool by_ordinal = IMAGE_SNAP_BY_ORDINAL32(names->u1.Ordinal) != 0;
            WORD ordinal = by_ordinal ? (WORD)IMAGE_ORDINAL32(names->u1.Ordinal) : 0;
#endif
            const char *name = nullptr;
            if (!by_ordinal) {
                IMAGE_IMPORT_BY_NAME *import_name =
                    reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(base + names->u1.AddressOfData);
                name = reinterpret_cast<const char *>(import_name->Name);
            }
            for (auto &hook : g_hooks) {
                if ((by_ordinal && ordinal != hook.ordinal) || (!by_ordinal && (!name || strcmp(name, hook.name)))) continue;
                void **slot = reinterpret_cast<void **>(&iat->u1.Function);
                if (*slot == hook.replacement) break;
                if (*hook.next == nullptr) *hook.next = *slot;
                DWORD old = 0;
                if (VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) {
                    *slot = hook.replacement;
                    DWORD ignored; VirtualProtect(slot, sizeof(void *), old, &ignored);
                    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void *));
                    InterlockedIncrement(&g_hook_count);
                }
                break;
            }
        }
    }
    return g_hook_count != 0;
}

#ifdef _WIN64
extern "C" __declspec(noinline) bool lan_duplicate_server_false();

bool install_duplicate_server_hook(HMODULE module) {
    constexpr uintptr_t kRva = 0x2E5AD0;
    static const unsigned char expected[] = {
        0x48,0x83,0xEC,0x28,0x83,0x3D,0x85,0x8A,0x5C,0x00,0x00,0x74,0x79
    };
    unsigned char *target = reinterpret_cast<unsigned char *>(module) + kRva;
    if (memcmp(target, expected, sizeof(expected)) != 0) {
        log_line("LAN_HOOK", "status=skipped reason=prologue_mismatch rva=0x%llX", (unsigned long long)kRva);
        return false;
    }
    DWORD old = 0;
    if (!VirtualProtect(target, 13, PAGE_EXECUTE_READWRITE, &old)) {
        log_line("LAN_HOOK", "status=failed stage=VirtualProtect error=%d/%s", GetLastError(), "WIN32_ERROR");
        return false;
    }
    unsigned char patch[13] = {0x48,0xB8};
    const uintptr_t replacement = reinterpret_cast<uintptr_t>(&lan_duplicate_server_false);
    memcpy(patch + 2, &replacement, sizeof(replacement));
    patch[10] = 0xFF; patch[11] = 0xE0; patch[12] = 0x90;
    memcpy(target, patch, sizeof(patch));
    DWORD ignored; VirtualProtect(target, 13, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), target, 13);
    log_line("LAN_HOOK", "status=installed target=amdaemon.exe rva=0x%llX action=force_duplicate_server_false", (unsigned long long)kRva);
    return true;
}

extern "C" __declspec(noinline) bool lan_duplicate_server_false() {
    InterlockedIncrement(&g_duplicate_checks);
    log_line("LAN_HOOK", "duplicate_check=hit result=false count=%ld", g_duplicate_checks);
    return false;
}
#endif

DWORD WINAPI initialize(void *) {
    configure_paths();
    load_config();
    char config_path[512] = {};
    wide_to_utf8(g_config_path, config_path, sizeof(config_path));
    status_line("config=%s network.enable=%d interfaceAddress=%s forceLimitedBroadcast=%d "
        "forceTcpSource=%d strict=%d lanInstall.enable=%d log.enable=%d log.detailed=%d log.writeFile=%d",
        config_path, g_config.network_enable ? 1 : 0,
        g_config.interface_address[0] ? g_config.interface_address : "(empty)",
        g_config.force_limited_broadcast ? 1 : 0, g_config.force_tcp_source ? 1 : 0,
        g_config.strict ? 1 : 0, g_config.lan_install_enable ? 1 : 0,
        g_config.log_enable ? 1 : 0, g_config.log_detailed ? 1 : 0,
        g_config.log_write_file ? 1 : 0);
    open_log_file();
    HMODULE process = GetModuleHandleW(nullptr);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(process, path, sizeof(path));
    const char *exe = strrchr(path, '\\');
    exe = exe ? exe + 1 : path;
    human_line("INFO", "Starting in %s (%s).", exe,
#ifdef _WIN64
        "x64"
#else
        "x86"
#endif
    );
    if (g_config.log_write_file && g_log_file == INVALID_HANDLE_VALUE)
        human_line("ERROR", "File logging was requested, but the log file could not be created.");
    resolve_network_interface();
    initialize_crypto();
    log_adapters();
    bool iat = install_iat_hooks(process);
    const char *lan_hook_status = "not_applicable";
#ifdef _WIN64
    bool lan = false;
    if (g_config.lan_install_enable && _stricmp(exe, "amdaemon.exe") == 0)
        lan = install_duplicate_server_hook(process);
    if (_stricmp(exe, "amdaemon.exe") == 0)
        lan_hook_status = lan ? "installed" : (g_config.lan_install_enable ? "skipped_or_failed" : "disabled");
    log_line("START", "process=%s architecture=x64 image_base=%p iat=%s lan_duplicate_hook=%s ports=40110,40112,50200,50201,50202",
        exe, process, iat ? "installed" : "not_installed", lan ? "installed" : "not_applicable_or_skipped");
#else
    log_line("START", "process=%s architecture=x86 image_base=%p iat=%s ports=40110,40112,50200,50201,50202 lan_duplicate_hook=not_available",
        exe, process, iat ? "installed" : "not_installed");
#endif
    const char *network_status = !g_config.network_enable ? "disabled" :
        (g_network_ready ? "ready" : "failed");
    status_line("startup process=%s architecture=%s iat_hooks=%s lanInstallHook=%s network=%s "
        "interface=%s config=%s",
        exe,
#ifdef _WIN64
        "x64",
#else
        "x86",
#endif
        iat ? "installed" : "not_installed", lan_hook_status, network_status,
        g_network_ready ? g_config.interface_address : "(not selected)", config_path);
    human_line("INFO", "WinSock hooks are %s. LAN Install virtualization is %s.",
        iat ? "active" : "not active", g_config.lan_install_enable ? "enabled" : "disabled");
    human_line("INFO", "Logging is in %s mode%s.",
        g_config.log_detailed ? "detailed diagnostic" : "concise",
        g_config.log_write_file ? " and is also written to a file" : "");
    log_line("CONFIG",
        "network_enable=%d interface_address=%s force_limited_broadcast=%d force_tcp_source=%d strict=%d "
        "lan_install_enable=%d log_enable=%d log_detailed=%d log_write_file=%d",
        g_config.network_enable ? 1 : 0, g_config.interface_address,
        g_config.force_limited_broadcast ? 1 : 0, g_config.force_tcp_source ? 1 : 0,
        g_config.strict ? 1 : 0, g_config.lan_install_enable ? 1 : 0,
        g_config.log_enable ? 1 : 0, g_config.log_detailed ? 1 : 0,
        g_config.log_write_file ? 1 : 0);
    return 0;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_dll = instance;
        DisableThreadLibraryCalls(instance);
        QueryPerformanceFrequency(&g_qpc_frequency);
        QueryPerformanceCounter(&g_qpc_start);
        HANDLE thread = CreateThread(nullptr, 0, initialize, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
