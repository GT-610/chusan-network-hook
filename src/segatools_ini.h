// Minimal reader for the parts of segatools.ini this hook needs to reproduce
// netenv's decisions, so a stock segatools.ini keeps working unmodified.
//
// Only [netenv] and [keychip] matter here. Defaults mirror
// segatools/common/platform/config.c so an absent key means the same thing it
// means to segatools itself.
#pragma once

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace segatools {

struct NetenvConfig {
    bool enable = false;              // config.c:191, default 0
    bool redirect_broadcast = true;   // config.c:192, default 1
    unsigned addr_suffix = 11;        // config.c:198, default 11
    unsigned router_suffix = 254;     // config.c:204, default 254
    unsigned char mac[6] = {1, 2, 3, 4, 5, 6}; // config.c:210
};

struct KeychipConfig {
    bool enable = true;               // config.c:249, default 1
    in_addr subnet = {};              // config.c:283, default 192.168.100.0
    char subnet_text[16] = "192.168.100.0";
    in_addr broadcast = {};           // config.c:291, default 255.255.255.255
    char broadcast_text[16] = "255.255.255.255";
};

struct Config {
    bool found = false;
    wchar_t path[MAX_PATH] = {};
    NetenvConfig netenv;
    KeychipConfig keychip;
};

// `subnet` in segatools.ini is the network part ("192.168.139.0"); the address the
// game is told to expect is that network ORed with addrSuffix (netenv.c:192).
inline in_addr expected_address(const Config &cfg) {
    in_addr result = {};
    result.s_addr = htonl((ntohl(cfg.keychip.subnet.s_addr) & 0xFFFFFF00u) |
                          (cfg.netenv.addr_suffix & 0xFFu));
    return result;
}

inline in_addr subnet_network(const Config &cfg) {
    in_addr result = {};
    result.s_addr = htonl(ntohl(cfg.keychip.subnet.s_addr) & 0xFFFFFF00u);
    return result;
}

inline in_addr router_address(const Config &cfg) {
    in_addr result = {};
    result.s_addr = htonl((ntohl(cfg.keychip.subnet.s_addr) & 0xFFFFFF00u) |
                          (cfg.netenv.router_suffix & 0xFFu));
    return result;
}

inline unsigned read_uint(const wchar_t *path, const wchar_t *section,
                          const wchar_t *key, unsigned fallback) {
    return (unsigned)GetPrivateProfileIntW(section, key, (INT)fallback, path);
}

inline void read_text(const wchar_t *path, const wchar_t *section, const wchar_t *key,
                      const wchar_t *fallback, wchar_t *out, size_t out_count) {
    GetPrivateProfileStringW(section, key, fallback, out, (DWORD)out_count, path);
}

inline bool parse_ipv4(const wchar_t *text, in_addr *out) {
    wchar_t buffer[64] = {};
    wcsncpy_s(buffer, text, _TRUNCATE);
    unsigned octet[4] = {};
    if (swscanf_s(buffer, L"%u.%u.%u.%u", &octet[0], &octet[1], &octet[2], &octet[3]) != 4)
        return false;
    for (int i = 0; i < 4; ++i) {
        if (octet[i] > 255) return false;
    }
    *out = {};
    reinterpret_cast<unsigned char *>(&out->s_addr)[0] = (unsigned char)octet[0];
    reinterpret_cast<unsigned char *>(&out->s_addr)[1] = (unsigned char)octet[1];
    reinterpret_cast<unsigned char *>(&out->s_addr)[2] = (unsigned char)octet[2];
    reinterpret_cast<unsigned char *>(&out->s_addr)[3] = (unsigned char)octet[3];
    return true;
}

inline void parse_mac(const wchar_t *text, unsigned char *out) {
    wchar_t buffer[32] = {};
    wcsncpy_s(buffer, text, _TRUNCATE);
    unsigned value[6] = {};
    if (swscanf_s(buffer, L"%x:%x:%x:%x:%x:%x", &value[0], &value[1], &value[2],
                  &value[3], &value[4], &value[5]) != 6)
        return;
    for (int i = 0; i < 6; ++i) out[i] = (unsigned char)value[i];
}

// Finds segatools.ini. `dll_dir` is where network_hook.dll lives, which in a
// normal segatools install is also where segatools.ini and the game live, so the
// same-directory case is tried first.
inline bool locate(const wchar_t *dll_dir, const wchar_t *explicit_path,
                   wchar_t *out, size_t out_count) {
    if (explicit_path != nullptr && explicit_path[0] != 0) {
        if (GetFileAttributesW(explicit_path) == INVALID_FILE_ATTRIBUTES) {
            // An explicitly configured path that does not exist is a hard error:
            // silently falling back would hide a typo.
            _snwprintf_s(out, out_count, _TRUNCATE, L"%s", explicit_path);
            return false;
        }
        _snwprintf_s(out, out_count, _TRUNCATE, L"%s", explicit_path);
        return true;
    }

    wchar_t candidate[MAX_PATH] = {};
    _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\segatools.ini", dll_dir);
    if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
        _snwprintf_s(out, out_count, _TRUNCATE, L"%s", candidate);
        return true;
    }

    // segatools puts the hook DLLs one level above bin/, so the caller may be in
    // bin/ while segatools.ini sits in the package root.
    wchar_t parent[MAX_PATH] = {};
    _snwprintf_s(parent, MAX_PATH, _TRUNCATE, L"%s", dll_dir);
    wchar_t *separator = wcsrchr(parent, L'\\');
    if (separator != nullptr) {
        *separator = L'\0';
        _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\segatools.ini", parent);
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
            _snwprintf_s(out, out_count, _TRUNCATE, L"%s", candidate);
            return true;
        }
    }
    return false;
}

inline bool load(Config *cfg, const wchar_t *dll_dir, const wchar_t *explicit_path,
                 wchar_t *problem, size_t problem_count) {
    *cfg = {};
    wchar_t found[MAX_PATH] = {};
    const bool located = locate(dll_dir, explicit_path, found, MAX_PATH);
    if (!located) {
        if (found[0] != 0) {
            _snwprintf_s(problem, problem_count, _TRUNCATE,
                L"segatools.path names \"%s\", which does not exist.", found);
        }
        return false;
    }

    _snwprintf_s(cfg->path, MAX_PATH, _TRUNCATE, L"%s", found);
    cfg->found = true;

    cfg->netenv.enable = read_uint(found, L"netenv", L"enable", 0) != 0;
    cfg->netenv.redirect_broadcast =
        read_uint(found, L"netenv", L"redirectBroadcast", 1) != 0;
    cfg->netenv.addr_suffix = read_uint(found, L"netenv", L"addrSuffix", 11) & 0xFFu;
    cfg->netenv.router_suffix = read_uint(found, L"netenv", L"routerSuffix", 254) & 0xFFu;
    {
        wchar_t mac[32] = {};
        read_text(found, L"netenv", L"macAddr", L"01:02:03:04:05:06", mac, _countof(mac));
        parse_mac(mac, cfg->netenv.mac);
    }

    cfg->keychip.enable = read_uint(found, L"keychip", L"enable", 1) != 0;
    {
        wchar_t text[32] = {};
        read_text(found, L"keychip", L"subnet", L"192.168.100.0", text, _countof(text));
        if (!parse_ipv4(text, &cfg->keychip.subnet)) {
            _snwprintf_s(problem, problem_count, _TRUNCATE,
                L"[keychip] subnet \"%s\" is not a valid IPv4 network address.", text);
            return false;
        }
        WideCharToMultiByte(CP_UTF8, 0, text, -1, cfg->keychip.subnet_text,
            sizeof(cfg->keychip.subnet_text), nullptr, nullptr);
    }
    {
        wchar_t text[32] = {};
        read_text(found, L"netenv", L"broadcast", L"255.255.255.255", text, _countof(text));
        if (!parse_ipv4(text, &cfg->keychip.broadcast)) {
            _snwprintf_s(problem, problem_count, _TRUNCATE,
                L"[netenv] broadcast \"%s\" is not a valid IPv4 address.", text);
            return false;
        }
        WideCharToMultiByte(CP_UTF8, 0, text, -1, cfg->keychip.broadcast_text,
            sizeof(cfg->keychip.broadcast_text), nullptr, nullptr);
    }
    return true;
}

} // namespace segatools
