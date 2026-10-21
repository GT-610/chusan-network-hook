// Exercises hook_IcmpSendEcho2 directly, without a real process to inject into.
//
// The behaviour being pinned down is the NUMBER OF HOP item. amdaemon's traceroute
// starts at TTL 1 (FUN_1403ba120 -> state 1, FUN_1403d7a60 -> first three probes TTL 1)
// and FUN_1403f0b00 passes that TTL through as RequestOptions->Ttl. A traceroute only
// reports 1 hop if the TTL=1 probe to its final target is answered, so this probe checks
// that path rather than a synthetic destination of convenience.
//
// 203.0.113.9 is TEST-NET-3 and stands in for the ALL.Net authentication server, which is
// what the traceroute in alwAuthPhaseTraceroute (0x1403c1a00) actually targets. Every
// destination is answered now, so the address only has to be one no hook would treat
// specially.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdio.h>
#include <string.h>

#include "../src/adapter_override.h"

namespace {

int g_failures = 0;

// inet_addr is deprecated and the build runs at /W4; keep the probe warning-clean.
in_addr addr_of(const char *text) {
    in_addr result = {};
    InetPtonA(AF_INET, text, &result);
    return result;
}

void check(bool condition, const char *what) {
    printf("%-78s %s\n", what, condition ? "ok" : "FAILED");
    if (!condition) ++g_failures;
}

void present(void) {
    AdapterPresentation &p = adapter_override::state();
    p = {};
    // These two are all the ICMP item consults: it answers every destination at every
    // TTL, which is exactly what the network test depends on, so there is no address,
    // mask or index to set here.
    p.present = true;
    p.virtualize_icmp = true;
}

struct Outcome {
    ULONG result;
    DWORD last_error;
    bool event_signalled;
    DWORD reply_status;
};

Outcome echo_once(const char *destination, unsigned char ttl) {
    Outcome outcome = {};
    HANDLE event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (event == nullptr) return outcome;

    IP_OPTION_INFORMATION options = {};
    options.Ttl = ttl;

    ICMP_ECHO_REPLY reply = {};
    const IPAddr target = addr_of(destination).S_un.S_addr;

    SetLastError(0xDEADBEEF);
    outcome.result = adapter_override::hook_IcmpSendEcho2(
        reinterpret_cast<HANDLE>(1), event, nullptr, nullptr, target,
        nullptr, 0, &options, &reply, sizeof(reply), 5000);
    outcome.last_error = GetLastError();
    outcome.event_signalled = WaitForSingleObject(event, 0) == WAIT_OBJECT_0;
    outcome.reply_status = reply.Status;
    CloseHandle(event);
    return outcome;
}

} // namespace

int main(void) {
    printf("hook_IcmpSendEcho2 probe\n\n");

    // 1. The traceroute's first probe to a public address is answered. This is the case
    //    that makes NUMBER OF HOP read 1 instead of hanging.
    present();
    {
        const Outcome o = echo_once("203.0.113.9", 1);
        printf("  target=203.0.113.9 ttl=1 -> result=%lu error=%lu event=%d status=%lu\n",
            o.result, o.last_error, o.event_signalled ? 1 : 0, o.reply_status);
        check(o.result == 0, "returns 0, i.e. the async form's 'pending' result");
        check(o.last_error == ERROR_IO_PENDING, "sets ERROR_IO_PENDING, which amdaemon reads as success");
        check(o.event_signalled, "signals the event the caller waits on");
        check(o.reply_status == IP_SUCCESS, "reports IP_SUCCESS for a TTL=1 probe to the target");
    }

    // 2. A later TTL must behave identically: the traceroute must not be able to tell the
    //    difference, or it would report a hop count other than 1.
    {
        const Outcome o = echo_once("203.0.113.9", 7);
        printf("  target=203.0.113.9 ttl=7 -> status=%lu\n", o.reply_status);
        check(o.reply_status == IP_SUCCESS && o.event_signalled,
            "TTL does not change the answer, so the trace ends on its first probe");
    }

    // 3. The gateway item's target is inside the presented subnet; it must be answered
    //    for the same reason, or GATEWAY would report BAD on a router-less segment.
    {
        const Outcome o = echo_once("172.16.10.254", 1);
        printf("  target=172.16.10.254 ttl=1 -> status=%lu event=%d\n",
            o.reply_status, o.event_signalled ? 1 : 0);
        check(o.event_signalled && o.reply_status == IP_SUCCESS,
            "answers the presented gateway too");
    }

    // 4. Virtualisation off: nothing is answered, and the call falls through to the real
    //    API. next_icmp() is null in this harness, which is what a passthrough looks like.
    adapter_override::state().virtualize_icmp = false;
    {
        const Outcome o = echo_once("172.16.10.254", 1);
        check(!o.event_signalled, "answers nothing at all when virtualizeIcmp=0");
    }

    // 5. Not presented at all: no interception, same passthrough.
    adapter_override::state().present = false;
    adapter_override::state().virtualize_icmp = true;
    {
        const Outcome o = echo_once("172.16.10.254", 1);
        check(!o.event_signalled, "does not answer when no adapter is presented");
    }

    printf("\n%s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
