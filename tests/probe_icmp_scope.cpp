// Exercises hook_IcmpSendEcho2 directly, without a real process to inject into.
//
// The behaviour being pinned down is the NUMBER OF HOP item. amdaemon's traceroute
// starts at TTL 1 (FUN_1403ba120 -> state 1, FUN_1403d7a60 -> first three probes TTL 1)
// and FUN_1403f0b00 passes that TTL through as RequestOptions->Ttl. A traceroute only
// reports 1 hop if the TTL=1 probe to its final target is answered, so this probe checks
// that path rather than a synthetic destination of convenience.
//
// Two destinations are used:
//   * 203.0.113.9  - TEST-NET-3, never inside any presented subnet; stands in for the
//                    ALL.Net authentication server, which is what the traceroute in
//                    alwAuthPhaseTraceroute (0x1403c1a00) actually targets;
//   * 172.16.10.254 - inside the presented subnet of the fixture below.
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

// A presented /18 containing 172.16.10.235, matching the fixture the other probes use.
void present_subnet(bool all_destinations) {
    AdapterPresentation &p = adapter_override::state();
    p = {};
    p.present = true;
    p.virtualize_icmp = true;
    p.icmp_all_destinations = all_destinations;
    p.if_index = 10;
    p.address = addr_of("172.16.10.235");
    p.mask = addr_of("255.255.192.0");
    p.presented_mask = addr_of("255.255.192.0");
    p.presented_network = addr_of("172.16.0.0");
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
    printf("hook_IcmpSendEcho2 scope probe\n\n");

    // 1. netenv parity: the traceroute's first probe to a public address is answered.
    //    This is the case that makes NUMBER OF HOP read 1 instead of hanging.
    present_subnet(true);
    {
        const Outcome o = echo_once("203.0.113.9", 1);
        printf("  icmpScope=all,    target=203.0.113.9 ttl=1 -> result=%lu error=%lu "
               "event=%d status=%lu\n", o.result, o.last_error,
               o.event_signalled ? 1 : 0, o.reply_status);
        check(o.result == 0, "returns 0, i.e. the async form's 'pending' result");
        check(o.last_error == ERROR_IO_PENDING, "sets ERROR_IO_PENDING, which amdaemon reads as success");
        check(o.event_signalled, "signals the event the caller waits on");
        check(o.reply_status == IP_SUCCESS, "reports IP_SUCCESS for a TTL=1 probe to the target");
    }

    // 2. A later TTL must behave identically: the traceroute must not be able to tell
    //    the difference, or it would report a hop count other than 1.
    {
        const Outcome o = echo_once("203.0.113.9", 7);
        printf("  icmpScope=all,    target=203.0.113.9 ttl=7 -> status=%lu\n", o.reply_status);
        check(o.reply_status == IP_SUCCESS && o.event_signalled,
            "TTL does not change the answer, so the trace ends on its first probe");
    }

    // 3. Scoped: an address outside the presented subnet is passed through. next_icmp()
    //    is null in this harness, which is exactly what a passthrough looks like.
    present_subnet(false);
    {
        const Outcome o = echo_once("203.0.113.9", 1);
        printf("  icmpScope=subnet, target=203.0.113.9 ttl=1 -> result=%lu event=%d\n",
            o.result, o.event_signalled ? 1 : 0);
        check(!o.event_signalled, "passes the out-of-subnet probe through instead of answering it");
    }

    // 4. Scoped, but inside the subnet: still answered, which keeps the GATEWAY item
    //    working on a router-less segment such as ZeroTier.
    {
        const Outcome o = echo_once("172.16.10.254", 1);
        printf("  icmpScope=subnet, target=172.16.10.254 ttl=1 -> status=%lu event=%d\n",
            o.reply_status, o.event_signalled ? 1 : 0);
        check(o.event_signalled && o.reply_status == IP_SUCCESS,
            "still answers a probe inside the presented subnet");
    }

    // 5. Virtualisation off: nothing is answered under either scope.
    adapter_override::state().virtualize_icmp = false;
    {
        const Outcome o = echo_once("172.16.10.254", 1);
        check(!o.event_signalled, "answers nothing at all when virtualizeIcmp=0");
    }

    printf("\n%s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
