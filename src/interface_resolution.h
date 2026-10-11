#ifndef CHUSAN_NETWORK_HOOK_INTERFACE_RESOLUTION_H
#define CHUSAN_NETWORK_HOOK_INTERFACE_RESOLUTION_H

// Cross-validation between the independent APIs used to pick the interface index for
// IP_UNICAST_IF. Kept as a small pure function so the decision table can be unit tested
// without loading the DLL or racing its initialization thread.
//
// Why this exists: segatools' netenv module virtualizes GetAdaptersAddresses,
// GetAdaptersInfo, GetBestRoute, and GetIfTable, reporting a synthetic "Fake Ethernet"
// adapter with a hardcoded IfIndex of 1. Trusting that index pins traffic to the wrong
// adapter. netenv does not hook GetIpAddrTable, GetBestRoute2, or GetIfEntry, so those
// are consulted instead, and their answers are compared:
//
//   table_index - interface that owns the configured address, from GetIpAddrTable
//   route_index - interface the stack would egress from, from GetBestRoute2
//
// If both sources are missing, nothing can be trusted and pinning is refused rather than
// falling back to a virtualized value. If they disagree, the address-ownership answer
// wins, because interfaceAddress is defined to select the interface that owns the
// address; the disagreement is reported separately by the caller.

enum InterfaceResolution {
    kInterfaceResolvedFromTable,   // GetIpAddrTable answered (route agreed or was silent)
    kInterfaceResolvedFromRoute,   // only GetBestRoute2 answered
    kInterfaceUnresolved,          // no usable source; caller must refuse to pin
};

inline InterfaceResolution decide_interface_index(
        bool table_found,
        unsigned long table_index,
        bool route_found,
        unsigned long route_index,
        unsigned long *out_index) {
    if (table_found) {
        if (out_index != nullptr) *out_index = table_index;
        return kInterfaceResolvedFromTable;
    }
    if (route_found) {
        if (out_index != nullptr) *out_index = route_index;
        return kInterfaceResolvedFromRoute;
    }
    if (out_index != nullptr) *out_index = 0;
    return kInterfaceUnresolved;
}

#endif // CHUSAN_NETWORK_HOOK_INTERFACE_RESOLUTION_H
