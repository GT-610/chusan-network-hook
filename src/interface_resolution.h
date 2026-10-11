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

// The directed broadcast the game computes through netenv's synthetic adapter.
//
// netenv hardcodes OnLinkPrefixLength = 24 (netenv.c, hook_GetAdaptersAddresses), so the
// game broadcasts to subnet | 0xFF no matter what the real interface's mask is. On an
// interface whose real mask is wider than /24 - a /16 link-local address, for example -
// that is NOT the same address as the interface's own subnet broadcast, so broadcast
// matching has to accept both or it silently stops pinning traffic.
//
// The argument and result are in_addr::s_addr, i.e. network byte order. On a little
// endian host the value therefore reads as 0x128BA8C0 for 192.168.139.18, whose last
// octet (0x12) is the most significant byte. Masking the low three bytes and forcing the
// top byte to 0xFF yields 192.168.139.255 as 0xFF8BA8C0.
inline unsigned long netenv_style_broadcast(unsigned long address_s_addr) {
    return (address_s_addr & 0x00FFFFFFul) | 0xFF000000ul;
}

#endif // CHUSAN_NETWORK_HOOK_INTERFACE_RESOLUTION_H
