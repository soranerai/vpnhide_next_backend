#ifndef VPNHIDE_DAEMON_IFACE_H
#define VPNHIDE_DAEMON_IFACE_H

#include <stdbool.h>
#include <string.h>

/*
 * A non-VPN netdev is not necessarily a physical uplink.  Android kernels
 * commonly keep dummy0 up as a routing anchor; on some devices it also has
 * an address and accepts a bound connect(), which makes the daemon's active
 * egress probe look successful.
 *
 * Keep this separate from vpnhide_iface_is_vpn(): dummy devices must remain
 * visible as ordinary system interfaces, but must never provide the cover
 * interface or the address used for socket-name spoofing.  Match the prefix
 * so additional dummy instances and vendor-suffixed variants are covered.
 */
static inline bool vpnhide_daemon_is_cover_candidate(const char *ifname)
{
	return ifname && ifname[0] && strncmp(ifname, "dummy", 5) != 0;
}

#endif /* VPNHIDE_DAEMON_IFACE_H */
