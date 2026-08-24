#ifndef VPNHIDE_DAEMON_IFACE_H
#define VPNHIDE_DAEMON_IFACE_H

#include <linux/if_arp.h>
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

/*
 * IFF_POINTOPOINT describes the link topology, not whether a netdev is a
 * VPN.  Android cellular drivers commonly expose the physical uplink with
 * this flag, so treating it as an unconditional VPN marker drops the only
 * usable cover interface when Wi-Fi is down.
 *
 * Keep this list aligned with the cellular families preferred by the cover
 * scoring code.  An explicit static/configured VPN-name match still wins;
 * this exception only narrows the anonymous point-to-point heuristic.
 */
static inline bool vpnhide_daemon_is_cellular_uplink(const char *ifname)
{
	return ifname &&
	       (strncmp(ifname, "rmnet", 5) == 0 ||
		strncmp(ifname, "ccmni", 5) == 0 ||
		strncmp(ifname, "epdg", 4) == 0 ||
		strncmp(ifname, "r_net", 5) == 0 ||
		strncmp(ifname, "pdp", 3) == 0);
}

static inline bool
vpnhide_daemon_is_vpn_interface(const char *ifname, bool is_point_to_point,
				 unsigned short arphrd, bool name_matches_vpn)
{
	if (name_matches_vpn)
		return true;

	/* ARPHRD_NONE covers TUN/WireGuard; PPP covers PPP-based VPNs. */
	/* Cellular raw-IP interfaces may report a tunnel-like ARPHRD too. */
	if (!vpnhide_daemon_is_cellular_uplink(ifname) &&
	    (arphrd == ARPHRD_NONE || arphrd == ARPHRD_PPP))
		return true;

	return is_point_to_point &&
	       !vpnhide_daemon_is_cellular_uplink(ifname);
}

#endif /* VPNHIDE_DAEMON_IFACE_H */
