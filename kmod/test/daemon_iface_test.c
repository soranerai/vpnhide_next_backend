#include <assert.h>

#include "../daemon_iface.h"

int main(void)
{
	assert(!vpnhide_daemon_is_cover_candidate(NULL));
	assert(!vpnhide_daemon_is_cover_candidate(""));
	assert(!vpnhide_daemon_is_cover_candidate("dummy"));
	assert(!vpnhide_daemon_is_cover_candidate("dummy0"));
	assert(!vpnhide_daemon_is_cover_candidate("dummy1"));
	assert(!vpnhide_daemon_is_cover_candidate("dummy_oem"));

	assert(vpnhide_daemon_is_cover_candidate("wlan0"));
	assert(vpnhide_daemon_is_cover_candidate("rmnet_data0"));
	assert(vpnhide_daemon_is_cover_candidate("ccmni0"));
	assert(vpnhide_daemon_is_cover_candidate("eth0"));

	/* Android cellular uplinks may legitimately be point-to-point. */
	assert(!vpnhide_daemon_is_vpn_interface("rmnet0", true, ARPHRD_NONE, false));
	assert(!vpnhide_daemon_is_vpn_interface("rmnet_data0", true, ARPHRD_NONE, false));
	assert(!vpnhide_daemon_is_vpn_interface("ccmni0", true, ARPHRD_NONE, false));
	assert(!vpnhide_daemon_is_vpn_interface("epdg0", true, ARPHRD_NONE, false));
	assert(!vpnhide_daemon_is_vpn_interface("r_net0", true, ARPHRD_NONE, false));
	assert(!vpnhide_daemon_is_vpn_interface("pdp0", true, ARPHRD_NONE, false));

	/* Preserve detection of anonymous/renamed point-to-point VPNs. */
	assert(vpnhide_daemon_is_vpn_interface("mystery0", true, 1, false));
	assert(!vpnhide_daemon_is_vpn_interface("mystery0", false, 1, false));

	/* ARPHRD catches a renamed non-point-to-point TUN/WireGuard interface. */
	assert(vpnhide_daemon_is_vpn_interface("mystery0", false, ARPHRD_NONE, false));
	assert(vpnhide_daemon_is_vpn_interface("ppp42", false, ARPHRD_PPP, false));
	assert(!vpnhide_daemon_is_vpn_interface("eth0", false, 1, false));

	/* Static and configured VPN prefixes override the cellular exception. */
	assert(vpnhide_daemon_is_vpn_interface("rmnet0", true, ARPHRD_NONE, true));

	return 0;
}
