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
	assert(!vpnhide_daemon_is_vpn_interface("rmnet0", true, false));
	assert(!vpnhide_daemon_is_vpn_interface("rmnet_data0", true, false));
	assert(!vpnhide_daemon_is_vpn_interface("ccmni0", true, false));
	assert(!vpnhide_daemon_is_vpn_interface("epdg0", true, false));
	assert(!vpnhide_daemon_is_vpn_interface("r_net0", true, false));
	assert(!vpnhide_daemon_is_vpn_interface("pdp0", true, false));

	/* Preserve detection of anonymous/renamed point-to-point VPNs. */
	assert(vpnhide_daemon_is_vpn_interface("mystery0", true, false));
	assert(!vpnhide_daemon_is_vpn_interface("mystery0", false, false));

	/* Static and configured VPN prefixes override the cellular exception. */
	assert(vpnhide_daemon_is_vpn_interface("rmnet0", true, true));

	return 0;
}
