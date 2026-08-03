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

	return 0;
}
