/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VPNHIDE_POLICY_H
#define VPNHIDE_POLICY_H

#include <sys/types.h>

#include "include/vpnhide.h"
#include "parson.h"

enum vpnhide_list_mode {
	VPNHIDE_LIST_BLACKLIST = 0,
	VPNHIDE_LIST_ALLOWLIST = 1,
};

struct vpnhide_policy_summary {
	enum vpnhide_list_mode mode;
	int discovered_packages;
	int eligible_packages;
	int protected_packages;
	int selected_exceptions;
	int kmod_targets;
	int lsposed_targets;
	int port_targets;
	int ignored_selected_system_packages;
};

/* Resolve the declarative JSON policy into the two UID snapshots consumed by
 * the kernel. In allowlist mode, system packages are never made targets. */
int vpnhide_resolve_targets(const JSON_Object *root, uid_t self_uid,
				    struct vpnhide_ioctl_data *kmod,
				    struct vpnhide_ioctl_data *lsposed,
				    struct vpnhide_policy_summary *summary,
				    char *error, size_t error_len);

/* Resolve port hiding using the same list mode and protected-package rules. */
int vpnhide_resolve_port_rules(const JSON_Object *root, uid_t self_uid,
				       struct vpnhide_port_ioctl_data *result,
				       struct vpnhide_policy_summary *summary,
				       char *error, size_t error_len);

const char *vpnhide_list_mode_name(enum vpnhide_list_mode mode);

#endif
