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
	int configured_entries;
	int rejected_core_uids;
	int kmod_targets;
	int lsposed_targets;
	int port_targets;
};

struct vpnhide_uid_vector {
	size_t count;
	size_t capacity;
	uid_t *items;
};

struct vpnhide_port_target {
	uid_t uid;
	unsigned char mode;
	size_t rule_count;
	size_t rule_capacity;
	struct vpnhide_port_rule *rules;
};

struct vpnhide_port_policy {
	size_t count;
	size_t capacity;
	struct vpnhide_port_target *targets;
};

void vpnhide_uid_vector_free(struct vpnhide_uid_vector *vector);
void vpnhide_port_policy_free(struct vpnhide_port_policy *policy);

/* Copy the application's declarative UID policy into kernel snapshot lists. */
int vpnhide_resolve_targets(const JSON_Object *root,
				    struct vpnhide_uid_vector *kmod,
				    struct vpnhide_uid_vector *lsposed,
				    struct vpnhide_policy_summary *summary,
				    char *error, size_t error_len);

/* Compile declarative port rules using the same list mode. */
int vpnhide_resolve_port_rules(const JSON_Object *root,
				       struct vpnhide_port_policy *result,
				       struct vpnhide_policy_summary *summary,
				       char *error, size_t error_len);

const char *vpnhide_list_mode_name(enum vpnhide_list_mode mode);

#endif
