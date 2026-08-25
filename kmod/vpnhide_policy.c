/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE

#include "vpnhide_policy.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char *error, size_t error_len, const char *message)
{
	if (error && error_len > 0)
		snprintf(error, error_len, "%s", message);
}

const char *vpnhide_list_mode_name(enum vpnhide_list_mode mode)
{
	return mode == VPNHIDE_LIST_ALLOWLIST ? "ALLOWLIST" : "BLACKLIST";
}

static enum vpnhide_list_mode read_mode(const JSON_Object *root)
{
	JSON_Object *global = json_object_get_object(root, "globalConfig");
	const char *mode;

	if (!global)
		return VPNHIDE_LIST_BLACKLIST;
	mode = json_object_get_string(global, "listMode");
	if (mode && (!strcmp(mode, "ALLOWLIST") || !strcmp(mode, "allowlist")))
		return VPNHIDE_LIST_ALLOWLIST;
	return VPNHIDE_LIST_BLACKLIST;
}

void vpnhide_uid_vector_free(struct vpnhide_uid_vector *vector)
{
	if (!vector)
		return;
	free(vector->items);
	memset(vector, 0, sizeof(*vector));
}

void vpnhide_port_policy_free(struct vpnhide_port_policy *policy)
{
	size_t i;
	if (!policy)
		return;
	for (i = 0; i < policy->count; i++)
		free(policy->targets[i].rules);
	free(policy->targets);
	memset(policy, 0, sizeof(*policy));
}

static int grow_array(void **items, size_t *capacity, size_t count,
		      size_t element_size)
{
	size_t new_capacity = *capacity ? *capacity : 16;
	void *grown;

	if (count < *capacity)
		return 0;
	while (new_capacity <= count) {
		if (new_capacity > SIZE_MAX / 2)
			return -EOVERFLOW;
		new_capacity *= 2;
	}
	if (new_capacity > SIZE_MAX / element_size)
		return -EOVERFLOW;
	grown = realloc(*items, new_capacity * element_size);
	if (!grown)
		return -ENOMEM;
	*items = grown;
	*capacity = new_capacity;
	return 0;
}

static int add_uid_distinct(struct vpnhide_uid_vector *vector, uid_t uid)
{
	size_t i;
	int ret;

	if (uid == 0)
		return 0;
	for (i = 0; i < vector->count; i++) {
		if (vector->items[i] == uid)
			return 0;
	}
	ret = grow_array((void **)&vector->items, &vector->capacity,
			 vector->count, sizeof(*vector->items));
	if (ret)
		return ret;
	vector->items[vector->count++] = uid;
	return 0;
}

static int add_port_rule(struct vpnhide_port_target *target,
				 JSON_Object *rule, char *error, size_t error_len)
{
	long start = (long)json_object_get_number(rule, "startPort");
	long end = (long)json_object_get_number(rule, "endPort");
	const char *protocol = json_object_get_string(rule, "protocol");
	unsigned char proto = VH_PROTO_BOTH;

	if (!json_object_get_boolean(rule, "enabled"))
		return 0;
	if (start < 0 || end < 0 || start > 65535 || end > 65535 || start > end) {
		set_error(error, error_len, "invalid port range");
		return -EINVAL;
	}
	if (protocol) {
		if (!strcmp(protocol, "TCP"))
			proto = VH_PROTO_TCP;
		else if (!strcmp(protocol, "UDP"))
			proto = VH_PROTO_UDP;
		else if (strcmp(protocol, "BOTH")) {
			set_error(error, error_len, "invalid port protocol");
			return -EINVAL;
		}
	}
	int ret = grow_array((void **)&target->rules, &target->rule_capacity,
			     target->rule_count, sizeof(*target->rules));
	if (ret) {
		set_error(error, error_len, "out of memory while adding port rule");
		return ret;
	}
	target->rules[target->rule_count].start_port = (unsigned short)start;
	target->rules[target->rule_count].end_port = (unsigned short)end;
	target->rules[target->rule_count].protocol = proto;
	target->rule_count++;
	return 1;
}

static int set_full_range_port_rules(struct vpnhide_port_target *target)
{
	int ret = grow_array((void **)&target->rules, &target->rule_capacity,
			     0, sizeof(*target->rules));
	if (ret)
		return ret;
	target->rule_count = 1;
	target->mode = VH_PORT_POLICY_DENY_ALL;
	target->rules[0].start_port = 0;
	target->rules[0].end_port = 65535;
	target->rules[0].protocol = VH_PROTO_BOTH;
	return 0;
}

static int resolve_named_port_rules(const JSON_Array *port_rules,
					    const JSON_Array *mass_rules,
					    const char *package_name, int user_id, uid_t package_uid,
					    int full_range_fallback,
					    struct vpnhide_port_target *target,
					    char *error, size_t error_len)
{
	size_t i, count;
	int ret;

	count = port_rules ? json_array_get_count(port_rules) : 0;
	for (i = 0; i < count; i++) {
		JSON_Object *rule = json_array_get_object(port_rules, i);
		const char *name;
		int user;
		uid_t rule_uid;
		int has_user;
		if (!rule)
			continue;
		name = json_object_get_string(rule, "packageName");
		user = (int)json_object_get_number(rule, "userId");
		rule_uid = (uid_t)json_object_get_number(rule, "uid");
		has_user = json_object_has_value(rule, "userId");
		if ((rule_uid && package_uid && rule_uid == package_uid) ||
		    (name && package_name && !strcmp(name, package_name) &&
		     (!has_user || user == user_id))) {
			ret = add_port_rule(target, rule, error, error_len);
			if (ret < 0)
				return ret;
		}
	}
	count = mass_rules ? json_array_get_count(mass_rules) : 0;
	for (i = 0; i < count; i++) {
		JSON_Object *rule = json_array_get_object(mass_rules, i);
		if (!rule)
			continue;
		ret = add_port_rule(target, rule, error, error_len);
		if (ret < 0)
			return ret;
	}
	/* Preserve denylist behavior: a selected app receives full-range hiding
	 * only when neither a matching local rule nor a mass rule was resolved. */
	if (full_range_fallback && target->rule_count == 0) {
		return set_full_range_port_rules(target);
	}
	return 0;
}

static int port_rule_allows(const struct vpnhide_port_target *allowed,
				    int port, unsigned char protocol)
{
	for (size_t i = 0; i < allowed->rule_count; i++) {
		const struct vpnhide_port_rule *rule = &allowed->rules[i];
		if (port >= rule->start_port && port <= rule->end_port &&
		    (rule->protocol == VH_PROTO_BOTH ||
		     rule->protocol == protocol))
			return 1;
	}
	return 0;
}

/* In allowlist mode an enabled P app is allowed only the explicitly listed
 * ports. The kernel policy is block-only, so compile the allowed ranges into
 * their complement before publishing the snapshot. */
static int resolve_allowlist_exception_rules(
		const JSON_Array *port_rules, const JSON_Array *mass_rules,
		const char *package_name, int user_id, uid_t package_uid,
		struct vpnhide_port_target *target,
		char *error, size_t error_len)
{
	struct vpnhide_port_target allowed;
	int range_start = -1;
	int range_protocol = -1;
	int ret;

	memset(&allowed, 0, sizeof(allowed));
	ret = resolve_named_port_rules(port_rules, mass_rules, package_name,
					       user_id, package_uid, 0, &allowed, error, error_len);
	if (ret) {
		free(allowed.rules);
		return ret;
	}
	memset(target, 0, sizeof(*target));
	if (allowed.rule_count == 0) {
		target->mode = VH_PORT_POLICY_UNRESTRICTED;
		free(allowed.rules);
		return 0;
	}
	target->mode = VH_PORT_POLICY_RULES;

	for (int port = 0; port <= 65536; port++) {
		int protocol = -1;
		if (port < 65536) {
			int tcp_blocked = !port_rule_allows(&allowed, port, VH_PROTO_TCP);
			int udp_blocked = !port_rule_allows(&allowed, port, VH_PROTO_UDP);
			if (tcp_blocked && udp_blocked)
				protocol = VH_PROTO_BOTH;
			else if (tcp_blocked)
				protocol = VH_PROTO_TCP;
			else if (udp_blocked)
				protocol = VH_PROTO_UDP;
		}

		if (protocol != range_protocol) {
			if (range_protocol >= 0) {
				ret = grow_array((void **)&target->rules,
						 &target->rule_capacity, target->rule_count,
						 sizeof(*target->rules));
				if (ret) {
					free(allowed.rules);
					set_error(error, error_len,
						  "out of memory while complementing port rules");
					return ret;
				}
				target->rules[target->rule_count].start_port =
					(unsigned short)range_start;
				target->rules[target->rule_count].end_port =
					(unsigned short)(port - 1);
				target->rules[target->rule_count].protocol =
					(unsigned char)range_protocol;
				target->rule_count++;
			}
			range_start = port;
			range_protocol = protocol;
		}
	}
	free(allowed.rules);
	return 0;
}

int vpnhide_resolve_targets(const JSON_Object *root,
				    struct vpnhide_uid_vector *kmod,
				    struct vpnhide_uid_vector *lsposed,
				    struct vpnhide_policy_summary *summary,
				    char *error, size_t error_len)
{
	const JSON_Array *apps;
	size_t i, count;
	if (!root || !kmod || !lsposed || !summary) {
		set_error(error, error_len, "invalid policy arguments");
		return -EINVAL;
	}
	vpnhide_uid_vector_free(kmod);
	vpnhide_uid_vector_free(lsposed);
	memset(summary, 0, sizeof(*summary));
	summary->mode = read_mode(root);
	apps = json_object_get_array(root, "apps");
	count = apps ? json_array_get_count(apps) : 0;
	for (i = 0; i < count; i++) {
		JSON_Object *app = json_array_get_object(apps, i);
		uid_t uid;
		if (!app)
			continue;
		uid = (uid_t)json_object_get_number(app, "uid");
		if (!uid || (uid % 100000) < 10000) {
			if (uid)
				summary->rejected_core_uids++;
			continue;
		}
		if (json_object_get_boolean(app, "kmod") == 1 &&
		    add_uid_distinct(kmod, uid)) {
			set_error(error, error_len, "cannot grow configured kernel UID set");
			return -ENOMEM;
		}
		if (json_object_get_boolean(app, "lsposed") == 1 &&
		    add_uid_distinct(lsposed, uid)) {
			set_error(error, error_len, "cannot grow configured framework UID set");
			return -ENOMEM;
		}
	}
	summary->configured_entries = (int)count;
	summary->kmod_targets = kmod->count;
	summary->lsposed_targets = lsposed->count;
	return 0;
}

int vpnhide_resolve_port_rules(const JSON_Object *root,
				       struct vpnhide_port_policy *result,
				       struct vpnhide_policy_summary *summary,
				       char *error, size_t error_len)
{
	const JSON_Array *apps;
	const JSON_Array *port_rules;
	const JSON_Array *mass_rules;
	int ret;
	size_t i, count;
	if (!root || !result || !summary) {
		set_error(error, error_len, "invalid port policy arguments");
		return -EINVAL;
	}
	vpnhide_port_policy_free(result);
	apps = json_object_get_array(root, "apps");
	port_rules = json_object_get_array(root, "portRules");
	mass_rules = json_object_get_array(root, "massPortRules");
	count = apps ? json_array_get_count(apps) : 0;
	for (i = 0; i < count; i++) {
		JSON_Object *app = json_array_get_object(apps, i);
		struct vpnhide_port_target *target;
		uid_t uid;
		if (!app || json_object_get_boolean(app, "portHiding") != 1)
			continue;
		uid = (uid_t)json_object_get_number(app, "uid");
		if (!uid || (uid % 100000) < 10000)
			continue;
		for (size_t existing = 0; existing < result->count; existing++)
			if (result->targets[existing].uid == uid)
				goto next_configured_app;
		ret = grow_array((void **)&result->targets, &result->capacity,
				 result->count, sizeof(*result->targets));
		if (ret) {
			set_error(error, error_len, "cannot grow configured port set");
			return ret;
		}
		target = &result->targets[result->count];
		memset(target, 0, sizeof(*target));
		if (summary->mode == VPNHIDE_LIST_ALLOWLIST) {
			ret = resolve_allowlist_exception_rules(
				port_rules, mass_rules,
				json_object_get_string(app, "packageName"),
				(int)json_object_get_number(app, "userId"), uid,
				target, error, error_len);
		} else {
			ret = resolve_named_port_rules(
				port_rules, mass_rules,
				json_object_get_string(app, "packageName"),
				(int)json_object_get_number(app, "userId"), uid, 1,
				target, error, error_len);
			target->mode = VH_PORT_POLICY_RULES;
		}
		if (ret)
			return ret;
		target->uid = uid;
		result->count++;
	next_configured_app:
		;
	}
	summary->port_targets = result->count;
	return 0;
}
