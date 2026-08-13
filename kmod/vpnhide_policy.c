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

#ifndef VPNHIDE_PM_COMMAND
#define VPNHIDE_PM_COMMAND "pm list packages -f -U --user all 2>/dev/null"
#endif
#ifndef VPNHIDE_PM_SYSTEM_COMMAND
#define VPNHIDE_PM_SYSTEM_COMMAND "pm list packages -s -U --user all 2>/dev/null"
#endif
#define VPNHIDE_PACKAGE_NAME_MAX 256
#define VPNHIDE_APK_PATH_MAX 512
#define VPNHIDE_UIDS_PER_PM_LINE 64

struct discovered_package {
	char name[VPNHIDE_PACKAGE_NAME_MAX];
	char apk_path[VPNHIDE_APK_PATH_MAX];
	uid_t uid;
	int user_id;
	unsigned int app_id;
	int system_package;
};

struct uid_seen_set {
	uid_t *slots;
	size_t capacity;
};

static int uid_seen_set_init(struct uid_seen_set *set, size_t expected)
{
	size_t capacity = 16;

	if (expected > SIZE_MAX / 2)
		return -EOVERFLOW;
	while (capacity < expected * 2) {
		if (capacity > SIZE_MAX / 2)
			return -EOVERFLOW;
		capacity *= 2;
	}
	set->slots = calloc(capacity, sizeof(*set->slots));
	if (!set->slots)
		return -ENOMEM;
	set->capacity = capacity;
	return 0;
}

static void uid_seen_set_free(struct uid_seen_set *set)
{
	free(set->slots);
	memset(set, 0, sizeof(*set));
}

/* Returns 1 when uid was already present, 0 when inserted. */
static int uid_seen_set_add(struct uid_seen_set *set, uid_t uid)
{
	size_t slot;

	if (!set->slots || !set->capacity)
		return -EINVAL;
	slot = ((uint32_t)uid * 2654435761U) & (set->capacity - 1);
	for (size_t probe = 0; probe < set->capacity; probe++) {
		uid_t *entry = &set->slots[(slot + probe) & (set->capacity - 1)];
		if (!*entry) {
			*entry = uid;
			return 0;
		}
		if (*entry == uid)
			return 1;
	}
	return -ENOSPC;
}

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

static int port_layer_enabled(const JSON_Array *apps)
{
	size_t i, count = apps ? json_array_get_count(apps) : 0;
	for (i = 0; i < count; i++) {
		JSON_Object *app = json_array_get_object(apps, i);
		if (app && json_object_get_boolean(app, "portHiding") == 1)
			return 1;
	}
	return 0;
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

static int package_is_system(const char *path)
{
	/* Package Manager's APK path is the only system classification available
	 * to this native backend. Treat every location outside /data/app as
	 * protected. This is deliberately conservative for shared/system UIDs. */
	return strncmp(path, "/data/app/", 10) != 0;
}

/* `pm list packages -U --user all` reports all installed-user UIDs for a
 * package on one line, e.g. `uid:10001,110001`. Keep one discovered record
 * per UID: the kernel policy is keyed by the full UID, not by appId. */
static int parse_pm_line(char *line, struct discovered_package *out,
			 size_t out_capacity)
{
	char *pkg_start, *equals, *uid_marker, *end;
	int count = 0;

	pkg_start = strstr(line, "package:");
	if (!pkg_start)
		return 0;
	pkg_start += strlen("package:");
	uid_marker = strstr(pkg_start, " uid:");
	if (!uid_marker)
		return 0;
	*uid_marker = '\0';
	uid_marker += strlen(" uid:");
	/* Modern /data/app paths contain base64 padding ('='). The package
	 * separator is therefore the last '=' before the uid field, not the
	 * first '=' in the PM output line. */
	equals = strrchr(pkg_start, '=');
	if (!equals)
		return 0;
	*equals = '\0';

	if (strlen(equals + 1) >= sizeof(out->name) ||
	    strlen(pkg_start) >= sizeof(out->apk_path))
		return 0;

	while (*uid_marker) {
		unsigned long uid;

		errno = 0;
		uid = strtoul(uid_marker, &end, 10);
		if (end == uid_marker || errno == ERANGE || uid == 0 ||
		    uid > UINT_MAX)
			return count;
		if ((size_t)count >= out_capacity)
			return -E2BIG;

		memset(&out[count], 0, sizeof(out[count]));
		strcpy(out[count].apk_path, pkg_start);
		strcpy(out[count].name, equals + 1);
		out[count].uid = (uid_t)uid;
		out[count].user_id = (int)(uid / 100000);
		out[count].app_id = (unsigned int)(uid % 100000);
		out[count].system_package = package_is_system(out[count].apk_path) ||
			out[count].app_id < 10000;
		count++;

		if (*end != ',')
			break;
		uid_marker = end + 1;
	}

	return count;
}

static void mark_system_packages(struct discovered_package *packages, int count)
{
	char line[1024];
	FILE *pipe = popen(VPNHIDE_PM_SYSTEM_COMMAND, "r");

	if (!pipe)
		return;
	while (fgets(line, sizeof(line), pipe)) {
		char *name = strstr(line, "package:");
		char *uid_marker = strstr(line, " uid:");
		char *end;
		long uid;
		if (!name || !uid_marker)
			continue;
		name += strlen("package:");
		*uid_marker = '\0';
		uid_marker += strlen(" uid:");
		uid = strtol(uid_marker, &end, 10);
		if (end == uid_marker || uid <= 0 || uid > UINT_MAX)
			continue;
		for (int i = 0; i < count; i++) {
			if ((uid_t)uid == packages[i].uid ||
			    !strcmp(name, packages[i].name))
				packages[i].system_package = 1;
		}
	}
	pclose(pipe);
}

static int discover_packages(struct discovered_package **out, int *count,
				     char *error, size_t error_len)
{
	struct discovered_package *packages;
	char line[1024];
	FILE *pipe;
	int capacity = 128;

	packages = calloc((size_t)capacity, sizeof(*packages));
	if (!packages) {
		set_error(error, error_len, "out of memory while discovering packages");
		return -ENOMEM;
	}

	{
		const char *command = getenv("VPNHIDE_PM_COMMAND");
		pipe = popen(command && command[0] ? command : VPNHIDE_PM_COMMAND, "r");
	}
	if (!pipe) {
		free(packages);
		set_error(error, error_len, "cannot execute Package Manager");
		return -EIO;
	}

	while (fgets(line, sizeof(line), pipe)) {
		struct discovered_package parsed[VPNHIDE_UIDS_PER_PM_LINE];
		struct discovered_package *grown;
		int parsed_count;

		parsed_count = parse_pm_line(line, parsed,
					    VPNHIDE_UIDS_PER_PM_LINE);
		if (parsed_count < 0) {
			pclose(pipe);
			free(packages);
			set_error(error, error_len,
				  "too many user UIDs in Package Manager output");
			return parsed_count;
		}
		if (parsed_count == 0)
			continue;
		if (*count > capacity - parsed_count) {
			int new_capacity = capacity;
			while (new_capacity < *count + parsed_count)
				new_capacity *= 2;
			grown = realloc(packages, (size_t)new_capacity * sizeof(*packages));
			if (!grown) {
				pclose(pipe);
				free(packages);
				set_error(error, error_len, "out of memory while discovering packages");
				return -ENOMEM;
			}
			packages = grown;
			capacity = new_capacity;
		}
		memcpy(&packages[*count], parsed,
		       (size_t)parsed_count * sizeof(parsed[0]));
		*count += parsed_count;
	}

	if (pclose(pipe) == -1 || *count == 0) {
		free(packages);
		set_error(error, error_len, "Package Manager returned no packages");
		return -EIO;
	}
	/* The APK path alone cannot identify updated system packages or shared
	 * system UIDs. Ask Package Manager for the authoritative system set and
	 * protect the whole UID group when any member is system. */
	mark_system_packages(packages, *count);
	*out = packages;
	return 0;
}

static int selected_for_layer(const JSON_Array *apps, const char *package,
				      int user_id, uid_t uid, const char *field)
{
	size_t i, count;

	if (!apps)
		return 0;
	count = json_array_get_count(apps);
	for (i = 0; i < count; i++) {
		JSON_Object *app = json_array_get_object(apps, i);
		const char *name;
		int configured_user;
		uid_t configured_uid;

		if (!app)
			continue;
		name = json_object_get_string(app, "packageName");
		configured_user = (int)json_object_get_number(app, "userId");
		configured_uid = (uid_t)json_object_get_number(app, "uid");
		if ((name && !strcmp(name, package) && configured_user == user_id) ||
		    (configured_uid != 0 && configured_uid == uid))
			return json_object_get_boolean(app, field) == 1;
	}
	return 0;
}

static int system_policy_is_explicit(const JSON_Array *apps, const char *package,
				     int user_id, uid_t uid)
{
	size_t i, count;

	if (!apps)
		return 0;
	count = json_array_get_count(apps);
	for (i = 0; i < count; i++) {
		JSON_Object *app = json_array_get_object(apps, i);
		const char *name;
		int configured_user;
		uid_t configured_uid;

		if (!app)
			continue;
		name = json_object_get_string(app, "packageName");
		configured_user = (int)json_object_get_number(app, "userId");
		configured_uid = (uid_t)json_object_get_number(app, "uid");
		if (name && !strcmp(name, package) && configured_user == user_id &&
		    configured_uid == uid)
			return json_object_get_boolean(app, "systemPolicyExplicit") == 1;
	}
	return 0;
}

static int selected_for_explicit_system_layer(
		const JSON_Array *apps, const char *package, int user_id, uid_t uid,
		const char *field)
{
	size_t i, count;

	if (!apps)
		return 0;
	count = json_array_get_count(apps);
	for (i = 0; i < count; i++) {
		JSON_Object *app = json_array_get_object(apps, i);
		const char *name;
		int configured_user;
		uid_t configured_uid;

		if (!app)
			continue;
		name = json_object_get_string(app, "packageName");
		configured_user = (int)json_object_get_number(app, "userId");
		configured_uid = (uid_t)json_object_get_number(app, "uid");
		if (name && !strcmp(name, package) && configured_user == user_id &&
		    configured_uid == uid)
			return json_object_get_boolean(app, field) == 1;
	}
	return 0;
}

static int configured_package_is_verified_system(
		const JSON_Object *app, const struct discovered_package *packages,
		int package_count)
{
	uid_t uid = (uid_t)json_object_get_number(app, "uid");
	const char *name = json_object_get_string(app, "packageName");
	int user_id = (int)json_object_get_number(app, "userId");

	if (!uid || (uid % 100000) < 10000)
		return 0;
	for (int i = 0; i < package_count; i++) {
		const struct discovered_package *pkg = &packages[i];
		if (name && !strcmp(pkg->name, name) && pkg->user_id == user_id &&
		    pkg->uid == uid)
			return pkg->system_package;
	}
	return 0;
}

static int configured_package_is_protected(const JSON_Object *app,
					   const struct discovered_package *packages,
					   int package_count)
{
	uid_t uid = (uid_t)json_object_get_number(app, "uid");
	const char *name = json_object_get_string(app, "packageName");
	int user_id = (int)json_object_get_number(app, "userId");
	int found = 0;

	if (uid && (uid % 100000) < 10000)
		return 1;
	for (int i = 0; i < package_count; i++) {
		const struct discovered_package *pkg = &packages[i];
		if ((uid && pkg->uid == uid) ||
		    (name && !strcmp(pkg->name, name) && pkg->user_id == user_id)) {
			found = 1;
			if (pkg->system_package)
				return 1;
		}
	}
	/* A stale package entry must not be turned into a hiding target. */
	return !found;
}

static int resolve_layer(const JSON_Array *apps,
					 const struct discovered_package *packages, int package_count,
					 const char *field, uid_t self_uid,
					 enum vpnhide_list_mode mode, struct vpnhide_uid_vector *result,
					 struct uid_seen_set *seen,
					 struct vpnhide_policy_summary *summary, char *error,
				 size_t error_len)
{
	int i;

	for (i = 0; i < package_count; i++) {
		const struct discovered_package *pkg = &packages[i];
		int explicit_system_policy = system_policy_is_explicit(
			apps, pkg->name, pkg->user_id, pkg->uid);
		int selected = pkg->system_package && explicit_system_policy ?
			selected_for_explicit_system_layer(
				apps, pkg->name, pkg->user_id, pkg->uid, field) :
			selected_for_layer(apps, pkg->name, pkg->user_id,
					   pkg->uid, field);

		if ((pkg->system_package && !explicit_system_policy) ||
		    pkg->app_id < 10000 ||
		    (pkg->uid == self_uid && mode == VPNHIDE_LIST_BLACKLIST)) {
			if (selected && pkg->system_package)
				summary->ignored_selected_system_packages++;
			if (pkg->system_package || pkg->uid < 10000)
				summary->protected_packages++;
			continue;
		}

		if (mode == VPNHIDE_LIST_BLACKLIST) {
			if (!selected)
				continue;
		} else if (selected) {
			summary->selected_exceptions++;
			continue;
		}

		{
			int seen_result = uid_seen_set_add(seen, pkg->uid);
			if (seen_result < 0 || seen_result == 1) {
				if (seen_result < 0)
					set_error(error, error_len, "cannot grow effective target set");
				if (seen_result < 0)
					return seen_result;
				continue;
			}
		}
		if (add_uid_distinct(result, pkg->uid)) {
			set_error(error, error_len, "cannot grow effective target set");
			return -ENOMEM;
		}
	}
	return 0;
}

int vpnhide_resolve_targets(const JSON_Object *root, uid_t self_uid,
				    struct vpnhide_uid_vector *kmod,
				    struct vpnhide_uid_vector *lsposed,
				    struct vpnhide_policy_summary *summary,
				    char *error, size_t error_len)
{
	const JSON_Array *apps;
	struct discovered_package *packages = NULL;
	int package_count = 0;
	int ret;

	if (!root || !kmod || !lsposed || !summary) {
		set_error(error, error_len, "invalid policy arguments");
		return -EINVAL;
	}
	vpnhide_uid_vector_free(kmod);
	vpnhide_uid_vector_free(lsposed);
	memset(summary, 0, sizeof(*summary));
	summary->mode = read_mode(root);
	apps = json_object_get_array(root, "apps");

	if (summary->mode == VPNHIDE_LIST_BLACKLIST) {
		/* Blacklist entries also require PM classification. Without it, a
		 * stale UID could now refer to a system/shared UID. */
		JSON_Array *array = (JSON_Array *)apps;
		ret = discover_packages(&packages, &package_count, error, error_len);
		if (ret)
			return ret;
		size_t i, count = array ? json_array_get_count(array) : 0;
		for (i = 0; i < count; i++) {
			JSON_Object *app = json_array_get_object(array, i);
			uid_t uid;
			if (!app)
				continue;
			uid = (uid_t)json_object_get_number(app, "uid");
			if (!uid || uid == 0)
				continue;
			if (configured_package_is_protected(app, packages, package_count) &&
			    !(json_object_get_boolean(app, "systemPolicyExplicit") == 1 &&
			      configured_package_is_verified_system(app, packages,
							package_count))) {
				if ((uid % 100000) < 10000)
					summary->protected_packages++;
				else
					summary->ignored_selected_system_packages++;
				continue;
			}
			if (json_object_get_boolean(app, "kmod") == 1 &&
			    add_uid_distinct(kmod, uid)) {
				set_error(error, error_len, "cannot grow blacklist target set");
				free(packages);
				return -ENOMEM;
			}
			if (json_object_get_boolean(app, "lsposed") == 1 &&
			    add_uid_distinct(lsposed, uid)) {
				set_error(error, error_len, "cannot grow blacklist target set");
				free(packages);
				return -ENOMEM;
			}
		}
		free(packages);
		if (self_uid) {
			if (add_uid_distinct(kmod, self_uid) ||
			    add_uid_distinct(lsposed, self_uid)) {
				set_error(error, error_len, "cannot grow blacklist target set");
				return -ENOMEM;
			}
		}
		summary->kmod_targets = kmod->count;
		summary->lsposed_targets = lsposed->count;
		return 0;
	}

	ret = discover_packages(&packages, &package_count, error, error_len);
	if (ret)
		return ret;
	summary->discovered_packages = package_count;
	struct uid_seen_set kmod_seen = {0};
	struct uid_seen_set lsposed_seen = {0};
	ret = uid_seen_set_init(&kmod_seen, (size_t)package_count);
	if (!ret)
		ret = uid_seen_set_init(&lsposed_seen, (size_t)package_count);
	if (ret) {
		uid_seen_set_free(&kmod_seen);
		uid_seen_set_free(&lsposed_seen);
		free(packages);
		set_error(error, error_len, "out of memory while indexing target UIDs");
		return ret;
	}
	ret = resolve_layer(apps, packages, package_count, "kmod", self_uid,
				    summary->mode, kmod, &kmod_seen, summary, error, error_len);
	if (!ret)
		ret = resolve_layer(apps, packages, package_count, "lsposed", self_uid,
				    summary->mode, lsposed, &lsposed_seen, summary, error, error_len);
	uid_seen_set_free(&kmod_seen);
	uid_seen_set_free(&lsposed_seen);
	free(packages);
	if (ret)
		return ret;
	summary->eligible_packages = kmod->count > lsposed->count ?
		kmod->count : lsposed->count;
	summary->kmod_targets = kmod->count;
	summary->lsposed_targets = lsposed->count;
	return 0;
}

int vpnhide_resolve_port_rules(const JSON_Object *root, uid_t self_uid,
				       struct vpnhide_port_policy *result,
				       struct vpnhide_policy_summary *summary,
				       char *error, size_t error_len)
{
	const JSON_Array *apps;
	const JSON_Array *port_rules;
	const JSON_Array *mass_rules;
	struct discovered_package *packages = NULL;
	int package_count = 0;
	int ret;
	int i;

	if (!root || !result || !summary) {
		set_error(error, error_len, "invalid port policy arguments");
		return -EINVAL;
	}
	vpnhide_port_policy_free(result);
	apps = json_object_get_array(root, "apps");
	port_rules = json_object_get_array(root, "portRules");
	mass_rules = json_object_get_array(root, "massPortRules");
	/* Blacklist is opt-in. In allowlist every eligible app is a target unless
	 * explicitly selected as an exception, even when apps[] has no such entry. */
	if (summary->mode == VPNHIDE_LIST_BLACKLIST && !port_layer_enabled(apps))
		return 0;

	if (summary->mode == VPNHIDE_LIST_BLACKLIST) {
		size_t n = apps ? json_array_get_count(apps) : 0;
		size_t j;
		ret = discover_packages(&packages, &package_count, error, error_len);
		if (ret)
			return ret;
		for (j = 0; j < n; j++) {
			JSON_Object *app = json_array_get_object(apps, j);
			struct vpnhide_port_target *target;
			uid_t uid;
			if (!app || json_object_get_boolean(app, "portHiding") != 1)
				continue;
			uid = (uid_t)json_object_get_number(app, "uid");
			if (!uid || uid == self_uid || uid < 10000)
				continue;
			if (configured_package_is_protected(app, packages, package_count) &&
			    !(json_object_get_boolean(app, "systemPolicyExplicit") == 1 &&
			      configured_package_is_verified_system(app, packages,
							package_count)))
				continue;
			for (size_t existing = 0; existing < result->count; existing++) {
				if (result->targets[existing].uid == uid)
					goto next_blacklist_package;
			}
			ret = grow_array((void **)&result->targets, &result->capacity,
					 result->count, sizeof(*result->targets));
			if (ret) {
				free(packages);
				set_error(error, error_len, "cannot grow port target set");
				return ret;
			}
			target = &result->targets[result->count];
			memset(target, 0, sizeof(*target));
			target->uid = uid;
			/* Blacklist entries may have stale package metadata, so use the
			 * configured package key only when it is available. */
			ret = resolve_named_port_rules(
				port_rules, mass_rules,
				json_object_get_string(app, "packageName"),
				(int)json_object_get_number(app, "userId"),
				(uid_t)json_object_get_number(app, "uid"),
				1,
				target, error, error_len);
			if (ret)
				return ret;
			target->mode = VH_PORT_POLICY_RULES;
			result->count++;
	next_blacklist_package:
			;
		}
		free(packages);
		summary->port_targets = result->count;
		return 0;
	}

	ret = discover_packages(&packages, &package_count, error, error_len);
	if (ret)
		return ret;
	for (i = 0; i < package_count; i++) {
		struct discovered_package *pkg = &packages[i];
		int selected;
		int explicit_system_policy = system_policy_is_explicit(
			apps, pkg->name, pkg->user_id, pkg->uid);
		if ((pkg->system_package && !explicit_system_policy) ||
		    pkg->app_id < 10000 ||
		    (pkg->uid == self_uid && summary->mode == VPNHIDE_LIST_BLACKLIST))
			continue;
		selected = pkg->system_package && explicit_system_policy ?
			selected_for_explicit_system_layer(
				apps, pkg->name, pkg->user_id, pkg->uid,
				"portHiding") :
			selected_for_layer(apps, pkg->name, pkg->user_id,
					   pkg->uid, "portHiding");
		/* Several packages may share one UID. Port policy is keyed by UID,
		 * so resolve that UID only once rather than emitting duplicate rules. */
		for (size_t existing = 0; existing < result->count; existing++) {
			if (result->targets[existing].uid == pkg->uid)
				goto next_package;
		}
		if (selected) {
			ret = grow_array((void **)&result->targets, &result->capacity,
					 result->count, sizeof(*result->targets));
			if (ret) {
				free(packages);
				set_error(error, error_len, "cannot grow port target set");
				return ret;
			}
			ret = resolve_allowlist_exception_rules(
				port_rules, mass_rules, pkg->name, pkg->user_id, pkg->uid,
				&result->targets[result->count], error, error_len);
			if (ret) {
				free(packages);
				return ret;
			}
			result->targets[result->count].uid = pkg->uid;
			result->count++;
			goto next_package;
		}
		ret = grow_array((void **)&result->targets, &result->capacity,
				 result->count, sizeof(*result->targets));
		if (ret) {
			free(packages);
			set_error(error, error_len, "cannot grow port target set");
			return ret;
		}
		/* In ALLOWLIST, an app outside the selected exception set is denied
		 * every port. Do not resolve global rules here: they describe the
		 * selected app's visible set and must never become an allowlist for
		 * unselected apps. */
		memset(&result->targets[result->count], 0,
		       sizeof(result->targets[result->count]));
		result->targets[result->count].uid = pkg->uid;
		/* Keep the full range as a compatibility fallback for an older
		 * backend that does not know the explicit DENY_ALL mode yet. */
		ret = set_full_range_port_rules(&result->targets[result->count]);
		if (ret) {
			free(packages);
			set_error(error, error_len, "cannot allocate deny-all port rule");
			return ret;
		}
		result->count++;
	next_package:
		;
	}
	free(packages);
	summary->port_targets = result->count;
	return 0;
}
