/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE

#include "vpnhide_policy.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
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

struct discovered_package {
	char name[VPNHIDE_PACKAGE_NAME_MAX];
	char apk_path[VPNHIDE_APK_PATH_MAX];
	uid_t uid;
	int user_id;
	unsigned int app_id;
	int system_package;
};

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

static int add_uid_distinct(uid_t *uids, int *count, uid_t uid)
{
	int i;

	if (uid == 0)
		return 0;
	for (i = 0; i < *count; i++) {
		if (uids[i] == uid)
			return 0;
	}
	if (*count >= MAX_TARGET_UIDS)
		return -E2BIG;
	uids[(*count)++] = uid;
	return 0;
}

static int add_port_rule(struct vpnhide_uid_port_rules *target,
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
	if (target->rule_count >= MAX_PORT_RULES_PER_UID) {
		set_error(error, error_len, "effective port rules exceed MAX_PORT_RULES_PER_UID");
		return -E2BIG;
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

static int resolve_package_port_rules(const JSON_Array *port_rules,
					      const JSON_Array *mass_rules,
					      const struct discovered_package *pkg,
					      struct vpnhide_uid_port_rules *target,
					      char *error, size_t error_len)
{
	size_t i, count;
	int ret;

	memset(target, 0, sizeof(*target));
	target->uid = pkg->uid;
	count = port_rules ? json_array_get_count(port_rules) : 0;
	for (i = 0; i < count; i++) {
		JSON_Object *rule = json_array_get_object(port_rules, i);
		const char *name;
		int user;
		if (!rule)
			continue;
		name = json_object_get_string(rule, "packageName");
		user = (int)json_object_get_number(rule, "userId");
		if (name && !strcmp(name, pkg->name) && user == pkg->user_id) {
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
	if (target->rule_count == 0) {
		target->rules[0].start_port = 0;
		target->rules[0].end_port = 65535;
		target->rules[0].protocol = VH_PROTO_BOTH;
		target->rule_count = 1;
	}
	return 0;
}

static int package_is_system(const char *path)
{
	/* Package Manager's APK path is the only system classification available
	 * to this native backend. Treat every location outside /data/app as
	 * protected. This is deliberately conservative for shared/system UIDs. */
	return strncmp(path, "/data/app/", 10) != 0;
}

static int parse_pm_line(char *line, struct discovered_package *out)
{
	char *pkg_start, *equals, *uid_marker, *end;
	long uid;

	pkg_start = strstr(line, "package:");
	if (!pkg_start)
		return 0;
	pkg_start += strlen("package:");
	equals = strchr(pkg_start, '=');
	if (!equals)
		return 0;
	*equals = '\0';
	uid_marker = strstr(equals + 1, " uid:");
	if (!uid_marker)
		return 0;
	*uid_marker = '\0';
	uid_marker += strlen(" uid:");

	uid = strtol(uid_marker, &end, 10);
	if (end == uid_marker || uid <= 0 || uid > UINT_MAX)
		return 0;

	if (strlen(equals + 1) >= sizeof(out->name) ||
	    strlen(pkg_start) >= sizeof(out->apk_path))
		return 0;
	strcpy(out->apk_path, pkg_start);
	strcpy(out->name, equals + 1);
	out->uid = (uid_t)uid;
	out->user_id = (int)(uid / 100000);
	out->app_id = (unsigned int)(uid % 100000);
	out->system_package = package_is_system(out->apk_path) || out->app_id < 10000;
	return 1;
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
		struct discovered_package parsed;
		struct discovered_package *grown;

		if (!parse_pm_line(line, &parsed))
			continue;
		if (*count == capacity) {
			capacity *= 2;
			grown = realloc(packages, (size_t)capacity * sizeof(*packages));
			if (!grown) {
				pclose(pipe);
				free(packages);
				set_error(error, error_len, "out of memory while discovering packages");
				return -ENOMEM;
			}
			packages = grown;
		}
		packages[(*count)++] = parsed;
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
				 enum vpnhide_list_mode mode, struct vpnhide_ioctl_data *result,
				 struct vpnhide_policy_summary *summary, char *error,
				 size_t error_len)
{
	int i;

	memset(result, 0, sizeof(*result));
	for (i = 0; i < package_count; i++) {
		const struct discovered_package *pkg = &packages[i];
		int selected = selected_for_layer(apps, pkg->name, pkg->user_id,
						  pkg->uid, field);

		if (pkg->system_package || pkg->uid == self_uid || pkg->uid < 10000) {
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

		if (add_uid_distinct(result->uids, &result->count, pkg->uid)) {
			set_error(error, error_len, "effective target set exceeds MAX_TARGET_UIDS");
			return -E2BIG;
		}
	}
	return 0;
}

int vpnhide_resolve_targets(const JSON_Object *root, uid_t self_uid,
				    struct vpnhide_ioctl_data *kmod,
				    struct vpnhide_ioctl_data *lsposed,
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
	memset(kmod, 0, sizeof(*kmod));
	memset(lsposed, 0, sizeof(*lsposed));
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
			if (configured_package_is_protected(app, packages, package_count)) {
				if ((uid % 100000) < 10000)
					summary->protected_packages++;
				else
					summary->ignored_selected_system_packages++;
				continue;
			}
			if (json_object_get_boolean(app, "kmod") == 1 &&
			    add_uid_distinct(kmod->uids, &kmod->count, uid)) {
				set_error(error, error_len, "blacklist target set exceeds MAX_TARGET_UIDS");
				return -E2BIG;
			}
			if (json_object_get_boolean(app, "lsposed") == 1 &&
			    add_uid_distinct(lsposed->uids, &lsposed->count, uid)) {
				set_error(error, error_len, "blacklist target set exceeds MAX_TARGET_UIDS");
				return -E2BIG;
			}
		}
		free(packages);
		if (self_uid) {
			if (add_uid_distinct(kmod->uids, &kmod->count, self_uid) ||
			    add_uid_distinct(lsposed->uids, &lsposed->count, self_uid)) {
				set_error(error, error_len, "blacklist target set exceeds MAX_TARGET_UIDS");
				return -E2BIG;
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
	ret = resolve_layer(apps, packages, package_count, "kmod", self_uid,
				    summary->mode, kmod, summary, error, error_len);
	if (!ret)
		ret = resolve_layer(apps, packages, package_count, "lsposed", self_uid,
				    summary->mode, lsposed, summary, error, error_len);
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
				       struct vpnhide_port_ioctl_data *result,
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
	memset(result, 0, sizeof(*result));
	apps = json_object_get_array(root, "apps");
	port_rules = json_object_get_array(root, "portRules");
	mass_rules = json_object_get_array(root, "massPortRules");
	if (!port_layer_enabled(apps))
		return 0;

	if (summary->mode == VPNHIDE_LIST_BLACKLIST) {
		size_t n = apps ? json_array_get_count(apps) : 0;
		size_t j;
		ret = discover_packages(&packages, &package_count, error, error_len);
		if (ret)
			return ret;
		for (j = 0; j < n; j++) {
			JSON_Object *app = json_array_get_object(apps, j);
			struct vpnhide_uid_port_rules *target;
			uid_t uid;
			if (!app || json_object_get_boolean(app, "portHiding") != 1)
				continue;
			uid = (uid_t)json_object_get_number(app, "uid");
			if (!uid || uid == self_uid || uid < 10000)
				continue;
			if (configured_package_is_protected(app, packages, package_count))
				continue;
			if (result->count >= MAX_TARGET_UIDS) {
				set_error(error, error_len, "port target set exceeds MAX_TARGET_UIDS");
				return -E2BIG;
			}
			target = &result->targets[result->count];
			memset(target, 0, sizeof(*target));
			target->uid = uid;
			/* Blacklist entries may have stale package metadata, so use the
			 * configured package key only when it is available. */
			{
				const char *name = json_object_get_string(app, "packageName");
				int user = (int)json_object_get_number(app, "userId");
				size_t k, m = port_rules ? json_array_get_count(port_rules) : 0;
				for (k = 0; k < m; k++) {
					JSON_Object *rule = json_array_get_object(port_rules, k);
					const char *rule_name;
					if (!rule)
						continue;
					rule_name = json_object_get_string(rule, "packageName");
					if (name && rule_name && !strcmp(name, rule_name) &&
					    (int)json_object_get_number(rule, "userId") == user) {
						ret = add_port_rule(target, rule, error, error_len);
						if (ret < 0)
							return ret;
					}
				}
			}
			{
				size_t k;
				for (k = 0; mass_rules && k < json_array_get_count(mass_rules); k++) {
				JSON_Object *rule = json_array_get_object(mass_rules, k);
			if (!rule)
				continue;
			ret = add_port_rule(target, rule, error, error_len);
			if (ret < 0)
				return ret;
				}
			}
			if (!target->rule_count) {
				target->rules[0].start_port = 0;
				target->rules[0].end_port = 65535;
				target->rules[0].protocol = VH_PROTO_BOTH;
				target->rule_count = 1;
			}
			result->count++;
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
		if (pkg->system_package || pkg->uid == self_uid || pkg->uid < 10000)
			continue;
		selected = selected_for_layer(apps, pkg->name, pkg->user_id,
					      pkg->uid, "portHiding");
		if (selected)
			continue;
		/* Several packages may share one UID. Port policy is keyed by UID,
		 * so resolve that UID only once rather than emitting duplicate rules. */
		for (int existing = 0; existing < result->count; existing++) {
			if (result->targets[existing].uid == pkg->uid)
				goto next_package;
		}
		if (result->count >= MAX_TARGET_UIDS) {
			free(packages);
			set_error(error, error_len, "port target set exceeds MAX_TARGET_UIDS");
			return -E2BIG;
		}
		ret = resolve_package_port_rules(port_rules, mass_rules, pkg,
						&result->targets[result->count], error, error_len);
		if (ret) {
			free(packages);
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
