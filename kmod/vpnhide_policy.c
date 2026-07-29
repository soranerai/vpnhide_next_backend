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
#define VPNHIDE_PACKAGE_NAME_MAX 256
#define VPNHIDE_APK_PATH_MAX 512

struct discovered_package {
	char name[VPNHIDE_PACKAGE_NAME_MAX];
	char apk_path[VPNHIDE_APK_PATH_MAX];
	uid_t uid;
	int user_id;
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
	out->system_package = package_is_system(out->apk_path);
	return 1;
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

	pipe = popen(VPNHIDE_PM_COMMAND, "r");
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
		/* Preserve legacy semantics without requiring Package Manager. */
		JSON_Array *array = (JSON_Array *)apps;
		size_t i, count = array ? json_array_get_count(array) : 0;
		for (i = 0; i < count; i++) {
			JSON_Object *app = json_array_get_object(array, i);
			uid_t uid;
			if (!app)
				continue;
			uid = (uid_t)json_object_get_number(app, "uid");
			if (!uid || uid == 0)
				continue;
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
