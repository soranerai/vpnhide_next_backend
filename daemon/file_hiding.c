#include "daemon.h"

static void susfs_log_error(const char *format, ...);

/* A VPN interface can disappear and be recreated under the same name, so keep a
 * small userspace identity cache and register each new object once. */
#define SUSFS_MAX_PATHS (MAX_ACTIVE_VPNS * 8)
#define SUSFS_RETRY_LOG_MS (60ULL * 1000ULL)
#define NOMOUNT_MAX_PATHS (MAX_ACTIVE_VPNS * 8)

struct susfs_registered_path {
  char path[PATH_MAX];
  dev_t dev;
  ino_t ino;
  bool valid;
};

static struct susfs_registered_path susfs_registered[SUSFS_MAX_PATHS];
static const char *const susfs_tool_candidates[] = {
    "/data/adb/ksu/bin/ksu_susfs",
    "/data/adb/ksu/bin/susfs",
};
static const char *susfs_tool;
static unsigned long long susfs_last_error_log;
static const char *susfs_config_path;
static bool susfs_enabled = true;
static bool use_nomount_for_file_hiding;

void file_hiding_set_config_path(const char *config_path) {
  susfs_config_path = config_path;
}

struct nomount_registered_path {
  char path[PATH_MAX];
  bool valid;
};

static struct nomount_registered_path nomount_registered[NOMOUNT_MAX_PATHS];
static const char *const nomount_tool_candidates[] = {
    "/data/adb/modules/nomount/bin/nm",
};
static const char *nomount_tool;

/* Bit 18 remains a compatibility/configuration bit, but is no longer read by
 * the kernel.  The daemon owns this decision because SUSFS is userspace-
 * commanded and its path rules are not part of the kmod policy snapshot. */
static void susfs_refresh_enabled(void) {
  FILE *file;
  char buffer[131072];
  size_t length;
  char *global;
  char *apps;
  char *mask;
  char *nomount;
  char *end;
  unsigned long long value;

  use_nomount_for_file_hiding = false;
  if (!susfs_config_path || !susfs_config_path[0]) {
    susfs_enabled = true;
    return;
  }
  file = fopen(susfs_config_path, "r");
  if (!file)
    return;
  length = fread(buffer, 1, sizeof(buffer) - 1, file);
  fclose(file);
  buffer[length] = '\0';
  global = strstr(buffer, "\"globalConfig\"");
  if (!global)
    return;
  apps = strstr(global, "\"apps\"");
  nomount = strstr(global, "\"useNoMountForFileHiding\"");
  if (nomount && (!apps || nomount < apps)) {
    nomount = strchr(nomount, ':');
    if (nomount) {
      while (*++nomount == ' ' || *nomount == '\t')
        ;
      use_nomount_for_file_hiding = !strncmp(nomount, "true", 4);
    }
  }
  mask = strstr(global, "\"kernelHookMask\"");
  if (!mask || (apps && mask > apps))
    return;
  mask = strchr(mask, ':');
  if (!mask)
    return;
  value = strtoull(mask + 1, &end, 0);
  if (end == mask + 1)
    return;
  susfs_enabled = (value & (1ULL << 18)) != 0 && !use_nomount_for_file_hiding;
}

static const char *nomount_find_tool(void) {
  size_t i;

  if (nomount_tool)
    return nomount_tool;
  for (i = 0;
       i < sizeof(nomount_tool_candidates) / sizeof(nomount_tool_candidates[0]);
       i++) {
    if (access(nomount_tool_candidates[i], X_OK) == 0) {
      nomount_tool = nomount_tool_candidates[i];
      return nomount_tool;
    }
  }
  return NULL;
}

static int nomount_run_rule(const char *action, const char *path) {
  const char *tool = nomount_find_tool();
  int status;
  pid_t pid;
  unsigned long long deadline;

  if (!tool) {
    susfs_log_error(
        "NoMount binary not found at /data/adb/modules/nomount/bin/nm");
    return -ENOENT;
  }
  pid = fork();
  if (pid < 0)
    return -errno;
  if (pid == 0) {
    if (!strcmp(action, "add"))
      execl(tool, tool, "rule", "add", "--whiteout", path, (char *)NULL);
    else
      execl(tool, tool, "rule", "del", path, (char *)NULL);
    _exit(127);
  }

  deadline = daemon_get_time_ms() + 2000;
  for (;;) {
    pid_t waited = waitpid(pid, &status, WNOHANG);
    if (waited == pid)
      break;
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      return -errno;
    }
    if (daemon_get_time_ms() >= deadline) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      return -ETIMEDOUT;
    }
    usleep(10000);
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

static struct nomount_registered_path *
nomount_find_registered_path(const char *path) {
  size_t i;

  for (i = 0; i < NOMOUNT_MAX_PATHS; i++)
    if (nomount_registered[i].valid &&
        !strcmp(nomount_registered[i].path, path))
      return &nomount_registered[i];
  return NULL;
}

static void nomount_register_path(const char *path) {
  struct nomount_registered_path *registered;
  size_t i;

  if (!path || !path[0])
    return;
  registered = nomount_find_registered_path(path);
  if (registered)
    return;
  if (nomount_run_rule("add", path))
    return;
  for (i = 0; i < NOMOUNT_MAX_PATHS; i++) {
    if (!nomount_registered[i].valid) {
      nomount_registered[i].valid = true;
      strncpy(nomount_registered[i].path, path, PATH_MAX - 1);
      nomount_registered[i].path[PATH_MAX - 1] = '\0';
      return;
    }
  }
  susfs_log_error("NoMount registration cache is full; path %s was not cached",
                  path);
}

static void nomount_unregister_paths(void) {
  size_t i;

  for (i = 0; i < NOMOUNT_MAX_PATHS; i++) {
    if (!nomount_registered[i].valid)
      continue;
    nomount_run_rule("del", nomount_registered[i].path);
    nomount_registered[i].valid = false;
  }
}

static const char *susfs_find_tool(void) {
  size_t i;

  if (susfs_tool)
    return susfs_tool;
  for (i = 0;
       i < sizeof(susfs_tool_candidates) / sizeof(susfs_tool_candidates[0]);
       i++) {
    if (access(susfs_tool_candidates[i], X_OK) == 0) {
      susfs_tool = susfs_tool_candidates[i];
      return susfs_tool;
    }
  }
  return NULL;
}

static void susfs_log_error(const char *format, ...) {
  unsigned long long now = daemon_get_time_ms();
  va_list ap;

  if (susfs_last_error_log && now - susfs_last_error_log < SUSFS_RETRY_LOG_MS)
    return;
  susfs_last_error_log = now;
  fputs("vpnhide-daemon: SUSFS path hiding unavailable: ", stderr);
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
  fputc('\n', stderr);
}

static int susfs_add_path_loop(const char *path) {
  const char *tool = susfs_find_tool();
  int status;
  pid_t pid;
  unsigned long long deadline;

  if (!tool) {
    susfs_log_error(
        "ksu_susfs command not found; continuing without path hiding");
    return -ENOENT;
  }

  pid = fork();
  if (pid < 0) {
    susfs_log_error("fork failed: %s", strerror(errno));
    return -errno;
  }
  if (pid == 0) {
    execl(tool, tool, "add_sus_path_loop", path, (char *)NULL);
    _exit(127);
  }

  deadline = daemon_get_time_ms() + 2000;
  for (;;) {
    pid_t waited = waitpid(pid, &status, WNOHANG);
    if (waited == pid)
      break;
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      susfs_log_error("waitpid failed for %s: %s", path, strerror(errno));
      return -errno;
    }
    if (daemon_get_time_ms() >= deadline) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      susfs_log_error("command timed out for %s", path);
      return -ETIMEDOUT;
    }
    usleep(10000);
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    susfs_log_error("add_sus_path_loop failed for %s (status=%d)", path,
                    status);
    return -EIO;
  }
  return 0;
}

static bool susfs_path_registered(const char *path, const struct stat *st) {
  size_t i;

  for (i = 0; i < SUSFS_MAX_PATHS; i++) {
    if (susfs_registered[i].valid && susfs_registered[i].dev == st->st_dev &&
        susfs_registered[i].ino == st->st_ino &&
        strcmp(susfs_registered[i].path, path) == 0)
      return true;
  }
  return false;
}

static void susfs_forget_path(const char *path) {
  size_t i;

  for (i = 0; i < SUSFS_MAX_PATHS; i++) {
    if (susfs_registered[i].valid &&
        strcmp(susfs_registered[i].path, path) == 0)
      susfs_registered[i].valid = false;
  }
}

static void susfs_remember_path(const char *path, const struct stat *st) {
  size_t i;

  for (i = 0; i < SUSFS_MAX_PATHS; i++) {
    if (!susfs_registered[i].valid) {
      susfs_registered[i].valid = true;
      susfs_registered[i].dev = st->st_dev;
      susfs_registered[i].ino = st->st_ino;
      strncpy(susfs_registered[i].path, path,
              sizeof(susfs_registered[i].path) - 1);
      susfs_registered[i].path[sizeof(susfs_registered[i].path) - 1] = '\0';
      return;
    }
  }
  susfs_log_error("registration cache is full; path %s was not cached", path);
}

static void susfs_register_path(const char *path) {
  struct stat st;

  if (!path || !path[0])
    return;
  if (stat(path, &st) < 0) {
    susfs_forget_path(path);
    return;
  }
  if (susfs_path_registered(path, &st))
    return;
  if (susfs_add_path_loop(path) == 0)
    susfs_remember_path(path, &st);
}

static void susfs_sync_interface(const char *ifname) {
  char path[PATH_MAX];
  char real_path[PATH_MAX];
  const char *const suffixes[] = {
      "/proc/sys/net/ipv4/conf/%s",  "/proc/sys/net/ipv6/conf/%s",
      "/proc/sys/net/ipv4/neigh/%s", "/proc/sys/net/ipv6/neigh/%s",
      "/proc/net/dev_snmp6/%s",
  };
  size_t i;

  if (!ifname || !ifname[0])
    return;
  snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
  susfs_register_path(path);
  if (realpath(path, real_path))
    susfs_register_path(real_path);
  for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    snprintf(path, sizeof(path), suffixes[i], ifname);
    susfs_register_path(path);
  }
}

static void susfs_sync_interfaces(const struct vpnhide_vpn_ifindexes *vpns) {
  int i;

  if (!vpns)
    return;
  if (!susfs_enabled)
    return;
  for (i = 0; i < vpns->count && i < MAX_ACTIVE_VPNS; i++)
    susfs_sync_interface(vpns->vpns[i].name);
}

static void nomount_sync_interface(const char *ifname) {
  char path[PATH_MAX];
  const char *const suffixes[] = {
      "/proc/sys/net/ipv4/conf/%s",  "/proc/sys/net/ipv6/conf/%s",
      "/proc/sys/net/ipv4/neigh/%s", "/proc/sys/net/ipv6/neigh/%s",
      "/proc/net/dev_snmp6/%s",
  };
  size_t i;

  if (!ifname || !ifname[0])
    return;
  snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
  nomount_register_path(path);
  for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    snprintf(path, sizeof(path), suffixes[i], ifname);
    nomount_register_path(path);
  }
}

void file_hiding_sync_interfaces(const struct vpnhide_vpn_ifindexes *vpns) {
  int i;

  if (!vpns)
    return;
  susfs_refresh_enabled();
  if (use_nomount_for_file_hiding) {
    for (i = 0; i < vpns->count && i < MAX_ACTIVE_VPNS; i++)
      nomount_sync_interface(vpns->vpns[i].name);
    return;
  }
  nomount_unregister_paths();
  susfs_sync_interfaces(vpns);
}
