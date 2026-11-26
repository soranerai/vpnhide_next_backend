#include "daemon.h"

static void susfs_log_error(const char *format, ...);

/* A VPN interface can disappear and be recreated under the same name, so SUSFS
 * keeps a small userspace identity cache and registers each new object once. */
#define SUSFS_MAX_PATHS (MAX_ACTIVE_VPNS * 8)
#define SUSFS_RETRY_LOG_MS (60ULL * 1000ULL)

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
static const char *const ksud_tool_candidates[] = {
    "/data/adb/ksu/bin/ksud",
    "/data/adb/ksud",
};
static const char *susfs_tool;
static const char *ksud_tool;
static bool ksud_susfs_checked;
static bool ksud_susfs_available;
static unsigned long long susfs_last_error_log;
static const char *susfs_config_path;
static bool susfs_enabled = true;
static bool use_nomount_for_file_hiding;

void file_hiding_set_config_path(const char *config_path) {
  susfs_config_path = config_path;
}

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

static int nomount_run_rule(const char *path) {
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
    execl(tool, tool, "rule", "add", "--whiteout", path, (char *)NULL);
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

/* Sukisu Nova exposes SUSFS through ksud. Check its advertised subcommands
 * once, so older ksud builds without add-sus-path-loop are not invoked. */
static const char *susfs_find_ksud_tool(void) {
  size_t i;
  int status;
  pid_t pid;
  unsigned long long deadline;
  char output[8192];
  size_t used = 0;
  int pipefd[2];

  if (ksud_susfs_checked)
    return ksud_susfs_available ? ksud_tool : NULL;
  ksud_susfs_checked = true;
  for (i = 0; i < sizeof(ksud_tool_candidates) / sizeof(ksud_tool_candidates[0]); i++)
    if (access(ksud_tool_candidates[i], X_OK) == 0) {
      ksud_tool = ksud_tool_candidates[i];
      break;
    }
  if (!ksud_tool || pipe(pipefd) < 0)
    return NULL;
  pid = fork();
  if (pid < 0) {
    close(pipefd[0]); close(pipefd[1]);
    return NULL;
  }
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    execl(ksud_tool, ksud_tool, "susfs", "--help", (char *)NULL);
    _exit(127);
  }
  close(pipefd[1]);
  deadline = daemon_get_time_ms() + 2000;
  while (used < sizeof(output) - 1) {
    ssize_t n = read(pipefd[0], output + used, sizeof(output) - 1 - used);
    if (n > 0) { used += (size_t)n; continue; }
    if (n < 0 && errno == EINTR) continue;
    break;
  }
  close(pipefd[0]);
  output[used] = '\0';
  while (waitpid(pid, &status, WNOHANG) == 0 && daemon_get_time_ms() < deadline)
    usleep(10000);
  if (waitpid(pid, &status, WNOHANG) == 0) {
    kill(pid, SIGKILL); waitpid(pid, &status, 0);
    return NULL;
  }
  ksud_susfs_available = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                         strstr(output, "add-sus-path-loop") != NULL;
  return ksud_susfs_available ? ksud_tool : NULL;
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
  bool use_ksud = false;
  int status;
  pid_t pid;
  unsigned long long deadline;

  if (!tool) {
    tool = susfs_find_ksud_tool();
    use_ksud = tool != NULL;
  }
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
    if (use_ksud)
      execl(tool, tool, "susfs", "add-sus-path-loop", path, (char *)NULL);
    else
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
  nomount_run_rule(path);
  for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    snprintf(path, sizeof(path), suffixes[i], ifname);
    nomount_run_rule(path);
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
  susfs_sync_interfaces(vpns);
}
