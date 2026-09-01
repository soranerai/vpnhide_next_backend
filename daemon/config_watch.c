#include "daemon.h"

static void reload_policy(const char *ctl, const char *config) {
  pid_t pid;
  int status;

  if (!ctl || !config || access(config, R_OK) != 0)
    return;
  pid = fork();
  if (pid < 0) {
    fprintf(stderr, "vpnhide-daemon: cannot fork policy reload: %s\n",
            strerror(errno));
    return;
  }
  if (pid == 0) {
    execl(ctl, ctl, "load", config, (char *)NULL);
    _exit(127);
  }
  if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0)
    fprintf(stderr, "vpnhide-daemon: policy reload failed\n");
}

void drain_config_events(int inotify_fd, const char *config, const char *ctl) {
  char buffer[4096];
  ssize_t length;
  bool changed = false;
  const char *config_name = strrchr(config, '/');

  config_name = config_name ? config_name + 1 : config;
  while ((length = read(inotify_fd, buffer, sizeof(buffer))) > 0) {
    size_t offset = 0;

    while (offset < (size_t)length) {
      struct inotify_event *event = (struct inotify_event *)(buffer + offset);

      if (event->len > 0 && !strcmp(event->name, config_name) &&
          (event->mask &
           (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ATTRIB)))
        changed = true;
      offset += sizeof(*event) + event->len;
    }
  }
  if (changed) {
    fprintf(stderr, "vpnhide-daemon: configuration changed, reloading\n");
    reload_policy(ctl, config);
  }
}
