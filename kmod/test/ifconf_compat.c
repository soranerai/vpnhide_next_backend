/* Run as a 32-bit process in the QEMU guest. */
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static _Thread_local volatile char vh_tls_alignment __attribute__((aligned(64)));

static int check(int fd, int hidden)
{
    struct ifconf query = {0}, result;
    unsigned char buf[4096];
    int vpn = 0, eth = 0;
    if (ioctl(fd, SIOCGIFCONF, &query)) return 1;
    memset(buf, 0xa5, sizeof(buf));
    result.ifc_len = sizeof(buf);
    result.ifc_buf = (char *)buf;
    if (ioctl(fd, SIOCGIFCONF, &result)) return 2;
    if (result.ifc_len != query.ifc_len || result.ifc_len < 0 ||
        result.ifc_len > (int)sizeof(buf) || result.ifc_len % sizeof(struct ifreq)) return 3;
    for (int i = 0; i < result.ifc_len; i += sizeof(struct ifreq)) {
        struct ifreq entry;
        memcpy(&entry, buf + i, sizeof(entry));
        entry.ifr_name[IFNAMSIZ - 1] = 0;
        if (!strcmp(entry.ifr_name, "vpn0")) vpn++;
        if (!strcmp(entry.ifr_name, "eth0")) eth++;
    }
    if (!!vpn == !!hidden || !eth) return 4;
    for (int i = result.ifc_len; i < (int)sizeof(buf); i++)
        if (buf[i] != 0xa5) return 5;
    memset(buf, 0xa5, sizeof(buf));
    result.ifc_len = sizeof(struct ifreq) * 2;
    result.ifc_buf = (char *)buf;
    if (ioctl(fd, SIOCGIFCONF, &result)) return 6;
    if (result.ifc_len < 0 || result.ifc_len > (int)(sizeof(struct ifreq) * 2)) return 7;
    for (int i = result.ifc_len; i < (int)sizeof(buf); i++)
        if (buf[i] != 0xa5) return 8;
    return 0;
}
int main(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0), status, rc;
    vh_tls_alignment = 1;
    pid_t pid;
    if (fd < 0 || sizeof(void *) != 4) return 1;
    rc = check(fd, 0);
    if (rc) { printf("compat non-target failed: %d errno=%d\n", rc, errno); return 1; }
    pid = fork();
    if (pid < 0) return 1;
    if (!pid) {
        if (setuid(115555)) _exit(1);
        rc = check(fd, 1);
        if (rc) dprintf(2, "compat target failed: %d errno=%d\n", rc, errno);
        _exit(rc ? 1 : 0);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    close(fd);
    return 0;
}
