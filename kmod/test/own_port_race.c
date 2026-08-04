#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct failure_stats {
	unsigned int total;
	unsigned int refused;
	unsigned int timed_out;
	unsigned int other;
	int first_errno;
	unsigned int first_iteration;
};

static uint64_t monotonic_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void record_failure(struct failure_stats *stats, unsigned int iteration,
			   int error)
{
	stats->total++;
	if (!stats->first_errno) {
		stats->first_errno = error;
		stats->first_iteration = iteration;
	}
	if (error == ECONNREFUSED)
		stats->refused++;
	else if (error == ETIMEDOUT || error == EAGAIN || error == EWOULDBLOCK)
		stats->timed_out++;
	else
		stats->other++;
}

static void set_timeout(int fd)
{
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static int choose_explicit_port(int type, struct sockaddr_in *address)
{
	int probe = socket(AF_INET, type | SOCK_CLOEXEC, 0);
	socklen_t length = sizeof(*address);

	if (probe < 0 || bind(probe, (struct sockaddr *)address, sizeof(*address)) < 0 ||
	    getsockname(probe, (struct sockaddr *)address, &length) < 0) {
		int error = errno;
		if (probe >= 0)
			close(probe);
		errno = error;
		return -1;
	}
	close(probe);
	return 0;
}

static int run_tcp_iteration(unsigned int iteration,
			     struct failure_stats *failures, uint64_t *max_connect_us)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	socklen_t address_length = sizeof(address);
	int listener = -1, client = -1, accepted = -1;
	uint64_t started, elapsed;
	int error = 0;
	int reuse = 1;

	if (choose_explicit_port(SOCK_STREAM, &address) < 0) {
		error = errno;
		goto fail;
	}
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener >= 0)
		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	if (listener < 0 || bind(listener, (struct sockaddr *)&address,
					 sizeof(address)) < 0 ||
	    listen(listener, 1) < 0) {
		error = errno;
		goto fail;
	}
	{
		struct sockaddr_in actual;
		if (getsockname(listener, (struct sockaddr *)&actual, &address_length) < 0 ||
		    actual.sin_port != address.sin_port) {
			error = errno ? errno : EADDRNOTAVAIL;
			goto fail;
		}
	}

	client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client < 0) {
		error = errno;
		goto fail;
	}
	set_timeout(client);
	started = monotonic_us();
	if (connect(client, (struct sockaddr *)&address, sizeof(address)) < 0) {
		error = errno;
		goto fail;
	}
	elapsed = monotonic_us() - started;
	if (elapsed > *max_connect_us)
		*max_connect_us = elapsed;

	accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	if (accepted < 0) {
		error = errno;
		goto fail;
	}
	close(accepted);
	close(client);
	close(listener);
	return 0;

fail:
	record_failure(failures, iteration, error ? error : EIO);
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	if (listener >= 0)
		close(listener);
	return -1;
}

static int run_udp_iteration(unsigned int iteration,
			     struct failure_stats *failures, uint64_t *max_connect_us)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	socklen_t address_length = sizeof(address);
	char sent = 'V', received = 0;
	int server = -1, client = -1;
	uint64_t started, elapsed;
	int error = 0;

	if (choose_explicit_port(SOCK_DGRAM, &address) < 0) {
		error = errno;
		goto fail;
	}
	server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (server < 0 || bind(server, (struct sockaddr *)&address,
				     sizeof(address)) < 0) {
		error = errno;
		goto fail;
	}
	{
		struct sockaddr_in actual;
		if (getsockname(server, (struct sockaddr *)&actual, &address_length) < 0 ||
		    actual.sin_port != address.sin_port) {
			error = errno ? errno : EADDRNOTAVAIL;
			goto fail;
		}
	}
	set_timeout(server);

	client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (client < 0) {
		error = errno;
		goto fail;
	}
	set_timeout(client);
	started = monotonic_us();
	if (connect(client, (struct sockaddr *)&address, sizeof(address)) < 0) {
		error = errno;
		goto fail;
	}
	elapsed = monotonic_us() - started;
	if (elapsed > *max_connect_us)
		*max_connect_us = elapsed;
	if (send(client, &sent, sizeof(sent), 0) != sizeof(sent) ||
	    recv(server, &received, sizeof(received), 0) != sizeof(received) ||
	    received != sent) {
		error = errno ? errno : EIO;
		goto fail;
	}

	close(client);
	close(server);
	return 0;

fail:
	record_failure(failures, iteration, error ? error : EIO);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	return -1;
}

int main(int argc, char **argv)
{
	unsigned int iterations = 250;
	struct failure_stats tcp = {0}, udp = {0};
	uint64_t tcp_max_us = 0, udp_max_us = 0;
	unsigned int i;

	if (argc > 1) {
		char *end = NULL;
		unsigned long parsed = strtoul(argv[1], &end, 10);

		if (!end || *end || !parsed || parsed > 100000) {
			fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
			return 2;
		}
		iterations = (unsigned int)parsed;
	}

	printf("OWN_PORT_RACE uid=%u gid=%u iterations=%u\n",
	       (unsigned int)getuid(), (unsigned int)getgid(), iterations);
	for (i = 1; i <= iterations; i++) {
		run_tcp_iteration(i, &tcp, &tcp_max_us);
		run_udp_iteration(i, &udp, &udp_max_us);
	}

	printf("TCP pass=%u fail=%u refused=%u timeout=%u other=%u "
	       "first_iteration=%u first_errno=%d(%s) max_connect_us=%" PRIu64 "\n",
	       iterations - tcp.total, tcp.total, tcp.refused, tcp.timed_out,
	       tcp.other, tcp.first_iteration, tcp.first_errno,
	       tcp.first_errno ? strerror(tcp.first_errno) : "none", tcp_max_us);
	printf("UDP pass=%u fail=%u refused=%u timeout=%u other=%u "
	       "first_iteration=%u first_errno=%d(%s) max_connect_us=%" PRIu64 "\n",
	       iterations - udp.total, udp.total, udp.refused, udp.timed_out,
	       udp.other, udp.first_iteration, udp.first_errno,
	       udp.first_errno ? strerror(udp.first_errno) : "none", udp_max_us);
	printf("RESULT own_port_race=%s\n", tcp.total || udp.total ? "FAIL" : "PASS");
	return tcp.total || udp.total ? 1 : 0;
}
