/* SPDX-License-Identifier: Apache-2.0 */
/* Implements the unprivileged loopback client for authentication IPC. */
#define _GNU_SOURCE

#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef PKU_AUTH_RESPONSE_TIMEOUT_SECONDS
#define PKU_AUTH_RESPONSE_TIMEOUT_SECONDS 130
#endif

#define PKU_AUTH_CONTROL_TIMEOUT_SECONDS 5

/* Writes an exact bounded buffer, retrying only interrupted system calls. */
static int write_all(int fd, const void *data, size_t length)
{
	const unsigned char *cursor = data;

	while (length)
	{
		ssize_t written = write(fd, cursor, length);

		if (written < 0 && errno == EINTR)
			continue;

		if (written <= 0)
			return -1;

		cursor += (size_t)written;
		length -= (size_t)written;
	}

	return 0;
}

/* Reads an exact bounded buffer, retrying only interrupted system calls. */
static int read_all(int fd, void *data, size_t length)
{
	unsigned char *cursor = data;

	while (length)
	{
		ssize_t received = read(fd, cursor, length);

		if (received < 0 && errno == EINTR)
			continue;

		if (received <= 0)
			return -1;

		cursor += (size_t)received;
		length -= (size_t)received;
	}

	return 0;
}

/* Connects to the loopback sidecar with an operation-specific timeout. */
static int connect_server(uint8_t operation)
{
	struct sockaddr_in address;

	struct timeval receive_timeout =
		{
			.tv_sec = operation == PKU_AUTH_OP_AUTHENTICATE ? PKU_AUTH_RESPONSE_TIMEOUT_SECONDS : PKU_AUTH_CONTROL_TIMEOUT_SECONDS,
			.tv_usec = 0,
		};

	struct timeval send_timeout =
		{
			.tv_sec = PKU_AUTH_CONTROL_TIMEOUT_SECONDS,
			.tv_usec = 0,
		};

	int fd;
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
					 sizeof(receive_timeout));

	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout,
					 sizeof(send_timeout));

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(PKU_AUTH_PORT);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)))
	{
		close(fd);
		return -1;
	}

	return fd;
}

/* Exchanges one authenticated, health, or invalidation IPC request. */
static int request(uint8_t operation, struct in_addr candidate)
{
	struct pku_auth_request request_message;
	struct pku_auth_response response;
	char payload[PKU_AUTH_COOKIE_MAX + 1];
	uint32_t payload_length;
	uint16_t reason;
	int fd;
	fd = connect_server(operation);

	if (fd < 0)
	{
		fprintf(stderr, "ARRAY_AUTH_TRANSIENT:UNAVAILABLE\n");
		return PKU_AUTH_STATUS_TRANSIENT;
	}

	memset(&request_message, 0, sizeof(request_message));
	memcpy(request_message.magic, PKU_AUTH_MAGIC, PKU_AUTH_MAGIC_LEN);
	request_message.version = PKU_AUTH_VERSION;
	request_message.operation = operation;
	request_message.candidate_ipv4 = candidate.s_addr;

	if (write_all(fd, &request_message, sizeof(request_message)) ||
		read_all(fd, &response, sizeof(response)))
	{
		close(fd);
		fprintf(stderr, "ARRAY_AUTH_TRANSIENT:UNAVAILABLE\n");
		return PKU_AUTH_STATUS_TRANSIENT;
	}

	if (memcmp(response.magic, PKU_AUTH_MAGIC, PKU_AUTH_MAGIC_LEN) ||
		response.version != PKU_AUTH_VERSION)
	{
		close(fd);
		fprintf(stderr, "ARRAY_AUTH_PERMANENT:BAD_RESPONSE\n");
		return PKU_AUTH_STATUS_PERMANENT;
	}

	payload_length = ntohl(response.payload_length);
	reason = ntohs(response.reason);

	if (!pku_auth_reason_valid(reason) ||
		(response.status != PKU_AUTH_STATUS_OK &&
		 response.status != PKU_AUTH_STATUS_PERMANENT &&
		 response.status != PKU_AUTH_STATUS_TRANSIENT) ||
		(response.status == PKU_AUTH_STATUS_OK &&
		 reason != PKU_AUTH_REASON_NONE) ||
		(response.status != PKU_AUTH_STATUS_OK &&
		 reason == PKU_AUTH_REASON_NONE) ||
		payload_length > PKU_AUTH_COOKIE_MAX ||
		(response.status == PKU_AUTH_STATUS_OK &&
		 operation != PKU_AUTH_OP_AUTHENTICATE && payload_length) ||
		(response.status != PKU_AUTH_STATUS_OK && payload_length))
	{
		close(fd);
		fprintf(stderr, "ARRAY_AUTH_PERMANENT:BAD_RESPONSE\n");
		return PKU_AUTH_STATUS_PERMANENT;
	}

	if (payload_length && read_all(fd, payload, payload_length))
	{
		close(fd);
		fprintf(stderr, "ARRAY_AUTH_TRANSIENT:UNAVAILABLE\n");
		return PKU_AUTH_STATUS_TRANSIENT;
	}

	close(fd);

	if (response.status == PKU_AUTH_STATUS_PERMANENT)
	{
		fprintf(stderr, "ARRAY_AUTH_PERMANENT:%s\n",
				pku_auth_reason_name(reason));

		return PKU_AUTH_STATUS_PERMANENT;
	}

	if (response.status == PKU_AUTH_STATUS_TRANSIENT)
	{
		fprintf(stderr, "ARRAY_AUTH_TRANSIENT:%s\n",
				pku_auth_reason_name(reason));

		return PKU_AUTH_STATUS_TRANSIENT;
	}

	if (operation != PKU_AUTH_OP_AUTHENTICATE)
	{
		return 0;
	}

	if (!pku_auth_cookie_valid(payload, payload_length))
	{
		fprintf(stderr, "ARRAY_AUTH_PERMANENT:COOKIE\n");
		return PKU_AUTH_STATUS_PERMANENT;
	}

	payload[payload_length] = 0;

	if (write_all(STDOUT_FILENO, payload, payload_length) ||
		write_all(STDOUT_FILENO, "\n", 1))
		return PKU_AUTH_STATUS_TRANSIENT;

	memset(payload, 0, sizeof(payload));
	return 0;
}

/* Parses the private CLI and forwards exactly one operation to the sidecar. */
int main(int argc, char **argv)
{
	struct in_addr candidate = {.s_addr = 0};
	uint8_t operation;
	(void)signal(SIGPIPE, SIG_IGN);

	if (argc == 2 && !strcmp(argv[1], "--healthcheck"))
	{
		operation = PKU_AUTH_OP_HEALTH;
	}
	else if (argc == 2 && !strcmp(argv[1], "--invalidate"))
	{
		operation = PKU_AUTH_OP_INVALIDATE;
	}
	else if (argc == 2 && inet_pton(AF_INET, argv[1], &candidate) == 1)
	{
		operation = PKU_AUTH_OP_AUTHENTICATE;
	}
	else
	{
		fprintf(stderr,
				"usage: array-auth-client <candidate-ipv4>|--healthcheck|--invalidate\n");

		return PKU_AUTH_STATUS_PERMANENT;
	}

	return request(operation, candidate);
}
