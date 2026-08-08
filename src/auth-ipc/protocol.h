/* SPDX-License-Identifier: Apache-2.0 */
/* Defines the fixed authentication-sidecar loopback protocol and validators. */
#ifndef PKU_ARRAY_AUTH_PROTOCOL_H
#define PKU_ARRAY_AUTH_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef PKU_AUTH_MAGIC
#define PKU_AUTH_MAGIC "PKUAUTH1"
#endif

#define PKU_AUTH_MAGIC_LEN 8
#define PKU_AUTH_VERSION 1

#ifndef PKU_AUTH_PORT
#define PKU_AUTH_PORT 10981
#endif

#define PKU_AUTH_COOKIE_MAX 8192

/** Operations accepted by the version-1 sidecar endpoint. */
enum pku_auth_operation
{
	PKU_AUTH_OP_AUTHENTICATE = 1,
	PKU_AUTH_OP_HEALTH = 2,
	PKU_AUTH_OP_INVALIDATE = 3,
};

/** Process-compatible status values returned in IPC response headers. */
enum pku_auth_status
{
	PKU_AUTH_STATUS_OK = 0,
	PKU_AUTH_STATUS_PERMANENT = 64,
	PKU_AUTH_STATUS_TRANSIENT = 75,
};

/** Stable sanitized reason values shared by the client and server. */
enum pku_auth_reason
{
	PKU_AUTH_REASON_NONE = 0,
	PKU_AUTH_REASON_BAD_REQUEST = 1,
	PKU_AUTH_REASON_UNAVAILABLE = 2,
	PKU_AUTH_REASON_CONFIG = 3,
	PKU_AUTH_REASON_SECRET = 4,
	PKU_AUTH_REASON_SDK_INCOMPATIBLE = 5,
	PKU_AUTH_REASON_CERTIFICATE = 6,
	PKU_AUTH_REASON_METHOD = 7,
	PKU_AUTH_REASON_UNKNOWN_CHALLENGE = 8,
	PKU_AUTH_REASON_REPEATED_CHALLENGE = 9,
	PKU_AUTH_REASON_AUTH_REJECTED = 10,
	PKU_AUTH_REASON_AUTH_TIMEOUT = 11,
	PKU_AUTH_REASON_COOKIE = 12,
	PKU_AUTH_REASON_NETWORK = 13,
	PKU_AUTH_REASON_INTERNAL = 14,
	PKU_AUTH_REASON_RATE_LIMIT = 15,
	PKU_AUTH_REASON_MAUTH = 16,
	PKU_AUTH_REASON_METHOD_INPUT = 17,
	PKU_AUTH_REASON_METHOD_SELECTION = 18,
	PKU_AUTH_REASON_METHOD_STEPS = 19,
	PKU_AUTH_REASON_METHOD_SEQUENCE = 20,
	PKU_AUTH_REASON_METHOD_CALLBACK_ERROR = 21,
	PKU_AUTH_REASON_METHOD_BUFFER = 22,
	PKU_AUTH_REASON_METHOD_COUNT = 23,
	PKU_AUTH_REASON_METHOD_NAME = 24,
	PKU_AUTH_REASON_METHOD_INPUT_NULL = 25,
	PKU_AUTH_REASON_METHOD_INPUT_LENGTH = 26,
	PKU_AUTH_REASON_METHOD_OUTPUT_NULL = 27,
	PKU_AUTH_REASON_METHOD_OUTPUT_LENGTH_NULL = 28,
	PKU_AUTH_REASON_METHOD_OUTPUT_CAPACITY = 29,
	PKU_AUTH_REASON_MAX = PKU_AUTH_REASON_METHOD_OUTPUT_CAPACITY,
};

/** Fixed 16-byte client request; multibyte fields use network byte order. */
struct __attribute__((packed)) pku_auth_request
{
	char magic[PKU_AUTH_MAGIC_LEN];
	uint8_t version;
	uint8_t operation;
	uint16_t reserved;
	uint32_t candidate_ipv4;
};

/** Fixed 16-byte response header followed by an optional Cookie payload. */
struct __attribute__((packed)) pku_auth_response
{
	char magic[PKU_AUTH_MAGIC_LEN];
	uint8_t version;
	uint8_t status;
	uint16_t reason;
	uint32_t payload_length;
};

_Static_assert(sizeof(struct pku_auth_request) == 16,
			   "unexpected authentication request wire size");
_Static_assert(sizeof(struct pku_auth_response) == 16,
			   "unexpected authentication response wire size");

/**
 * Reports whether a numeric reason is part of the version-1 wire protocol.
 *
 * Args:
 *   reason: Host-byte-order reason value received from the peer.
 *
 * Returns:
 *   Nonzero for a declared reason; zero for unknown or reserved values.
 */
static inline int pku_auth_reason_valid(uint16_t reason)
{
	switch (reason)
	{
	case PKU_AUTH_REASON_NONE:
	case PKU_AUTH_REASON_BAD_REQUEST:
	case PKU_AUTH_REASON_UNAVAILABLE:
	case PKU_AUTH_REASON_CONFIG:
	case PKU_AUTH_REASON_SECRET:
	case PKU_AUTH_REASON_SDK_INCOMPATIBLE:
	case PKU_AUTH_REASON_CERTIFICATE:
	case PKU_AUTH_REASON_METHOD:
	case PKU_AUTH_REASON_UNKNOWN_CHALLENGE:
	case PKU_AUTH_REASON_REPEATED_CHALLENGE:
	case PKU_AUTH_REASON_AUTH_REJECTED:
	case PKU_AUTH_REASON_AUTH_TIMEOUT:
	case PKU_AUTH_REASON_COOKIE:
	case PKU_AUTH_REASON_NETWORK:
	case PKU_AUTH_REASON_INTERNAL:
	case PKU_AUTH_REASON_RATE_LIMIT:
	case PKU_AUTH_REASON_MAUTH:
	case PKU_AUTH_REASON_METHOD_INPUT:
	case PKU_AUTH_REASON_METHOD_SELECTION:
	case PKU_AUTH_REASON_METHOD_STEPS:
	case PKU_AUTH_REASON_METHOD_SEQUENCE:
	case PKU_AUTH_REASON_METHOD_CALLBACK_ERROR:
	case PKU_AUTH_REASON_METHOD_BUFFER:
	case PKU_AUTH_REASON_METHOD_COUNT:
	case PKU_AUTH_REASON_METHOD_NAME:
	case PKU_AUTH_REASON_METHOD_INPUT_NULL:
	case PKU_AUTH_REASON_METHOD_INPUT_LENGTH:
	case PKU_AUTH_REASON_METHOD_OUTPUT_NULL:
	case PKU_AUTH_REASON_METHOD_OUTPUT_LENGTH_NULL:
	case PKU_AUTH_REASON_METHOD_OUTPUT_CAPACITY:
		return 1;
	default:
		return 0;
	}
}

/**
 * Validates an authentication payload without treating it as a C string.
 *
 * Args:
 *   cookie: Candidate `ANsession*=value` bytes.
 *   length: Exact payload length; a trailing NUL is neither required nor read.
 *
 * Returns:
 *   Nonzero when the name and value satisfy the IPC contract; otherwise zero.
 */
static inline int pku_auth_cookie_valid(const char *cookie, size_t length)
{
	size_t name_length = 0;
	size_t i;

	if (!cookie || !length || length > PKU_AUTH_COOKIE_MAX ||
		length < sizeof("ANsession=") - 1U ||
		memcmp(cookie, "ANsession", sizeof("ANsession") - 1U))
		return 0;

	while (name_length < length && cookie[name_length] != '=')
	{
		unsigned char value = (unsigned char)cookie[name_length];

		if (!((value >= 'a' && value <= 'z') ||
			  (value >= 'A' && value <= 'Z') ||
			  (value >= '0' && value <= '9') || value == '_' ||
			  value == '-' || value == '.'))
			return 0;

		name_length++;
	}

	if (name_length < sizeof("ANsession") - 1U ||
		name_length >= length || name_length > 64U ||
		name_length + 1U == length)
		return 0;

	for (i = name_length + 1U; i < length; i++)
	{
		unsigned char value = (unsigned char)cookie[i];

		if (value <= 0x20U || value == 0x7fU || value == ';')
			return 0;
	}

	return 1;
}

/**
 * Returns the stable diagnostic name for a wire-protocol reason.
 *
 * Args:
 *   reason: Host-byte-order reason value.
 *
 * Returns:
 *   A process-lifetime string. Unknown values map to "UNKNOWN".
 */
static inline const char *pku_auth_reason_name(uint16_t reason)
{
	switch (reason)
	{
	case PKU_AUTH_REASON_NONE:
		return "NONE";
	case PKU_AUTH_REASON_BAD_REQUEST:
		return "BAD_REQUEST";
	case PKU_AUTH_REASON_UNAVAILABLE:
		return "UNAVAILABLE";
	case PKU_AUTH_REASON_CONFIG:
		return "CONFIG";
	case PKU_AUTH_REASON_SECRET:
		return "SECRET";
	case PKU_AUTH_REASON_SDK_INCOMPATIBLE:
		return "SDK_INCOMPATIBLE";
	case PKU_AUTH_REASON_CERTIFICATE:
		return "CERTIFICATE";
	case PKU_AUTH_REASON_METHOD:
		return "METHOD";
	case PKU_AUTH_REASON_UNKNOWN_CHALLENGE:
		return "UNKNOWN_CHALLENGE";
	case PKU_AUTH_REASON_REPEATED_CHALLENGE:
		return "REPEATED_CHALLENGE";
	case PKU_AUTH_REASON_AUTH_REJECTED:
		return "AUTH_REJECTED";
	case PKU_AUTH_REASON_AUTH_TIMEOUT:
		return "AUTH_TIMEOUT";
	case PKU_AUTH_REASON_COOKIE:
		return "COOKIE";
	case PKU_AUTH_REASON_NETWORK:
		return "NETWORK";
	case PKU_AUTH_REASON_INTERNAL:
		return "INTERNAL";
	case PKU_AUTH_REASON_RATE_LIMIT:
		return "RATE_LIMIT";
	case PKU_AUTH_REASON_MAUTH:
		return "MAUTH";
	case PKU_AUTH_REASON_METHOD_INPUT:
		return "METHOD_INPUT";
	case PKU_AUTH_REASON_METHOD_SELECTION:
		return "METHOD_SELECTION";
	case PKU_AUTH_REASON_METHOD_STEPS:
		return "METHOD_STEPS";
	case PKU_AUTH_REASON_METHOD_SEQUENCE:
		return "METHOD_SEQUENCE";
	case PKU_AUTH_REASON_METHOD_CALLBACK_ERROR:
		return "METHOD_CALLBACK_ERROR";
	case PKU_AUTH_REASON_METHOD_BUFFER:
		return "METHOD_BUFFER";
	case PKU_AUTH_REASON_METHOD_COUNT:
		return "METHOD_COUNT";
	case PKU_AUTH_REASON_METHOD_NAME:
		return "METHOD_NAME";
	case PKU_AUTH_REASON_METHOD_INPUT_NULL:
		return "METHOD_INPUT_NULL";
	case PKU_AUTH_REASON_METHOD_INPUT_LENGTH:
		return "METHOD_INPUT_LENGTH";
	case PKU_AUTH_REASON_METHOD_OUTPUT_NULL:
		return "METHOD_OUTPUT_NULL";
	case PKU_AUTH_REASON_METHOD_OUTPUT_LENGTH_NULL:
		return "METHOD_OUTPUT_LENGTH_NULL";
	case PKU_AUTH_REASON_METHOD_OUTPUT_CAPACITY:
		return "METHOD_OUTPUT_CAPACITY";
	default:
		return "UNKNOWN";
	}
}

#endif
