/* SPDX-License-Identifier: Apache-2.0 */
/* Isolates the hash-locked iSecSP authentication component behind bounded IPC. */
#define _GNU_SOURCE

#include "../auth-ipc/protocol.h"
#include "sdk_abi.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef ARRAY_GATEWAY_HOST
#define ARRAY_GATEWAY_HOST "arrayvpn.pku.edu.cn"
#endif

#define ARRAY_GATEWAY_PORT 443

#ifndef ISECSP_LIBRARY_PATH
#define ISECSP_LIBRARY_PATH "/opt/isecsp/libvl3vpn.so"
#endif

#ifndef ISEC_LIBRARY_PATH
#define ISEC_LIBRARY_PATH "/opt/isecsp/libisec.so"
#endif

#ifndef PIN_FILE_PATH
#define PIN_FILE_PATH "/etc/arrayvpn/servercert-pins.txt"
#endif

#ifndef SECRET_DIRECTORY
#define SECRET_DIRECTORY "/run/secrets"
#endif

#define AUTH_METHOD_NAME "北京大学VPN"
#define AUTH_METHOD_RADIUS 2
#define SDK_SESSION_SIZE 9216
#define SDK_RETURN_SIZE 4096
#define MAX_PINS 8
#define MAX_VERIFIED_SSL 16
#define AUTH_TIMEOUT_SECONDS 120
#define CACHE_TTL_SECONDS 1200
#define FRESH_ATTEMPT_FLOOR_SECONDS 30
/* Locked to libisec.so SHA-256 cf9df4e6...; Docker and preparation
 * checks verify these local symbol offsets before the helper is built. */
#define ISEC_NET_SSL_OFFSET 16
#define ISEC_SSL_GET_PEER_CERTIFICATE_OFFSET ((uintptr_t)0x264bb0U)
#define ISEC_X509_GET_X509_PUBKEY_OFFSET ((uintptr_t)0x33bdd0U)
#define ISEC_I2D_X509_PUBKEY_OFFSET ((uintptr_t)0x346030U)
#define ISEC_SHA256_OFFSET ((uintptr_t)0x3206c0U)
#define ISEC_X509_FREE_OFFSET ((uintptr_t)0x346820U)
#define WORKER_MAGIC 0x504b5752U

/* Distinguishes credential submission from a worker's terminal result. */
enum worker_message_kind
{
	WORKER_MESSAGE_PRIMARY = 1,
	WORKER_MESSAGE_FINAL = 2,
};

/* Carries one fixed, bounded worker-to-parent authentication message. */
struct worker_message
{
	uint32_t magic;
	uint8_t kind;
	uint8_t status;
	uint16_t reason;
	uint32_t payload_length;
	char payload[PKU_AUTH_COOKIE_MAX];
};

/* Classifies the only supplemental prompts this adapter may answer. */
enum challenge_kind
{
	CHALLENGE_NONE = 0,
	CHALLENGE_ID_CARD = 1,
	CHALLENGE_PHONE = 2,
	CHALLENGE_AMBIGUOUS = 3,
};

/* Holds one worker's credentials and bounded authentication progress. */
struct worker_auth_state
{
	char username[257];
	char password[4097];
	char id_card_last6[7];
	char phone_missing4[5];
	bool primary_submitted;
	bool connected;
	bool id_card_submitted;
	bool phone_submitted;
	unsigned int supplemental_count;
	enum challenge_kind expected[2];
	unsigned int expected_count;
};

/* Opaque TLS types used by the hash-locked SDK entry points. */
typedef struct ssl_st SSL;
typedef struct x509_st X509;
typedef struct X509_pubkey_st X509_PUBKEY;

/* Function signatures resolved from the two isolated SDK libraries. */
typedef int (*ssl_connect_fn)(SSL *ssl);
typedef int (*ssl_write_fn)(SSL *ssl, const void *buffer, int length);
typedef int (*ssl_write_ex_fn)(SSL *ssl, const void *buffer, size_t length,
							   size_t *written);

typedef void (*ssl_free_fn)(SSL *ssl);
typedef int (*ssl_clear_fn)(SSL *ssl);
typedef X509 *(*ssl_get_peer_certificate_fn)(const SSL *ssl);
typedef X509_PUBKEY *(*x509_get_pubkey_fn)(const X509 *certificate);
typedef int (*i2d_x509_pubkey_fn)(const X509_PUBKEY *pubkey,
								  unsigned char **output);

typedef unsigned char *(*sha256_fn)(const unsigned char *data, size_t length,
									unsigned char *digest);

typedef void (*x509_free_fn)(X509 *certificate);
typedef int (*isec_net_connect_fn)(void *network);

typedef int (*isec_net_read_fn)(void *network, void *buffer,
								uint32_t length, void *error);

typedef int (*isec_net_write_fn)(void *network, const void *buffer,
								 uint32_t length, void *error);

typedef int (*isec_net_free_fn)(void *network);

typedef int (*isecsp_get_session_fn)(isecsp_user_parameter user,
									 char *session, uint32_t session_length,
									 char *return_value, uint32_t return_length);

typedef int (*array_get_cookies_fn)(char *session, size_t session_length);
typedef void (*array_log_level_fn)(int level, unsigned char flags);
static int (*real_connect_fn)(int, __CONST_SOCKADDR_ARG, socklen_t);

static int (*real_getaddrinfo_fn)(const char *, const char *,
								  const struct addrinfo *, struct addrinfo **);

static struct hostent *(*real_gethostbyname_fn)(const char *);
static pthread_once_t libc_symbols_once = PTHREAD_ONCE_INIT;
static ssl_connect_fn embedded_ssl_connect;
static ssl_write_fn embedded_ssl_write;
static ssl_write_ex_fn embedded_ssl_write_ex;
static ssl_free_fn embedded_ssl_free;
static ssl_clear_fn embedded_ssl_clear;
static ssl_get_peer_certificate_fn embedded_get_peer_certificate;
static x509_get_pubkey_fn embedded_get_x509_pubkey;
static i2d_x509_pubkey_fn embedded_i2d_x509_pubkey;
static sha256_fn embedded_sha256;
static x509_free_fn embedded_x509_free;
static isec_net_connect_fn embedded_isec_net_connect;
static isec_net_read_fn embedded_isec_net_read;
static isec_net_write_fn embedded_isec_net_write;
static isec_net_free_fn embedded_isec_net_free;
static array_get_cookies_fn embedded_get_cookies;
static ssl_get_peer_certificate_fn isec_get_peer_certificate;
static x509_get_pubkey_fn isec_get_x509_pubkey;
static i2d_x509_pubkey_fn isec_i2d_x509_pubkey;
static sha256_fn isec_sha256;
static x509_free_fn isec_x509_free;
static pthread_mutex_t verified_ssl_lock = PTHREAD_MUTEX_INITIALIZER;
static SSL *verified_ssl[MAX_VERIFIED_SSL];
static void *verified_isec_network[MAX_VERIFIED_SSL];
static unsigned int pinned_handshakes;
static unsigned char configured_pins[MAX_PINS][32];
static size_t configured_pin_count;
static struct worker_auth_state worker_auth;
static int worker_result_fd = -1;
static bool worker_active;
static struct in_addr worker_candidate;
static char worker_candidate_text[INET_ADDRSTRLEN];
static volatile sig_atomic_t server_stopping;
static int server_listener = -1;

static int select_session_cookie(char *session, char *selected,
								 size_t selected_size, size_t *selected_length);

/* Overwrites sensitive memory through a volatile byte pointer. */
static void secure_zero(void *data, size_t length)
{
	volatile unsigned char *cursor = data;

	while (length--)
		*cursor++ = 0;
}

/* Copies a dynamically resolved function address without aliasing violations. */
static void assign_symbol(void *destination, void *symbol)
{
	memcpy(destination, &symbol, sizeof(symbol));
}

/* Resolves the real libc calls wrapped by the worker network sandbox. */
static void load_libc_symbols(void)
{
	assign_symbol(&real_connect_fn, dlsym(RTLD_NEXT, "connect"));
	assign_symbol(&real_getaddrinfo_fn, dlsym(RTLD_NEXT, "getaddrinfo"));
	assign_symbol(&real_gethostbyname_fn, dlsym(RTLD_NEXT, "gethostbyname"));
}

/* Sends one bounded status packet from an authentication worker. */
static int send_worker_packet(uint8_t kind, uint8_t status, uint16_t reason,
							  const char *payload, size_t payload_length)
{
	struct worker_message message;
	size_t message_length;

	if (worker_result_fd < 0 || payload_length > sizeof(message.payload))
		return -1;

	memset(&message, 0, sizeof(message));
	message.magic = WORKER_MAGIC;
	message.kind = kind;
	message.status = status;
	message.reason = reason;
	message.payload_length = (uint32_t)payload_length;

	if (payload_length)
		memcpy(message.payload, payload, payload_length);

	message_length = offsetof(struct worker_message, payload) + payload_length;

	if (send(worker_result_fd, &message, message_length, MSG_NOSIGNAL) !=
		(ssize_t)message_length)
		return -1;

	secure_zero(&message, sizeof(message));
	return 0;
}

/* Reports a final worker result, clears secrets, and exits immediately. */
__attribute__((noreturn)) static void worker_finish(uint8_t status, uint16_t reason,
													const char *payload, size_t payload_length)
{
	(void)send_worker_packet(WORKER_MESSAGE_FINAL, status, reason,
							 payload, payload_length);

	secure_zero(&worker_auth, sizeof(worker_auth));
	secure_zero(configured_pins, sizeof(configured_pins));
	_exit(status == PKU_AUTH_STATUS_OK ? 0 : status);
}

/* Terminates the active worker with one sanitized permanent reason. */
__attribute__((noreturn)) static void worker_abort(uint16_t reason)
{
	worker_finish(PKU_AUTH_STATUS_PERMANENT, reason, NULL, 0);
}

/* Resolves one mandatory SDK symbol into typed function storage. */
static int load_required_symbol(void *handle, const char *name, void *target)
{
	void *symbol;
	dlerror();
	symbol = dlsym(handle, name);

	if (!symbol || dlerror())
		return -1;

	assign_symbol(target, symbol);
	return 0;
}

/* Reports whether an SSL object completed this worker's pin check. */
static int ssl_is_verified(SSL *ssl)
{
	size_t i;
	int found = 0;

	if (!ssl)
		return 0;

	if (pthread_mutex_lock(&verified_ssl_lock))
		return 0;

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (verified_ssl[i] == ssl)
		{
			found = 1;
			break;
		}
	}

	(void)pthread_mutex_unlock(&verified_ssl_lock);
	return found;
}

/* Adds a successfully pinned SSL object to the bounded allowlist. */
static int add_verified_ssl(SSL *ssl)
{
	size_t i;
	int result = -1;

	if (!ssl || pthread_mutex_lock(&verified_ssl_lock))
		return -1;

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (verified_ssl[i] == ssl)
		{
			result = 0;
			goto out;
		}
	}

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (!verified_ssl[i])
		{
			verified_ssl[i] = ssl;
			pinned_handshakes++;
			result = 0;
			break;
		}
	}

out:
	(void)pthread_mutex_unlock(&verified_ssl_lock);
	return result;
}

/* Reports whether any SDK TLS path has completed certificate pinning. */
static int has_pinned_handshake(void)
{
	int result;

	if (pthread_mutex_lock(&verified_ssl_lock))
		return 0;

	result = pinned_handshakes != 0;
	(void)pthread_mutex_unlock(&verified_ssl_lock);
	return result;
}

/* Removes an SSL object from the verified-object allowlist. */
static void remove_verified_ssl(SSL *ssl)
{
	size_t i;

	if (!ssl)
		return;

	if (pthread_mutex_lock(&verified_ssl_lock))
		return;

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (verified_ssl[i] == ssl)
			verified_ssl[i] = NULL;
	}

	(void)pthread_mutex_unlock(&verified_ssl_lock);
}

/* Reports whether a libisec network object completed certificate pinning. */
static int isec_network_is_verified(void *network)
{
	size_t i;
	int found = 0;

	if (!network)
		return 0;

	if (pthread_mutex_lock(&verified_ssl_lock))
		return 0;

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (verified_isec_network[i] == network)
		{
			found = 1;
			break;
		}
	}

	(void)pthread_mutex_unlock(&verified_ssl_lock);
	return found;
}

/* Adds a pinned libisec network object to the bounded allowlist. */
static int add_verified_isec_network(void *network)
{
	size_t i;
	int result = -1;

	if (!network || pthread_mutex_lock(&verified_ssl_lock))
		return -1;

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (verified_isec_network[i] == network)
		{
			result = 0;
			goto out;
		}
	}

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (!verified_isec_network[i])
		{
			verified_isec_network[i] = network;
			pinned_handshakes++;
			result = 0;
			break;
		}
	}

out:
	(void)pthread_mutex_unlock(&verified_ssl_lock);
	return result;
}

/* Removes a libisec network object from the verified-object allowlist. */
static void remove_verified_isec_network(void *network)
{
	size_t i;

	if (!network)
		return;

	if (pthread_mutex_lock(&verified_ssl_lock))
		return;

	for (i = 0; i < MAX_VERIFIED_SSL; i++)
	{
		if (verified_isec_network[i] == network)
			verified_isec_network[i] = NULL;
	}

	(void)pthread_mutex_unlock(&verified_ssl_lock);
}

/* Compares a certificate digest against every configured pin. */
static int digest_matches_pin(const unsigned char digest[32])
{
	size_t i;
	unsigned int any_match = 0;

	for (i = 0; i < configured_pin_count; i++)
	{
		unsigned int difference = 0;
		size_t j;

		for (j = 0; j < 32; j++)
			difference |= digest[j] ^ configured_pins[i][j];

		any_match |= (difference == 0);
	}

	return any_match != 0;
}

/* Verifies one peer SPKI with a selected library's X.509 entry points. */
static int verify_tls_peer_with(
	SSL *ssl, ssl_get_peer_certificate_fn get_peer_certificate,
	x509_get_pubkey_fn get_x509_pubkey,
	i2d_x509_pubkey_fn i2d_x509_pubkey, sha256_fn sha256,
	x509_free_fn x509_free)
{
	unsigned char digest[32];
	unsigned char *encoded = NULL;
	unsigned char *cursor;
	X509_PUBKEY *pubkey;
	X509 *certificate;
	int encoded_length = 0;
	int result = -1;

	if (!ssl || !get_peer_certificate || !get_x509_pubkey ||
		!i2d_x509_pubkey || !sha256 || !x509_free)
		return -1;

	certificate = get_peer_certificate(ssl);

	if (!certificate)
		return -1;

	pubkey = get_x509_pubkey(certificate);

	if (!pubkey)
		goto out;

	encoded_length = i2d_x509_pubkey(pubkey, NULL);

	if (encoded_length <= 0 || encoded_length > 16384)
		goto out;

	encoded = malloc((size_t)encoded_length);

	if (!encoded)
		goto out;

	cursor = encoded;

	if (i2d_x509_pubkey(pubkey, &cursor) != encoded_length ||
		cursor != encoded + encoded_length)
		goto out;

	if (!sha256(encoded, (size_t)encoded_length, digest))
		goto out;

	result = digest_matches_pin(digest) ? 0 : -1;

out:
	secure_zero(digest, sizeof(digest));

	if (encoded)
	{
		secure_zero(encoded, encoded_length > 0 ? (size_t)encoded_length : 0);
		free(encoded);
	}

	x509_free(certificate);
	return result;
}

/* Verifies the TLS peer created directly by libvl3vpn. */
static int verify_tls_peer(SSL *ssl)
{
	return verify_tls_peer_with(ssl, embedded_get_peer_certificate,
								embedded_get_x509_pubkey,
								embedded_i2d_x509_pubkey,
								embedded_sha256, embedded_x509_free);
}

/* Extracts and verifies the TLS peer stored in a libisec network object. */
static int verify_isec_tls_peer(void *network)
{
	SSL *ssl = NULL;

	if (!network)
		return -1;

	memcpy(&ssl, (const unsigned char *)network + ISEC_NET_SSL_OFFSET,
		   sizeof(ssl));

	return verify_tls_peer_with(ssl, isec_get_peer_certificate,
								isec_get_x509_pubkey,
								isec_i2d_x509_pubkey,
								isec_sha256, isec_x509_free);
}

/* Connects a libisec transport and authorizes it only after SPKI pinning. */
__attribute__((visibility("default"))) int isec_net_connect(void *network)
{
	int result;

	if (!worker_active || !embedded_isec_net_connect || !network)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	remove_verified_isec_network(network);
	result = embedded_isec_net_connect(network);

	if (result)
		return result;

	if (verify_isec_tls_peer(network) ||
		add_verified_isec_network(network))
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	return result;
}

/* Allows reads only through a previously verified libisec transport. */
__attribute__((visibility("default"))) int isec_net_read(void *network, void *buffer, uint32_t length, void *error)
{
	if (!worker_active || !embedded_isec_net_read)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	if (!isec_network_is_verified(network))
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	return embedded_isec_net_read(network, buffer, length, error);
}

/* Allows writes only through a previously verified libisec transport. */
__attribute__((visibility("default"))) int isec_net_write(void *network, const void *buffer, uint32_t length,
														  void *error)
{
	if (!worker_active || !embedded_isec_net_write)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	if (!isec_network_is_verified(network))
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	return embedded_isec_net_write(network, buffer, length, error);
}

/* Removes verification state before releasing a libisec transport. */
__attribute__((visibility("default"))) int isec_net_free(void *network)
{
	remove_verified_isec_network(network);

	if (!worker_active || !embedded_isec_net_free)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	return embedded_isec_net_free(network);
}

/* Generates fail-closed stubs for unsupported machine-authentication calls. */
#define DENY_ISEC_MAUTH(name)                                        \
	__attribute__((visibility("default"), noreturn)) void name(void) \
	{                                                                \
		worker_abort(PKU_AUTH_REASON_MAUTH);                         \
	}

DENY_ISEC_MAUTH(isec_mauth_new)
DENY_ISEC_MAUTH(isec_mauth_free)
DENY_ISEC_MAUTH(isec_mauth_cert_check_status)
DENY_ISEC_MAUTH(isec_mauth_cert_download)
DENY_ISEC_MAUTH(isec_mauth_device_register)
DENY_ISEC_MAUTH(isec_mauth_device_check_status)
#undef DENY_ISEC_MAUTH

/* Performs the embedded TLS handshake and pins its peer before use. */
__attribute__((visibility("default"))) int SSL_connect(SSL *ssl)
{
	int result;

	if (!worker_active || !embedded_ssl_connect)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	result = embedded_ssl_connect(ssl);

	if (result != 1)
		return result;

	if (verify_tls_peer(ssl) || add_verified_ssl(ssl))
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	return result;
}

/* Allows legacy TLS writes only on a verified SSL object. */
__attribute__((visibility("default"))) int SSL_write(SSL *ssl, const void *buffer, int length)
{
	if (!worker_active || !embedded_ssl_write || !ssl_is_verified(ssl))
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	return embedded_ssl_write(ssl, buffer, length);
}

/* Allows extended TLS writes only on a verified SSL object. */
__attribute__((visibility("default"))) int SSL_write_ex(SSL *ssl, const void *buffer, size_t length, size_t *written)
{
	if (!worker_active || !embedded_ssl_write_ex || !ssl_is_verified(ssl))
	{
		if (written)
			*written = 0;

		worker_abort(PKU_AUTH_REASON_CERTIFICATE);
	}

	return embedded_ssl_write_ex(ssl, buffer, length, written);
}

/* Drops verification state before forwarding an SSL object release. */
__attribute__((visibility("default"))) void SSL_free(SSL *ssl)
{
	remove_verified_ssl(ssl);

	if (!worker_active || !embedded_ssl_free)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	embedded_ssl_free(ssl);
}

/* Drops verification state before resetting an SSL object. */
__attribute__((visibility("default"))) int SSL_clear(SSL *ssl)
{
	remove_verified_ssl(ssl);

	if (!worker_active || !embedded_ssl_clear)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	return embedded_ssl_clear(ssl);
}

/* Restricts worker name resolution to the selected Array gateway address. */
__attribute__((visibility("default"))) int getaddrinfo(const char *node, const char *service,
													   const struct addrinfo *hints, struct addrinfo **result)
{
	struct addrinfo numeric_hints;
	(void)pthread_once(&libc_symbols_once, load_libc_symbols);

	if (!real_getaddrinfo_fn)
		return EAI_SYSTEM;

	if (!worker_active)
		return real_getaddrinfo_fn(node, service, hints, result);

	if (!node || (strcmp(node, ARRAY_GATEWAY_HOST) &&
				  strcmp(node, worker_candidate_text)))
		return EAI_NONAME;

	if (hints)
		numeric_hints = *hints;
	else
		memset(&numeric_hints, 0, sizeof(numeric_hints));

	if (numeric_hints.ai_family == AF_INET6)
		return EAI_NONAME;

	numeric_hints.ai_family = AF_INET;
	numeric_hints.ai_flags |= AI_NUMERICHOST;
	return real_getaddrinfo_fn(worker_candidate_text, service,
							   &numeric_hints, result);
}

/* Restricts legacy worker name resolution to the selected gateway address. */
__attribute__((visibility("default"))) struct hostent *gethostbyname(const char *name)
{
	(void)pthread_once(&libc_symbols_once, load_libc_symbols);

	if (!real_gethostbyname_fn)
	{
		h_errno = NO_RECOVERY;
		return NULL;
	}

	if (!worker_active)
		return real_gethostbyname_fn(name);

	if (!name || (strcmp(name, ARRAY_GATEWAY_HOST) &&
				  strcmp(name, worker_candidate_text)))
	{
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}

	return real_gethostbyname_fn(worker_candidate_text);
}

/* Restricts worker TCP connections to the selected gateway on port 443. */
__attribute__((visibility("default"))) int connect(int fd, __CONST_SOCKADDR_ARG address_argument,
												   socklen_t address_length)
{
	const struct sockaddr *address = address_argument.__sockaddr__;
	const struct sockaddr_in *ipv4;
	(void)pthread_once(&libc_symbols_once, load_libc_symbols);

	if (!real_connect_fn)
	{
		errno = ENOSYS;
		return -1;
	}

	if (!worker_active)
		return real_connect_fn(fd, address_argument, address_length);

	if (!address || address_length < sizeof(*ipv4) ||
		address->sa_family != AF_INET)
	{
		errno = EACCES;
		return -1;
	}

	ipv4 = (const struct sockaddr_in *)address;

	if (ipv4->sin_port != htons(ARRAY_GATEWAY_PORT) ||
		ipv4->sin_addr.s_addr != worker_candidate.s_addr)
	{
		errno = EACCES;
		return -1;
	}

	return real_connect_fn(fd, address_argument, address_length);
}

/* Converts one standard Base64 character to its six-bit value. */
static int base64_value(unsigned char character)
{
	if (character >= 'A' && character <= 'Z')
		return character - 'A';

	if (character >= 'a' && character <= 'z')
		return character - 'a' + 26;

	if (character >= '0' && character <= '9')
		return character - '0' + 52;

	if (character == '+')
		return 62;

	if (character == '/')
		return 63;

	return -1;
}

/* Decodes one canonical SHA-256 pin payload into exactly 32 bytes. */
static int decode_pin(const char *encoded, unsigned char output[32])
{
	uint32_t accumulator = 0;
	unsigned int bits = 0;
	size_t output_length = 0;
	size_t i;

	if (strlen(encoded) != 44 || encoded[43] != '=')
		return -1;

	for (i = 0; i < 43; i++)
	{
		int value = base64_value((unsigned char)encoded[i]);

		if (value < 0)
			return -1;

		accumulator = (accumulator << 6) | (uint32_t)value;
		bits += 6;

		while (bits >= 8)
		{
			bits -= 8;

			if (output_length >= 32)
				return -1;

			output[output_length++] =
				(unsigned char)(accumulator >> bits);

			if (bits)
				accumulator &= (1U << bits) - 1U;
			else
				accumulator = 0;
		}
	}

	if (output_length != 32 || bits != 2 || accumulator)
		return -1;

	return 0;
}

/* Reads one non-symlink regular file into a bounded NUL-terminated buffer. */
static int read_regular_file(const char *path, char *buffer, size_t capacity,
							 size_t *length)
{
	struct stat metadata;
	size_t received = 0;
	int fd;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

	if (fd < 0)
		return -1;

	if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) ||
		metadata.st_size < 0 || (uintmax_t)metadata.st_size >= capacity)
	{
		close(fd);
		return -1;
	}

	while (received < (size_t)metadata.st_size)
	{
		ssize_t chunk = read(fd, buffer + received,
							 (size_t)metadata.st_size - received);

		if (chunk < 0 && errno == EINTR)
			continue;

		if (chunk <= 0)
		{
			close(fd);
			return -1;
		}

		received += (size_t)chunk;
	}

	if (read(fd, buffer + received, 1) != 0)
	{
		close(fd);
		return -1;
	}

	close(fd);
	buffer[received] = 0;
	*length = received;
	return 0;
}

/* Loads and validates the bounded SPKI allowlist for this worker. */
static void load_pins(void)
{
	char file_data[2048];
	size_t file_length;
	char *cursor;

	if (read_regular_file(PIN_FILE_PATH, file_data, sizeof(file_data),
						  &file_length))
		worker_abort(PKU_AUTH_REASON_CONFIG);

	configured_pin_count = 0;
	cursor = file_data;

	while ((size_t)(cursor - file_data) < file_length)
	{
		char *newline = memchr(cursor, '\n',
							   file_length - (size_t)(cursor - file_data));

		size_t line_length = newline ? (size_t)(newline - cursor) : file_length - (size_t)(cursor - file_data);

		if (line_length && cursor[line_length - 1] == '\r')
			worker_abort(PKU_AUTH_REASON_CONFIG);

		if (line_length)
		{
			if (line_length != 55 ||
				memcmp(cursor, "pin-sha256:", 11) ||
				configured_pin_count >= MAX_PINS)
			{
				worker_abort(PKU_AUTH_REASON_CONFIG);
			}

			cursor[line_length] = 0;

			if (decode_pin(cursor + 11,
						   configured_pins[configured_pin_count]))
				worker_abort(PKU_AUTH_REASON_CONFIG);

			configured_pin_count++;
		}

		if (!newline)
			break;

		cursor = newline + 1;
	}

	secure_zero(file_data, sizeof(file_data));

	if (!configured_pin_count)
		worker_abort(PKU_AUTH_REASON_CONFIG);
}

/* Loads one owner-only secret file with exact length bounds. */
static void load_secret(const char *name, char *destination,
						size_t capacity, size_t minimum, size_t maximum)
{
	char path[128];
	struct stat metadata;
	size_t length;
	size_t i;
	int fd;

	if (snprintf(path, sizeof(path), "%s/%s", SECRET_DIRECTORY, name) >=
		(int)sizeof(path))
		worker_abort(PKU_AUTH_REASON_SECRET);

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

	if (fd < 0 || fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) ||
		metadata.st_uid != geteuid() || (metadata.st_mode & 0077) ||
		metadata.st_size < (off_t)minimum ||
		metadata.st_size > (off_t)maximum ||
		metadata.st_size >= (off_t)capacity)
	{
		if (fd >= 0)
			close(fd);

		worker_abort(PKU_AUTH_REASON_SECRET);
	}

	length = (size_t)metadata.st_size;

	{
		size_t received = 0;

		while (received < length)
		{
			ssize_t chunk = read(fd, destination + received,
								 length - received);

			if (chunk < 0 && errno == EINTR)
				continue;

			if (chunk <= 0)
			{
				close(fd);
				worker_abort(PKU_AUTH_REASON_SECRET);
			}

			received += (size_t)chunk;
		}

		if (read(fd, destination + length, 1) != 0)
		{
			close(fd);
			worker_abort(PKU_AUTH_REASON_SECRET);
		}
	}

	close(fd);
	destination[length] = 0;

	for (i = 0; i < length; i++)
	{
		if (!destination[i] || destination[i] == '\n' ||
			destination[i] == '\r')
			worker_abort(PKU_AUTH_REASON_SECRET);
	}
}

/* Loads, validates, and locks all credentials required by the SDK. */
static void load_secrets(void)
{
	size_t i;

	load_secret("vpn_username", worker_auth.username,
				sizeof(worker_auth.username), 1, 256);

	load_secret("vpn_password", worker_auth.password,
				sizeof(worker_auth.password), 1, 4096);

	load_secret("id_card_last6", worker_auth.id_card_last6,
				sizeof(worker_auth.id_card_last6), 6, 6);

	load_secret("phone_missing4", worker_auth.phone_missing4,
				sizeof(worker_auth.phone_missing4), 4, 4);

	for (i = 0; i < 5; i++)
	{
		if (worker_auth.id_card_last6[i] < '0' ||
			worker_auth.id_card_last6[i] > '9')
			worker_abort(PKU_AUTH_REASON_SECRET);
	}

	if (!((worker_auth.id_card_last6[5] >= '0' &&
		   worker_auth.id_card_last6[5] <= '9') ||
		  worker_auth.id_card_last6[5] == 'X' ||
		  worker_auth.id_card_last6[5] == 'x'))
		worker_abort(PKU_AUTH_REASON_SECRET);

	for (i = 0; i < 4; i++)
	{
		if (worker_auth.phone_missing4[i] < '0' ||
			worker_auth.phone_missing4[i] > '9')
			worker_abort(PKU_AUTH_REASON_SECRET);
	}

	(void)mlock(&worker_auth, sizeof(worker_auth));
}

/* Copies one fixed-width SDK field into a checked C string. */
static int field_to_string(const char *field, size_t field_size,
						   char *output, size_t output_size)
{
	size_t length = strnlen(field, field_size);

	if (length == field_size || length >= output_size)
		return -1;

	memcpy(output, field, length);
	output[length] = 0;
	return 0;
}

/* Classifies a server prompt without guessing from ambiguous text. */
static enum challenge_kind classify_prompt(const char *prompt)
{
	int id_card;
	int phone;
	int phone_context;

	if (!prompt || !*prompt)
		return CHALLENGE_NONE;

	id_card = strstr(prompt, "身份证") &&
			  (strstr(prompt, "后6位") || strstr(prompt, "后 6 位") ||
			   strstr(prompt, "后六位") || strstr(prompt, "后６位") ||
			   strstr(prompt, "末6位") || strstr(prompt, "末六位") ||
			   strstr(prompt, "最后6位") || strstr(prompt, "最后六位"));

	phone_context = strstr(prompt, "电话") || strstr(prompt, "手机");

	phone = phone_context &&
			(strstr(prompt, "缺位") || strstr(prompt, "缺失") ||
			 strstr(prompt, "第4到7位") || strstr(prompt, "第 4 到 7 位") ||
			 strstr(prompt, "第４到７位") || strstr(prompt, "四位") ||
			 strstr(prompt, "4位") || strstr(prompt, "4 位"));

	if (id_card && phone)
		return CHALLENGE_AMBIGUOUS;

	if (id_card)
		return CHALLENGE_ID_CARD;

	if (phone)
		return CHALLENGE_PHONE;

	return CHALLENGE_NONE;
}

/* Copies one validated credential into a bounded SDK destination. */
static void copy_credential(char *destination, size_t capacity,
							const char *source)
{
	size_t length = strlen(source);

	if (length >= capacity)
		worker_abort(PKU_AUTH_REASON_SECRET);

	memcpy(destination, source, length + 1);
}

/* Classifies one declared SDK step using its canonical prompt field. */
static enum challenge_kind classify_multi_step(
	const isecsp_multi_method *step)
{
	char server[514];
	char description[514];
	enum challenge_kind kind;

	if (field_to_string(step->server, sizeof(step->server),
						server, sizeof(server)))
		worker_abort(PKU_AUTH_REASON_METHOD_STEPS);

	kind = classify_prompt(server);

	if (*server)
	{
		secure_zero(server, sizeof(server));
		return kind;
	}

	secure_zero(server, sizeof(server));

	/* The locked official client reads server only. Accept description as a
	 * compatibility fallback solely when that canonical field is empty; an
	 * unknown nonempty server prompt must never be guessed from hidden data. */
	if (field_to_string(step->description, sizeof(step->description),
						description, sizeof(description)))
		worker_abort(PKU_AUTH_REASON_METHOD_STEPS);

	kind = classify_prompt(description);
	secure_zero(description, sizeof(description));
	return kind;
}

/* Records at most two unique, recognized supplemental authentication steps. */
static void record_expected_steps(const isecsp_auth_method *method)
{
	unsigned int i;

	if (method->multi_step_count > 2)
		worker_abort(PKU_AUTH_REASON_METHOD_STEPS);

	worker_auth.expected_count = 0;

	for (i = 0; i < method->multi_step_count; i++)
	{
		enum challenge_kind kind =
			classify_multi_step(&method->multi_steps[i]);

		if (kind == CHALLENGE_NONE || kind == CHALLENGE_AMBIGUOUS)
			worker_abort(PKU_AUTH_REASON_METHOD_STEPS);

		if (i && worker_auth.expected[i - 1] == kind)
			worker_abort(PKU_AUTH_REASON_METHOD_STEPS);

		worker_auth.expected[i] = kind;
		worker_auth.expected_count++;
	}
}

/* Places declared supplemental secrets in the SDK's ordered input fields. */
static void populate_declared_credentials(isecsp_auth_input *auth)
{
	unsigned int i;

	/* Command 13 consumes declared step inputs up front. The SDK still owns
	 * the sequential RADIUS exchange; this helper never sends them itself. */
	for (i = 0; i < worker_auth.expected_count; i++)
	{
		char *destination = i ? auth->password3 : auth->password2;
		size_t capacity = i ? sizeof(auth->password3) : sizeof(auth->password2);

		if (worker_auth.expected[i] == CHALLENGE_ID_CARD)
		{
			copy_credential(destination, capacity,
							worker_auth.id_card_last6);

			worker_auth.id_card_submitted = true;
		}
		else if (worker_auth.expected[i] == CHALLENGE_PHONE)
		{
			copy_credential(destination, capacity,
							worker_auth.phone_missing4);

			worker_auth.phone_submitted = true;
		}
		else
		{
			worker_abort(PKU_AUTH_REASON_METHOD_STEPS);
		}

		worker_auth.supplemental_count++;
	}
}

/* Validates method metadata and supplies the single primary login response. */
static void handle_initial_login(int error, const void *input,
								 uint32_t input_length, void *output,
								 uint32_t *output_length)
{
	const isecsp_auth_info *info = input;
	isecsp_auth_input *auth = output;
	const isecsp_auth_method *selected = NULL;
	unsigned int selected_count = 0;
	unsigned int i;

	if (error)
		worker_abort(PKU_AUTH_REASON_METHOD_CALLBACK_ERROR);

	if (!input)
		worker_abort(PKU_AUTH_REASON_METHOD_INPUT_NULL);

	if (input_length != sizeof(*info))
		worker_abort(PKU_AUTH_REASON_METHOD_INPUT_LENGTH);

	if (!output)
		worker_abort(PKU_AUTH_REASON_METHOD_OUTPUT_NULL);

	if (!output_length)
		worker_abort(PKU_AUTH_REASON_METHOD_OUTPUT_LENGTH_NULL);

	if (*output_length < sizeof(*auth))
		worker_abort(PKU_AUTH_REASON_METHOD_OUTPUT_CAPACITY);

	if (!info->method_count || info->method_count > 10)
		worker_abort(PKU_AUTH_REASON_METHOD_COUNT);

	if (worker_auth.primary_submitted)
		worker_abort(PKU_AUTH_REASON_METHOD_SEQUENCE);

	if (!has_pinned_handshake())
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	for (i = 0; i < info->method_count; i++)
	{
		char method_name[514];

		if (field_to_string(info->methods[i].name,
							sizeof(info->methods[i].name),
							method_name, sizeof(method_name)))
			worker_abort(PKU_AUTH_REASON_METHOD_NAME);

		if (!strcmp(method_name, AUTH_METHOD_NAME))
		{
			selected = &info->methods[i];
			selected_count++;
		}

		secure_zero(method_name, sizeof(method_name));
	}

	if (!selected_count && info->method_count == 1 &&
		info->methods[0].type == AUTH_METHOD_RADIUS)
	{
		selected = &info->methods[0];
		selected_count = 1;
	}

	if (selected_count != 1)
		worker_abort(PKU_AUTH_REASON_METHOD_SELECTION);

	record_expected_steps(selected);
	memset(auth, 0, sizeof(*auth));

	if (field_to_string(selected->name, sizeof(selected->name),
						auth->method, sizeof(auth->method)) ||
		!auth->method[0])
		worker_abort(PKU_AUTH_REASON_METHOD_SELECTION);

	copy_credential(auth->username, sizeof(auth->username),
					worker_auth.username);

	copy_credential(auth->password, sizeof(auth->password),
					worker_auth.password);

	populate_declared_credentials(auth);
	*output_length = sizeof(*auth);
	worker_auth.primary_submitted = true;

	if (send_worker_packet(WORKER_MESSAGE_PRIMARY, 0, 0, NULL, 0))
		worker_abort(PKU_AUTH_REASON_INTERNAL);
}

/* Classifies the two bounded text fields in a runtime challenge. */
static enum challenge_kind classify_challenge_info(
	const isecsp_challenge_info *challenge)
{
	char information[257];
	char error_message[257];
	enum challenge_kind first;
	enum challenge_kind second;

	if (field_to_string(challenge->information,
						sizeof(challenge->information),
						information, sizeof(information)) ||
		field_to_string(challenge->error_message,
						sizeof(challenge->error_message),
						error_message, sizeof(error_message)))
		return CHALLENGE_AMBIGUOUS;

	first = classify_prompt(information);
	second = classify_prompt(error_message);
	secure_zero(information, sizeof(information));
	secure_zero(error_message, sizeof(error_message));

	if (first == CHALLENGE_AMBIGUOUS || second == CHALLENGE_AMBIGUOUS ||
		(first != CHALLENGE_NONE && second != CHALLENGE_NONE && first != second))
		return CHALLENGE_AMBIGUOUS;

	return first != CHALLENGE_NONE ? first : second;
}

/* Answers one recognized, non-repeated supplemental challenge. */
static void handle_challenge(int error, const void *input,
							 uint32_t input_length, void *output,
							 uint32_t *output_length)
{
	const isecsp_challenge_info *challenge = input;
	isecsp_auth_input *auth = output;
	enum challenge_kind kind;

	if (error || !input || input_length != sizeof(*challenge) || !output ||
		!output_length || *output_length < sizeof(*auth) ||
		!worker_auth.primary_submitted)
		worker_abort(PKU_AUTH_REASON_UNKNOWN_CHALLENGE);

	kind = classify_challenge_info(challenge);

	if (kind == CHALLENGE_NONE || kind == CHALLENGE_AMBIGUOUS)
		worker_abort(PKU_AUTH_REASON_UNKNOWN_CHALLENGE);

	if ((kind == CHALLENGE_ID_CARD && worker_auth.id_card_submitted) ||
		(kind == CHALLENGE_PHONE && worker_auth.phone_submitted))
		worker_abort(PKU_AUTH_REASON_REPEATED_CHALLENGE);

	if (worker_auth.supplemental_count >= 2)
		worker_abort(PKU_AUTH_REASON_UNKNOWN_CHALLENGE);

	if (worker_auth.expected_count &&
		(worker_auth.supplemental_count >= worker_auth.expected_count ||
		 worker_auth.expected[worker_auth.supplemental_count] != kind))
		worker_abort(PKU_AUTH_REASON_UNKNOWN_CHALLENGE);

	memset(auth, 0, sizeof(*auth));

	if (kind == CHALLENGE_ID_CARD)
	{
		copy_credential(auth->password, sizeof(auth->password),
						worker_auth.id_card_last6);
		worker_auth.id_card_submitted = true;
	}
	else
	{
		copy_credential(auth->password, sizeof(auth->password),
						worker_auth.phone_missing4);
		worker_auth.phone_submitted = true;
	}

	worker_auth.supplemental_count++;
	*output_length = sizeof(*auth);
}

/* Retrieves, validates, and returns the authenticated ANsession cookie. */
__attribute__((noreturn)) static void finish_authenticated_session(void)
{
	char session[SDK_SESSION_SIZE];
	char selected_cookie[PKU_AUTH_COOKIE_MAX + 1];
	size_t selected_length = 0;
	memset(session, 0, sizeof(session));
	memset(selected_cookie, 0, sizeof(selected_cookie));

	if (!embedded_get_cookies ||
		embedded_get_cookies(session, sizeof(session)))
		worker_abort(PKU_AUTH_REASON_COOKIE);

	if (!has_pinned_handshake())
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	if (select_session_cookie(session, selected_cookie,
							  sizeof(selected_cookie), &selected_length))
		worker_abort(PKU_AUTH_REASON_COOKIE);

	secure_zero(session, sizeof(session));

	worker_finish(PKU_AUTH_STATUS_OK, PKU_AUTH_REASON_NONE,
				  selected_cookie, selected_length);
}

/* Dispatches the bounded subset of SDK callbacks used by PKU authentication. */
static int sdk_callback(int command, int error, const void *input,
						uint32_t input_length, void *output,
						uint32_t *output_length)
{
	switch (command)
	{
	case 3:
		if (error || !worker_auth.primary_submitted)
			worker_abort(error ? PKU_AUTH_REASON_AUTH_REJECTED : PKU_AUTH_REASON_METHOD_SEQUENCE);

		if (worker_auth.expected_count &&
			worker_auth.supplemental_count != worker_auth.expected_count)
			worker_abort(PKU_AUTH_REASON_METHOD_SEQUENCE);

		worker_auth.connected = true;
		finish_authenticated_session();
	case 13:
		handle_initial_login(error, input, input_length, output, output_length);
		break;
	case 15:
		handle_challenge(error, input, input_length, output, output_length);
		break;
	case 19:
		worker_abort(PKU_AUTH_REASON_UNKNOWN_CHALLENGE);
	default:
		break;
	}

	return 0;
}

/* Validates an ANsession value without interpreting it as structured data. */
static int cookie_value_valid(const char *value, size_t length)
{
	size_t i;

	if (!length || length > PKU_AUTH_COOKIE_MAX ||
		(length == 4 && !strncasecmp(value, "null", 4)) ||
		(length == 9 && !strncasecmp(value, "undefined", 9)) ||
		(length == 7 && !strncasecmp(value, "deleted", 7)) ||
		(length == 11 && !strncasecmp(value, "placeholder", 11)))
		return 0;

	for (i = 0; i < length; i++)
	{
		unsigned char c = (unsigned char)value[i];

		if (c <= 0x20 || c == 0x7f || c == ';')
			return 0;
	}

	return 1;
}

/* Validates one cookie name against the sidecar's restricted character set. */
static int cookie_name_valid(const char *name, size_t length)
{
	size_t i;

	if (!length || length > 64)
		return 0;

	for (i = 0; i < length; i++)
	{
		unsigned char c = (unsigned char)name[i];

		if (!((c >= 'a' && c <= 'z') ||
			  (c >= 'A' && c <= 'Z') ||
			  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
			return 0;
	}

	return 1;
}

/* Selects exactly one live ANsession assignment from an SDK cookie string. */
static int select_session_cookie(char *session, char *selected,
								 size_t selected_size, size_t *selected_length)
{
	char *cursor = session;
	unsigned int matches = 0;

	if (!strncmp(cursor, "Cookie:", 7))
	{
		cursor += 7;

		while (*cursor == ' ' || *cursor == '\t')
			cursor++;
	}

	for (char *scan = cursor; *scan; scan++)
	{
		unsigned char c = (unsigned char)*scan;

		if ((c < 0x20 && c != '\t') || c == 0x7f)
			return -1;
	}

	while (*cursor)
	{
		char *segment_end = strchr(cursor, ';');
		char *equals;
		char *name_start;
		char *name_end;
		char *value_start;
		char *value_end;
		size_t name_length;
		size_t value_length;

		if (!segment_end)
			segment_end = cursor + strlen(cursor);

		name_start = cursor;

		while (name_start < segment_end &&
			   (*name_start == ' ' || *name_start == '\t'))
			name_start++;

		value_end = segment_end;

		while (value_end > name_start &&
			   (value_end[-1] == ' ' || value_end[-1] == '\t'))
			value_end--;

		if (value_end == name_start)
			goto next;

		equals = memchr(name_start, '=', (size_t)(value_end - name_start));

		if (!equals)
			return -1;

		name_end = equals;

		while (name_end > name_start &&
			   (name_end[-1] == ' ' || name_end[-1] == '\t'))
			name_end--;

		value_start = equals + 1;

		while (value_start < value_end &&
			   (*value_start == ' ' || *value_start == '\t'))
			value_start++;

		name_length = (size_t)(name_end - name_start);
		value_length = (size_t)(value_end - value_start);

		if (!cookie_name_valid(name_start, name_length))
			return -1;

		if (name_length >= 9 && !memcmp(name_start, "ANsession", 9))
		{
			size_t total_length = name_length + 1 + value_length;

			if (!cookie_value_valid(value_start, value_length) ||
				total_length >= selected_size)
				return -1;

			matches++;
			memcpy(selected, name_start, name_length);
			selected[name_length] = '=';
			memcpy(selected + name_length + 1, value_start, value_length);
			selected[total_length] = 0;
			*selected_length = total_length;
		}

	next:
		if (!*segment_end)
			break;

		cursor = segment_end + 1;
	}

	return matches == 1 ? 0 : -1;
}

/* Redirects proprietary SDK output so credentials cannot reach container logs. */
static void redirect_worker_output(void)
{
	int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);

	if (null_fd < 0)
		worker_abort(PKU_AUTH_REASON_INTERNAL);

	if (dup2(null_fd, STDOUT_FILENO) < 0 ||
		dup2(null_fd, STDERR_FILENO) < 0)
	{
		close(null_fd);
		worker_abort(PKU_AUTH_REASON_INTERNAL);
	}

	if (null_fd > STDERR_FILENO)
		close(null_fd);
}

/* Confirms that a resolved function belongs to the expected shared object. */
static int loaded_symbol_is_from(void *function_storage, const char *library)
{
	Dl_info symbol_info;
	void *address = NULL;

	memcpy(&address, function_storage, sizeof(address));
	return address && dladdr(address, &symbol_info) && symbol_info.dli_fname &&
		   strstr(symbol_info.dli_fname, library);
}

#ifndef ISEC_TEST_DYNAMIC_TLS_SYMBOLS
/* Resolves one audited private libisec entry point from its locked offset. */
static int load_isec_offset_symbol(struct link_map *map, uintptr_t offset,
								   void *target)
{
	Dl_info symbol_info;
	uintptr_t base;
	void *address;

	if (!map || !map->l_name || !strstr(map->l_name, "libisec.so"))
		return -1;

	base = (uintptr_t)map->l_addr;

	if (offset > UINTPTR_MAX - base)
		return -1;

	address = (void *)(base + offset);

	if (!dladdr(address, &symbol_info) || !symbol_info.dli_fname ||
		!strstr(symbol_info.dli_fname, "libisec.so") ||
		(uintptr_t)symbol_info.dli_fbase != base)
		return -1;

	assign_symbol(target, address);
	return 0;
}
#endif

/* Loads the transport and certificate functions from the locked libisec. */
static void load_isec_symbols(void *handle)
{
#ifndef ISEC_TEST_DYNAMIC_TLS_SYMBOLS
	struct link_map *map = NULL;
#endif

	if (load_required_symbol(handle, "isec_net_connect",
							 &embedded_isec_net_connect) ||
		load_required_symbol(handle, "isec_net_read",
							 &embedded_isec_net_read) ||
		load_required_symbol(handle, "isec_net_write",
							 &embedded_isec_net_write) ||
		load_required_symbol(handle, "isec_net_free",
							 &embedded_isec_net_free) ||
		!loaded_symbol_is_from(&embedded_isec_net_connect, "libisec.so") ||
		!loaded_symbol_is_from(&embedded_isec_net_read, "libisec.so") ||
		!loaded_symbol_is_from(&embedded_isec_net_write, "libisec.so") ||
		!loaded_symbol_is_from(&embedded_isec_net_free, "libisec.so"))
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

#ifdef ISEC_TEST_DYNAMIC_TLS_SYMBOLS
	if (load_required_symbol(handle, "SSL_get_peer_certificate",
							 &isec_get_peer_certificate) ||
		load_required_symbol(handle, "X509_get_X509_PUBKEY",
							 &isec_get_x509_pubkey) ||
		load_required_symbol(handle, "i2d_X509_PUBKEY",
							 &isec_i2d_x509_pubkey) ||
		load_required_symbol(handle, "SHA256", &isec_sha256) ||
		load_required_symbol(handle, "X509_free", &isec_x509_free))
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);
#else
	if (dlinfo(handle, RTLD_DI_LINKMAP, &map) || !map ||
		load_isec_offset_symbol(map,
								ISEC_SSL_GET_PEER_CERTIFICATE_OFFSET,
								&isec_get_peer_certificate) ||
		load_isec_offset_symbol(map, ISEC_X509_GET_X509_PUBKEY_OFFSET,
								&isec_get_x509_pubkey) ||
		load_isec_offset_symbol(map, ISEC_I2D_X509_PUBKEY_OFFSET,
								&isec_i2d_x509_pubkey) ||
		load_isec_offset_symbol(map, ISEC_SHA256_OFFSET, &isec_sha256) ||
		load_isec_offset_symbol(map, ISEC_X509_FREE_OFFSET,
								&isec_x509_free))
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);
#endif
}

/* Loads the required session and TLS functions from the locked libvl3vpn. */
static void load_sdk_symbols(void *handle, isecsp_get_session_fn *get_session,
							 array_log_level_fn *set_log_level)
{
	Dl_info symbol_info;
	void *embedded_connect_address;
	void *wrapper_connect_address;

	if (load_required_symbol(handle, "isecsp_get_session", get_session) ||
		load_required_symbol(handle, "array_vpn_get_cookies",
							 &embedded_get_cookies) ||
		load_required_symbol(handle, "array_vpn_set_log_level", set_log_level) ||
		load_required_symbol(handle, "SSL_connect", &embedded_ssl_connect) ||
		load_required_symbol(handle, "SSL_write", &embedded_ssl_write) ||
		load_required_symbol(handle, "SSL_write_ex", &embedded_ssl_write_ex) ||
		load_required_symbol(handle, "SSL_free", &embedded_ssl_free) ||
		load_required_symbol(handle, "SSL_clear", &embedded_ssl_clear) ||
		load_required_symbol(handle, "SSL_get_peer_certificate",
							 &embedded_get_peer_certificate) ||
		load_required_symbol(handle, "X509_get_X509_PUBKEY",
							 &embedded_get_x509_pubkey) ||
		load_required_symbol(handle, "i2d_X509_PUBKEY",
							 &embedded_i2d_x509_pubkey) ||
		load_required_symbol(handle, "SHA256", &embedded_sha256) ||
		load_required_symbol(handle, "X509_free", &embedded_x509_free) ||
		!loaded_symbol_is_from(&embedded_get_cookies, "libvl3vpn.so"))
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	memcpy(&embedded_connect_address, &embedded_ssl_connect,
		   sizeof(embedded_connect_address));

	wrapper_connect_address = dlsym(RTLD_DEFAULT, "SSL_connect");

	if (!wrapper_connect_address ||
		embedded_connect_address == wrapper_connect_address ||
		!dladdr(embedded_connect_address, &symbol_info) ||
		!symbol_info.dli_fname ||
		!strstr(symbol_info.dli_fname, "libvl3vpn.so"))
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);
}

/* Executes one isolated SDK authentication attempt for a selected gateway. */
__attribute__((noreturn)) static void run_worker(int result_fd, struct in_addr candidate)
{
	isecsp_get_session_fn get_session = NULL;
	array_log_level_fn set_log_level = NULL;
	isecsp_user_parameter user;
	char session[SDK_SESSION_SIZE];
	char return_value[SDK_RETURN_SIZE];
	char selected_cookie[PKU_AUTH_COOKIE_MAX + 1];
	size_t selected_length = 0;
	void *isec_library;
	void *library;
	int result;
	worker_result_fd = result_fd;
	worker_candidate = candidate;

	if (!inet_ntop(AF_INET, &candidate, worker_candidate_text,
				   sizeof(worker_candidate_text)))
		worker_abort(PKU_AUTH_REASON_BAD_REQUEST);

	redirect_worker_output();
	load_secrets();
	load_pins();
	(void)pthread_once(&libc_symbols_once, load_libc_symbols);

	if (!real_connect_fn || !real_getaddrinfo_fn || !real_gethostbyname_fn)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	worker_active = true;
	isec_library = dlopen(ISEC_LIBRARY_PATH, RTLD_NOW | RTLD_GLOBAL);

	if (!isec_library)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	load_isec_symbols(isec_library);
	library = dlopen(ISECSP_LIBRARY_PATH, RTLD_NOW | RTLD_LOCAL);

	if (!library)
		worker_abort(PKU_AUTH_REASON_SDK_INCOMPATIBLE);

	load_sdk_symbols(library, &get_session, &set_log_level);
	set_log_level(INT_MAX, 0);
	memset(&user, 0, sizeof(user));
	memset(session, 0, sizeof(session));
	memset(return_value, 0, sizeof(return_value));
	memset(selected_cookie, 0, sizeof(selected_cookie));
	memcpy(user.host, ARRAY_GATEWAY_HOST, sizeof(ARRAY_GATEWAY_HOST));
	user.port = ARRAY_GATEWAY_PORT;
	user.callback = sdk_callback;

	result = get_session(user, session, sizeof(session) - 1,
						 return_value, sizeof(return_value) - 1);

	(void)result;

	if (!worker_auth.connected || !worker_auth.primary_submitted)
	{
		if (worker_auth.primary_submitted)
			worker_abort(PKU_AUTH_REASON_AUTH_REJECTED);

		worker_finish(PKU_AUTH_STATUS_TRANSIENT, PKU_AUTH_REASON_NETWORK,
					  NULL, 0);
	}

	if (!has_pinned_handshake())
		worker_abort(PKU_AUTH_REASON_CERTIFICATE);

	if (select_session_cookie(session, selected_cookie,
							  sizeof(selected_cookie), &selected_length))
		worker_abort(PKU_AUTH_REASON_COOKIE);

	secure_zero(session, sizeof(session));
	secure_zero(return_value, sizeof(return_value));
	worker_finish(PKU_AUTH_STATUS_OK, PKU_AUTH_REASON_NONE,
				  selected_cookie, selected_length);
}

/* Reads an exact IPC buffer while retrying interrupted system calls. */
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

/* Sends an exact IPC buffer while retrying interrupted system calls. */
static int write_all(int fd, const void *data, size_t length)
{
	const unsigned char *cursor = data;

	while (length)
	{
		ssize_t written = send(fd, cursor, length, MSG_NOSIGNAL);

		if (written < 0 && errno == EINTR)
			continue;

		if (written <= 0)
			return -1;

		cursor += (size_t)written;
		length -= (size_t)written;
	}

	return 0;
}

/* Sends one validated response header and optional bounded cookie payload. */
static int send_response(int fd, uint8_t status, uint16_t reason,
						 const char *payload, size_t payload_length)
{
	struct pku_auth_response response;

	if (payload_length > PKU_AUTH_COOKIE_MAX)
		return -1;

	memset(&response, 0, sizeof(response));
	memcpy(response.magic, PKU_AUTH_MAGIC, PKU_AUTH_MAGIC_LEN);
	response.version = PKU_AUTH_VERSION;
	response.status = status;
	response.reason = htons(reason);
	response.payload_length = htonl((uint32_t)payload_length);

	if (write_all(fd, &response, sizeof(response)))
		return -1;

	if (payload_length && write_all(fd, payload, payload_length))
		return -1;

	return 0;
}

/* Rejects non-routable, documentation, multicast, and fake-IP candidates. */
static int public_candidate(struct in_addr candidate)
{
	uint32_t address = ntohl(candidate.s_addr);
	uint8_t first = (uint8_t)(address >> 24);
	uint8_t second = (uint8_t)(address >> 16);
	uint8_t third = (uint8_t)(address >> 8);

	if (!first || first == 10 || first == 127 || first >= 224 ||
		(first == 100 && (second & 0xc0) == 0x40) ||
		(first == 169 && second == 254) ||
		(first == 172 && second >= 16 && second <= 31) ||
		(first == 192 && second == 168) ||
		(first == 192 && second == 0 && third == 0) ||
		(first == 192 && second == 0 && third == 2) ||
		(first == 198 && (second == 18 || second == 19)) ||
		(first == 198 && second == 51 && third == 100) ||
		(first == 203 && second == 0 && third == 113))
		return 0;

	return address != UINT32_MAX;
}

/* Returns whole monotonic seconds for cache and attempt deadlines. */
static int64_t monotonic_seconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;

	return now.tv_sec;
}

/**
 * Runs one authentication worker under a hard timeout.
 *
 * The parent accepts only the primary marker followed by one structurally valid
 * terminal packet. It kills and reaps a worker after any timeout or protocol
 * violation.
 */
static int run_auth_worker(struct in_addr candidate,
						   struct worker_message *final_message,
						   bool *primary_seen, int client_fd)
{
	struct pollfd poll_descriptor;
	int sockets[2];
	int64_t deadline;
	pid_t child;
	int child_status;
	int result = -1;
	*primary_seen = false;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets))
		return -1;

	child = fork();

	if (child < 0)
	{
		close(sockets[0]);
		close(sockets[1]);
		return -1;
	}

	if (!child)
	{
		close(sockets[0]);
		close(client_fd);

		if (server_listener >= 0)
			close(server_listener);

		run_worker(sockets[1], candidate);
	}

	close(sockets[1]);
	deadline = monotonic_seconds();

	if (deadline < 0)
	{
		(void)kill(child, SIGKILL);

		while (waitpid(child, &child_status, 0) < 0 && errno == EINTR)
			;

		close(sockets[0]);
		return -1;
	}

	deadline += AUTH_TIMEOUT_SECONDS;
	poll_descriptor.fd = sockets[0];
	poll_descriptor.events = POLLIN;

	while (!server_stopping)
	{
		struct worker_message message;
		int64_t now = monotonic_seconds();
		int64_t remaining;
		int poll_result;
		ssize_t length;

		if (now < 0)
			break;

		remaining = deadline - now;

		if (remaining <= 0)
			break;

		poll_result = poll(&poll_descriptor, 1,
						   remaining > INT_MAX / 1000 ? INT_MAX : (int)(remaining * 1000));

		if (poll_result < 0 && errno == EINTR)
			continue;

		if (poll_result <= 0)
			break;

		length = recv(sockets[0], &message, sizeof(message), 0);

		if (length <= 0)
			break;

		if ((size_t)length < offsetof(struct worker_message, payload) ||
			message.magic != WORKER_MAGIC ||
			message.payload_length > sizeof(message.payload) ||
			(size_t)length != offsetof(struct worker_message, payload) +
								  message.payload_length)
			break;

		if (message.kind == WORKER_MESSAGE_PRIMARY)
		{
			if (*primary_seen || message.status || message.reason ||
				message.payload_length)
			{
				secure_zero(&message, sizeof(message));
				break;
			}

			*primary_seen = true;
			secure_zero(&message, sizeof(message));
			continue;
		}

		if (message.kind != WORKER_MESSAGE_FINAL ||
			(message.status != PKU_AUTH_STATUS_OK &&
			 message.status != PKU_AUTH_STATUS_PERMANENT &&
			 message.status != PKU_AUTH_STATUS_TRANSIENT) ||
			message.reason > PKU_AUTH_REASON_MAX ||
			(message.status == PKU_AUTH_STATUS_OK &&
			 (!*primary_seen || message.reason != PKU_AUTH_REASON_NONE ||
			  !message.payload_length)) ||
			(message.status != PKU_AUTH_STATUS_OK &&
			 (!message.reason || message.payload_length)))
		{
			secure_zero(&message, sizeof(message));
			break;
		}

		*final_message = message;
		secure_zero(&message, sizeof(message));
		result = 0;
		break;
	}

	if (result)
		(void)kill(child, SIGKILL);

	while (waitpid(child, &child_status, 0) < 0 && errno == EINTR)
		;

	close(sockets[0]);
	return result;
}

/* Securely clears one cached session and resets its timestamp. */
static void clear_cache(char *cache, size_t cache_size, int64_t *cached_at)
{
	secure_zero(cache, cache_size);
	*cached_at = 0;
}

/* Validates and serves one loopback IPC request without retaining credentials. */
static void handle_client(int client_fd, char *cache, int64_t *cached_at,
						  uint16_t *permanent_latch,
						  int64_t *last_fresh_attempt)
{
	struct pku_auth_request request;
	struct worker_message result;
	struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
	struct in_addr candidate;
	int64_t now = monotonic_seconds();
	bool primary_seen;

	(void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
					 &timeout, sizeof(timeout));

	(void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
					 &timeout, sizeof(timeout));

	if (read_all(client_fd, &request, sizeof(request)) ||
		memcmp(request.magic, PKU_AUTH_MAGIC, PKU_AUTH_MAGIC_LEN) ||
		request.version != PKU_AUTH_VERSION || request.reserved)
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_PERMANENT,
							PKU_AUTH_REASON_BAD_REQUEST, NULL, 0);

		return;
	}

	if (now < 0)
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_TRANSIENT,
							PKU_AUTH_REASON_INTERNAL, NULL, 0);

		return;
	}

	if (request.operation == PKU_AUTH_OP_HEALTH)
	{
		if (*permanent_latch)
			(void)send_response(client_fd, PKU_AUTH_STATUS_PERMANENT,
								*permanent_latch, NULL, 0);
		else
			(void)send_response(client_fd, PKU_AUTH_STATUS_OK,
								PKU_AUTH_REASON_NONE, NULL, 0);

		return;
	}

	if (request.operation == PKU_AUTH_OP_INVALIDATE)
	{
		clear_cache(cache, PKU_AUTH_COOKIE_MAX + 1, cached_at);

		if (*permanent_latch)
			(void)send_response(client_fd, PKU_AUTH_STATUS_PERMANENT,
								*permanent_latch, NULL, 0);
		else
			(void)send_response(client_fd, PKU_AUTH_STATUS_OK,
								PKU_AUTH_REASON_NONE, NULL, 0);

		return;
	}

	if (request.operation != PKU_AUTH_OP_AUTHENTICATE)
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_PERMANENT,
							PKU_AUTH_REASON_BAD_REQUEST, NULL, 0);

		return;
	}

	if (*permanent_latch)
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_PERMANENT,
							*permanent_latch, NULL, 0);

		return;
	}

	candidate.s_addr = request.candidate_ipv4;

	if (!public_candidate(candidate))
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_PERMANENT,
							PKU_AUTH_REASON_BAD_REQUEST, NULL, 0);

		return;
	}

	if (*cached_at && now - *cached_at <= CACHE_TTL_SECONDS && cache[0])
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_OK,
							PKU_AUTH_REASON_NONE, cache, strlen(cache));

		return;
	}

	clear_cache(cache, PKU_AUTH_COOKIE_MAX + 1, cached_at);

	if (*last_fresh_attempt &&
		now - *last_fresh_attempt < FRESH_ATTEMPT_FLOOR_SECONDS)
	{
		(void)send_response(client_fd, PKU_AUTH_STATUS_TRANSIENT,
							PKU_AUTH_REASON_RATE_LIMIT, NULL, 0);

		return;
	}

	*last_fresh_attempt = now;
	memset(&result, 0, sizeof(result));

	if (run_auth_worker(candidate, &result, &primary_seen, client_fd))
	{
		uint16_t reason = primary_seen ? PKU_AUTH_REASON_AUTH_TIMEOUT : PKU_AUTH_REASON_NETWORK;
		uint8_t status = primary_seen ? PKU_AUTH_STATUS_PERMANENT : PKU_AUTH_STATUS_TRANSIENT;

		if (status == PKU_AUTH_STATUS_PERMANENT)
			*permanent_latch = reason;

		(void)send_response(client_fd, status, reason, NULL, 0);
		return;
	}

	if (primary_seen && result.status == PKU_AUTH_STATUS_TRANSIENT)
	{
		result.status = PKU_AUTH_STATUS_PERMANENT;
		result.reason = PKU_AUTH_REASON_AUTH_REJECTED;
		result.payload_length = 0;
	}

	if (result.status == PKU_AUTH_STATUS_OK)
	{
		if (!result.payload_length ||
			result.payload_length > PKU_AUTH_COOKIE_MAX)
		{
			result.status = PKU_AUTH_STATUS_PERMANENT;
			result.reason = PKU_AUTH_REASON_COOKIE;
			result.payload_length = 0;
		}
		else
		{
			memcpy(cache, result.payload, result.payload_length);
			cache[result.payload_length] = 0;
			*cached_at = now;
		}
	}

	if (result.status == PKU_AUTH_STATUS_PERMANENT)
		*permanent_latch = result.reason ? result.reason : PKU_AUTH_REASON_INTERNAL;

	(void)send_response(client_fd, result.status, result.reason,
						result.payload_length ? result.payload : NULL,
						result.payload_length);

	secure_zero(&result, sizeof(result));
}

/* Requests an orderly accept-loop shutdown from a process signal. */
static void signal_handler(int signal_number)
{
	(void)signal_number;
	server_stopping = 1;

	if (server_listener >= 0)
		close(server_listener);
}

/* Initializes the hardened loopback sidecar and serves requests serially. */
int main(void)
{
	struct sockaddr_in address;

	const struct rlimit core_limit =
		{
			.rlim_cur = 0,
			.rlim_max = 0,
		};

	char cache[PKU_AUTH_COOKIE_MAX + 1];
	int64_t cached_at = 0;
	int64_t last_fresh_attempt = 0;
	uint16_t permanent_latch = 0;
	int enable = 1;

	if (geteuid() == 0 || getegid() == 0)
	{
		fprintf(stderr, "auth_sidecar=permanent reason=RUNTIME_UID\n");
		return PKU_AUTH_STATUS_PERMANENT;
	}

	if (prctl(PR_SET_DUMPABLE, 0) || setrlimit(RLIMIT_CORE, &core_limit))
	{
		fprintf(stderr, "auth_sidecar=permanent reason=RUNTIME_HARDENING\n");
		return PKU_AUTH_STATUS_PERMANENT;
	}

	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGTERM, signal_handler);
	(void)signal(SIGINT, signal_handler);
	umask(077);
	memset(cache, 0, sizeof(cache));
	(void)mlock(cache, sizeof(cache));
	server_listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (server_listener < 0)
		return 1;

	(void)setsockopt(server_listener, SOL_SOCKET, SO_REUSEADDR,
					 &enable, sizeof(enable));

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(PKU_AUTH_PORT);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(server_listener, (const struct sockaddr *)&address,
			 sizeof(address)) ||
		listen(server_listener, 4))
	{
		fprintf(stderr, "auth_sidecar=permanent reason=LISTEN\n");
		close(server_listener);
		return 1;
	}

	printf("auth_sidecar=ready endpoint=loopback\n");
	fflush(stdout);

	while (!server_stopping)
	{
		int client = accept4(server_listener, NULL, NULL, SOCK_CLOEXEC);

		if (client < 0 && errno == EINTR)
			continue;

		if (client < 0)
			break;

		handle_client(client, cache, &cached_at,
					  &permanent_latch, &last_fresh_attempt);

		close(client);
	}

	secure_zero(cache, sizeof(cache));
	(void)munlock(cache, sizeof(cache));
	return 0;
}
