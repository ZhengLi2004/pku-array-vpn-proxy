/* SPDX-License-Identifier: Apache-2.0 */
/* Provides a synthetic libisec surface for compatibility-sidecar tests. */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Minimal SSL object used by the synthetic libisec transport. */
typedef struct ssl_st
{
	int value;
} SSL;

/* Minimal public-key object exposed to the pinning adapter. */
typedef struct X509_pubkey_st
{
	int value;
} X509_PUBKEY;

/* Minimal certificate object containing the synthetic public key. */
typedef struct x509_st
{
	X509_PUBKEY pubkey;
} X509;

/* Mirrors the audited leading layout of the locked libisec network object. */
struct fake_isec_network
{
	int fd;
	int padding;
	void *context;
	SSL *ssl;
};

static const unsigned char fake_digest[32] =
	{
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
		0x10,
		0x11,
		0x12,
		0x13,
		0x14,
		0x15,
		0x16,
		0x17,
		0x18,
		0x19,
		0x1a,
		0x1b,
		0x1c,
		0x1d,
		0x1e,
		0x1f,
};

/* Records that a guarded synthetic SDK operation reached its implementation. */
static void marker(const char *environment_name)
{
	const char *path = getenv(environment_name);
	int fd;

	if (!path || !*path)
		return;

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

	if (fd >= 0)
	{
		ssize_t ignored = write(fd, "1", 1);
		(void)ignored;
		close(fd);
	}
}

/* Reports successful initialization for the synthetic libisec instance. */
int isec_global_init(void)
{
	return 0;
}

/* Provides the no-op synthetic libisec cleanup entry point. */
void isec_global_cleanup(void)
{
}

/* Returns a stable nonzero synthetic libisec version. */
unsigned int isec_version(void)
{
	return 1;
}

/* Returns a fixed diagnostic string without exposing test input. */
const char *isec_strerror(unsigned int error)
{
	(void)error;
	return "synthetic";
}

/* Allocates a synthetic transport with the audited embedded SSL offset. */
int isec_net_new(const void *parameters, void **output)
{
	struct fake_isec_network *network;
	(void)parameters;

	if (!output)
		return 1;

	network = calloc(1, sizeof(*network));

	if (!network)
		return 1;

	network->ssl = calloc(1, sizeof(*network->ssl));

	if (!network->ssl)
	{
		free(network);
		return 1;
	}

	network->fd = 42;
	*output = network;
	return 0;
}

/* Marks a successful synthetic transport connection. */
int isec_net_connect(void *opaque)
{
	if (!opaque)
		return 1;

	marker("FAKE_ISEC_CONNECT_MARKER");
	return 0;
}

/* Reports a full synthetic read without accessing caller memory. */
int isec_net_read(void *opaque, void *buffer, uint32_t length, void *error)
{
	(void)opaque;
	(void)buffer;
	(void)error;
	return (int)length;
}

/* Marks and reports a full synthetic transport write. */
int isec_net_write(void *opaque, const void *buffer, uint32_t length,
				   void *error)
{
	(void)opaque;
	(void)buffer;
	(void)error;
	marker("FAKE_ISEC_WRITE_MARKER");
	return (int)length;
}

/* Releases a synthetic transport and its embedded SSL object. */
int isec_net_free(void *opaque)
{
	struct fake_isec_network *network = opaque;

	if (!network)
		return 0;

	free(network->ssl);
	free(network);
	return 0;
}

/* Returns the stable fake descriptor stored in a synthetic transport. */
int isec_net_get_fd(void *opaque)
{
	const struct fake_isec_network *network = opaque;
	return network ? network->fd : -1;
}

/* Rejects synthetic machine-authentication allocation. */
int isec_mauth_new(void)
{
	return 1;
}

/* Rejects synthetic machine-authentication cleanup. */
int isec_mauth_free(void)
{
	return 1;
}

/* Rejects synthetic machine-certificate status checks. */
int isec_mauth_cert_check_status(void)
{
	return 1;
}

/* Rejects synthetic machine-certificate downloads. */
int isec_mauth_cert_download(void)
{
	return 1;
}

/* Rejects synthetic device registration. */
int isec_mauth_device_register(void)
{
	return 1;
}

/* Rejects synthetic device-registration status checks. */
int isec_mauth_device_check_status(void)
{
	return 1;
}

/* Allocates a synthetic peer certificate for SPKI verification. */
X509 *SSL_get_peer_certificate(const SSL *ssl)
{
	(void)ssl;
	return calloc(1, sizeof(X509));
}

/* Returns the public key embedded in a synthetic certificate. */
X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *certificate)
{
	return certificate ? (X509_PUBKEY *)&certificate->pubkey : NULL;
}

/* Encodes the stable synthetic SPKI used by the pinning tests. */
int i2d_X509_PUBKEY(const X509_PUBKEY *pubkey, unsigned char **output)
{
	static const unsigned char encoded[] = "offline-fake-spki-v1";
	(void)pubkey;

	if (output && *output)
	{
		memcpy(*output, encoded, sizeof(encoded) - 1);
		*output += sizeof(encoded) - 1;
	}

	return (int)(sizeof(encoded) - 1);
}

/* Returns the deterministic digest matching the test pin fixture. */
unsigned char *SHA256(const unsigned char *data, size_t length,
					  unsigned char *digest)
{
	(void)data;
	(void)length;
	memcpy(digest, fake_digest, sizeof(fake_digest));
	return digest;
}

/* Releases a synthetic peer certificate. */
void X509_free(X509 *certificate)
{
	free(certificate);
}
