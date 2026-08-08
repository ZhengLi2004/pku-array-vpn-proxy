/* SPDX-License-Identifier: Apache-2.0 */
/* Emulates bounded iSecSP callback scenarios without proprietary binaries. */
#define _GNU_SOURCE

#include "../src/isecsp-auth/sdk_abi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Minimal SSL object passed through the server's exported TLS guards. */
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

/* Synthetic libisec entry points exercised by selected SDK scenarios. */
int isec_net_new(const void *parameters, void **output);
int isec_net_connect(void *network);

int isec_net_write(void *network, const void *buffer, uint32_t length,
				   void *error);

int isec_net_free(void *network);
int isec_mauth_new(void);

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

static char fake_session[9216];

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

/* Marks a successful synthetic TLS handshake. */
int SSL_connect(SSL *ssl)
{
	(void)ssl;
	marker("FAKE_SSL_CONNECT_MARKER");
	return 1;
}

/* Marks and reports a full legacy synthetic TLS write. */
int SSL_write(SSL *ssl, const void *buffer, int length)
{
	(void)ssl;
	(void)buffer;
	marker("FAKE_SSL_WRITE_MARKER");
	return length;
}

/* Marks and reports a full extended synthetic TLS write. */
int SSL_write_ex(SSL *ssl, const void *buffer, size_t length, size_t *written)
{
	(void)ssl;
	(void)buffer;
	marker("FAKE_SSL_WRITE_MARKER");

	if (written)
		*written = length;

	return 1;
}

/* Provides the no-op synthetic SSL release entry point. */
void SSL_free(SSL *ssl)
{
	(void)ssl;
}

/* Reports a successful synthetic SSL reset. */
int SSL_clear(SSL *ssl)
{
	(void)ssl;
	return 1;
}

/* Allocates a synthetic peer certificate for SPKI verification. */
X509 *SSL_get_peer_certificate(const SSL *ssl)
{
	X509 *certificate;
	(void)ssl;
	certificate = calloc(1, sizeof(*certificate));
	return certificate;
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

/* Accepts the SDK's log-level configuration without producing output. */
void array_vpn_set_log_level(int level, unsigned char flags)
{
	(void)level;
	(void)flags;
}

/* Returns the session string prepared by the active synthetic scenario. */
int array_vpn_get_cookies(char *session, size_t session_length)
{
	const char *scenario = getenv("FAKE_SCENARIO");
	size_t length = strlen(fake_session);

	if (scenario && !strcmp(scenario, "cookie-api-error"))
		return 26;

	if (!session || length + 1 > session_length)
		return 23;

	memcpy(session, fake_session, length + 1);
	return 0;
}

/* Confirms that gateway resolution was pinned to the requested candidate. */
static int check_resolution(void)
{
	const char *expected = getenv("FAKE_EXPECT_CANDIDATE");
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	char resolved[INET_ADDRSTRLEN];
	int status;

	if (!expected)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	status = getaddrinfo("arrayvpn.pku.edu.cn", "443", &hints, &result);

	if (status || !result || result->ai_family != AF_INET)
		return -1;

	if (!inet_ntop(AF_INET,
				   &((const struct sockaddr_in *)result->ai_addr)->sin_addr,
				   resolved, sizeof(resolved)))
	{
		freeaddrinfo(result);
		return -1;
	}

	freeaddrinfo(result);
	return strcmp(resolved, expected) ? -1 : 0;
}

/* Confirms that the worker's connection guard rejects an unrelated address. */
static int wrong_destination_is_blocked(void)
{
	struct sockaddr_in address;
	int fd;
	int saved_errno;
	int status;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(443);
	(void)inet_pton(AF_INET, "1.1.1.1", &address.sin_addr);
	errno = 0;
	status = connect(fd, (const struct sockaddr *)&address, sizeof(address));
	saved_errno = errno;
	close(fd);
	return status == -1 && saved_errno == EACCES ? 0 : -1;
}

/* Populates method metadata for one bounded synthetic SDK scenario. */
static void set_method(isecsp_auth_info *info, const char *scenario)
{
	info->method_count = 1;
	strcpy(info->methods[0].name, "北京大学VPN");
	info->methods[0].type = 2;

	if (!strcmp(scenario, "duplicate-method"))
	{
		info->method_count = 2;
		strcpy(info->methods[1].name, "北京大学VPN");
		info->methods[1].type = 2;
	}

	if (!strcmp(scenario, "zero-method"))
		info->method_count = 0;

	if (!strcmp(scenario, "too-many-methods"))
		info->method_count = 11;

	if (!strcmp(scenario, "wrong-method"))
	{
		strcpy(info->methods[0].name, "其他认证");
		info->methods[0].type = 0;
	}

	if (!strcmp(scenario, "sole-radius-alias"))
		strcpy(info->methods[0].name, "PKU-RADIUS-ACTUAL");

	if (!strcmp(scenario, "method-description-only"))
	{
		strcpy(info->methods[0].name, "PKU-RADIUS-ACTUAL");
		strcpy(info->methods[0].description, "北京大学VPN");
		info->methods[0].type = 0;
	}

	if (!strcmp(scenario, "malformed-method-name"))
		memset(info->methods[0].name, 'A', sizeof(info->methods[0].name));

	if (!strcmp(scenario, "announced-id"))
	{
		info->methods[0].multi_step_count = 1;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入身份证后6位");
	}

	if (!strcmp(scenario, "announced-phone"))
	{
		info->methods[0].multi_step_count = 1;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入缺位电话号码四位数字");
	}

	if (!strcmp(scenario, "announced-dual") ||
		!strcmp(scenario, "announced-dual-repeat"))
	{
		info->methods[0].multi_step_count = 2;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入身份证后6位");

		strcpy(info->methods[0].multi_steps[1].server,
			   "请输入缺位电话号码四位数字");
	}

	if (!strcmp(scenario, "announced-description-dual"))
	{
		info->methods[0].multi_step_count = 2;

		strcpy(info->methods[0].multi_steps[0].description,
			   "请输入身份证后6位");

		strcpy(info->methods[0].multi_steps[1].description,
			   "请输入缺位电话号码四位数字");
	}

	if (!strcmp(scenario, "announced-server-wins"))
	{
		info->methods[0].multi_step_count = 1;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入身份证后6位");

		strcpy(info->methods[0].multi_steps[0].description,
			   "请输入缺位电话号码四位数字");
	}

	if (!strcmp(scenario, "announced-unused-malformed-description"))
	{
		info->methods[0].multi_step_count = 1;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入身份证后6位");

		memset(info->methods[0].multi_steps[0].description, 'A',
			   sizeof(info->methods[0].multi_steps[0].description));
	}

	if (!strcmp(scenario, "unknown-announced"))
	{
		info->methods[0].multi_step_count = 1;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入动态口令");
	}

	if (!strcmp(scenario, "unknown-server-known-description"))
	{
		info->methods[0].multi_step_count = 1;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入动态口令");

		strcpy(info->methods[0].multi_steps[0].description,
			   "请输入身份证后6位");
	}

	if (!strcmp(scenario, "duplicate-announced"))
	{
		info->methods[0].multi_step_count = 2;

		strcpy(info->methods[0].multi_steps[0].server,
			   "请输入身份证后6位");

		strcpy(info->methods[0].multi_steps[1].server,
			   "请填写身份证最后六位");
	}

	if (!strcmp(scenario, "malformed-announced"))
	{
		info->methods[0].multi_step_count = 1;

		memset(info->methods[0].multi_steps[0].server, 'A',
			   sizeof(info->methods[0].multi_steps[0].server));
	}

	if (!strcmp(scenario, "too-many-announced"))
		info->methods[0].multi_step_count = 3;
}

/* Issues one runtime prompt and validates the adapter's supplemental response. */
static void issue_challenge(isecsp_user_parameter *user, const char *prompt)
{
	isecsp_challenge_info challenge;
	isecsp_auth_input output;
	uint32_t output_length = sizeof(output);
	memset(&challenge, 0, sizeof(challenge));
	memset(&output, 0, sizeof(output));

	strncpy(challenge.information, prompt,
			sizeof(challenge.information) - 1);

	(void)user->callback(15, 0, &challenge, sizeof(challenge),
						 &output, &output_length);

	if (!output.password[0] || output.method[0] || output.username[0] ||
		output.password2[0] || output.password3[0])
		_exit(90);
}

/* Drives the selected SDK callback scenario and returns a synthetic session. */
int isecsp_get_session(isecsp_user_parameter user, char *session,
					   uint32_t session_length, char *return_value,
					   uint32_t return_length)
{
	const char *scenario = getenv("FAKE_SCENARIO");
	isecsp_auth_info info;
	isecsp_auth_input output;
	uint32_t output_length = sizeof(output);
	SSL ssl = {0};
	static const char request[] = "GET / HTTP/1.1\r\n\r\n";

	const char *cookie =
		"ANStandalone=true; ANsessionFAKE=abc=123; SPA-Session=0303";

	size_t written = 0;
	(void)return_value;
	(void)return_length;

	if (!scenario)
		scenario = "none";

	if (strcmp(user.host, "arrayvpn.pku.edu.cn") || user.port != 443 ||
		user.alias[0] || user.method[0] || user.username[0] ||
		user.password[0] || !user.callback)
		return 91;

	if (!strcmp(scenario, "network"))
		return 1;

	if (check_resolution() || wrong_destination_is_blocked())
		return 92;

	if (!strcmp(scenario, "mauth"))
	{
		(void)isec_mauth_new();
		return 93;
	}

	if (!strcmp(scenario, "isec-net") ||
		!strcmp(scenario, "isec-net-bad-pin") ||
		!strcmp(scenario, "isec-write-before-connect") ||
		!strcmp(scenario, "isec-null-write"))
	{
		void *network = NULL;

		if (!strcmp(scenario, "isec-null-write"))
		{
			(void)isec_net_write(NULL, request,
								 (uint32_t)(sizeof(request) - 1), NULL);

			return 93;
		}

		if (isec_net_new(NULL, &network) || !network)
			return 93;

		if (!strcmp(scenario, "isec-write-before-connect"))
		{
			(void)isec_net_write(network, request,
								 (uint32_t)(sizeof(request) - 1), NULL);

			return 93;
		}

		if (isec_net_connect(network))
			return 93;

		if (isec_net_write(network, request,
						   (uint32_t)(sizeof(request) - 1), NULL) < 0)
			return 93;

		if (isec_net_free(network))
			return 93;
	}

	if (!strcmp(scenario, "write-before-pin"))
	{
		(void)SSL_write(&ssl, request, (int)(sizeof(request) - 1));
		return 93;
	}

	if (!strcmp(scenario, "null-ssl-write"))
	{
		(void)SSL_write(NULL, request, (int)(sizeof(request) - 1));
		return 93;
	}

	if (!strcmp(scenario, "write-ex-before-pin"))
	{
		(void)SSL_write_ex(&ssl, request, sizeof(request) - 1, &written);
		return 93;
	}

	if (SSL_connect(&ssl) != 1)
		return 94;

	if (!strcmp(scenario, "clear-before-write"))
	{
		if (SSL_clear(&ssl) != 1)
			return 95;

		(void)SSL_write(&ssl, request, (int)(sizeof(request) - 1));
		return 95;
	}

	if (!strcmp(scenario, "write-ex"))
	{
		if (SSL_write_ex(&ssl, request, sizeof(request) - 1, &written) != 1 ||
			written != sizeof(request) - 1)
			return 95;
	}
	else if (SSL_write(&ssl, request, (int)(sizeof(request) - 1)) < 0)
	{
		return 95;
	}

	if (!strcmp(scenario, "success-before-primary"))
	{
		(void)user.callback(3, 0, NULL, 0, NULL, NULL);
		return 96;
	}

	memset(&info, 0, sizeof(info));
	memset(&output, 0, sizeof(output));
	set_method(&info, scenario);

	if (!strcmp(scenario, "short-output"))
		output_length = sizeof(output) - 1;

	(void)user.callback(13, !strcmp(scenario, "initial-error"),
						!strcmp(scenario, "null-initial") ? NULL : &info,
						!strcmp(scenario, "short-initial") ? sizeof(info) - 1 : sizeof(info),
						!strcmp(scenario, "null-output") ? NULL : &output,
						!strcmp(scenario, "null-output-length") ? NULL : &output_length);

	if (strcmp(output.method,
			   !strcmp(scenario, "sole-radius-alias") ? "PKU-RADIUS-ACTUAL" : "北京大学VPN") ||
		!output.username[0] || !output.password[0] ||
		output.customer1[0] || output.device_id[0] || output.device_name[0])
		return 96;

	if (!strcmp(scenario, "announced-id") ||
		!strcmp(scenario, "announced-server-wins") ||
		!strcmp(scenario, "announced-unused-malformed-description"))
	{
		if (strcmp(output.password2, "12345X") || output.password3[0])
			return 96;
	}
	else if (!strcmp(scenario, "announced-phone"))
	{
		if (strcmp(output.password2, "6789") || output.password3[0])
			return 96;
	}
	else if (!strcmp(scenario, "announced-dual") ||
			 !strcmp(scenario, "announced-dual-repeat") ||
			 !strcmp(scenario, "announced-description-dual"))
	{
		if (strcmp(output.password2, "12345X") ||
			strcmp(output.password3, "6789"))
			return 96;
	}
	else if (output.password2[0] || output.password3[0])
	{
		return 96;
	}

	if (!strcmp(scenario, "repeat-primary"))
		(void)user.callback(13, 0, &info, sizeof(info), &output,
							&output_length);

	if (!strcmp(scenario, "bad-password"))
		return 2;

	if (!strcmp(scenario, "id"))
		issue_challenge(&user, "请输入身份证后6位");

	if (!strcmp(scenario, "id-variant"))
		issue_challenge(&user, "请填写身份证最后六位");

	if (!strcmp(scenario, "phone"))
		issue_challenge(&user, "请输入缺位电话号码四位数字");

	if (!strcmp(scenario, "phone-position"))
		issue_challenge(&user, "请输入手机号第4到7位");

	if (!strcmp(scenario, "dual"))
	{
		issue_challenge(&user, "请输入身份证后 6 位");
		issue_challenge(&user, "请输入手机号第 4 到 7 位");
	}

	if (!strcmp(scenario, "announced-dual-repeat"))
		issue_challenge(&user, "请输入身份证后 6 位");

	if (!strcmp(scenario, "unknown"))
		issue_challenge(&user, "请输入动态口令");

	if (!strcmp(scenario, "ambiguous"))
		issue_challenge(&user, "身份证后6位或缺位电话号码四位数字");

	if (!strcmp(scenario, "repeat"))
	{
		issue_challenge(&user, "请输入身份证后6位");
		issue_challenge(&user, "请输入身份证后6位");
	}

	if (!strcmp(scenario, "sms"))
	{
		(void)user.callback(19, 0, NULL, 0, NULL, NULL);
		return 97;
	}

	if (!strcmp(scenario, "placeholder"))
		cookie = "ANsessionFAKE=placeholder";

	if (!strcmp(scenario, "multiple-cookie"))
		cookie = "ANsessionONE=one; ANsessionTWO=two";

	if (!strcmp(scenario, "control-cookie"))
		cookie = "ANsessionFAKE=good\r\nbad";

	if (strlen(cookie) >= sizeof(fake_session))
		return 98;

	strcpy(fake_session, cookie);
	(void)user.callback(3, !strcmp(scenario, "success-error"),
						NULL, 0, NULL, NULL);

	if (!strcmp(scenario, "mauth-after-success"))
	{
		marker("FAKE_POST_SUCCESS_MAUTH_MARKER");
		(void)isec_mauth_new();
		return 99;
	}

	if (strlen(cookie) >= session_length)
		return 98;

	strcpy(session, cookie);
	SSL_free(&ssl);
	return 0;
}
