/* SPDX-License-Identifier: Apache-2.0 */
/* Declares the ABI exposed by the single hash-locked iSecSP package revision. */
#ifndef PKU_ISECSP_SDK_ABI_H
#define PKU_ISECSP_SDK_ABI_H

#include <stddef.h>
#include <stdint.h>

/* Handles one bounded request from the SDK's authentication state machine. */
typedef int (*isecsp_callback_fn)(int command, int error,
								  const void *input, uint32_t input_length,
								  void *output, uint32_t *output_length);

/* Supplies gateway configuration and callback storage to the SDK entry point. */
typedef struct
{
	char host[256];
	int32_t port;
	char alias[256];
	char method[256];
	char username[256];
	char password[256];
	char password2[256];
	char password3[256];
	char customer1[1024];
	int32_t ssl_protocol;
	isecsp_callback_fn callback;
} isecsp_user_parameter;

/* Describes one announced supplemental method in the locked SDK ABI.
 * Field names and offsets match the DWARF in the hash-locked iSecSP 2.4.0
 * vpn_cmdline. Its login callback displays server, not description. */
typedef struct __attribute__((packed))
{
	char server[513];
	char description[513];
	int32_t type;
	int32_t action;
} isecsp_multi_method;

/* Describes one selectable authentication method and its bounded steps. */
typedef struct __attribute__((packed))
{
	char name[513];
	char description[513];
	char server[513];
	char server_description[513];
	int32_t type;
	int32_t action;
	int32_t certificate_id_type;
	char certificate_id_value[257];
	uint32_t multi_step_count;
	isecsp_multi_method multi_steps[2];
	unsigned char unused[2578];
} isecsp_auth_method;

/* Carries the server's complete method-selection callback input. */
typedef struct __attribute__((packed))
{
	int32_t device_type;
	unsigned char flags[5];
	int32_t multi_password_flag;
	uint8_t ranked_method_index;
	uint8_t default_method_index;
	uint8_t method_count;
	int32_t error_message_id;
	isecsp_auth_method methods[10];
	char error_message[2048];
	char virtual_site[64];
	uint8_t server_certificate_check;
	/* These trailing fields are not consumed by the helper, but their exact
	 * sizes keep the callback input ABI aligned with aaa_auth_info_t in the
	 * hash-locked iSecSP 2.4.0 DWARF. */
	char portal_language[63];
	uint8_t client_update_oem;
	char access_token[256];
	char two_dimension_token[256];
	char special_error_message[2048];
	char server_version[260];
	uint8_t sandbox_enabled;
	uint8_t synchronized_password;
	char login_tips[16384];
	uint8_t base64_enabled;
} isecsp_auth_info;

/* Carries credentials returned to initial-login and challenge callbacks. */
typedef struct __attribute__((packed))
{
	char method[513];
	char username[257];
	char password[4097];
	char password2[4097];
	char password3[4097];
	char customer1[1024];
	char device_id[256];
	char device_name[513];
	char verification_code[4097];
	char random_id[4097];
	char phone_number[4097];
	char sms_code[4097];
	char third_party_random_id[4097];
} isecsp_auth_input;

/* Carries the two bounded prompt fields used by a runtime challenge. */
typedef struct
{
	char information[256];
	char error_message[256];
} isecsp_challenge_info;

_Static_assert(sizeof(isecsp_user_parameter) == 2832,
			   "unsupported iSecSP user parameter ABI");

_Static_assert(offsetof(isecsp_user_parameter, port) == 256,
			   "unsupported iSecSP port offset");

_Static_assert(offsetof(isecsp_user_parameter, alias) == 260,
			   "unsupported iSecSP alias offset");

_Static_assert(offsetof(isecsp_user_parameter, method) == 516,
			   "unsupported iSecSP method offset");

_Static_assert(offsetof(isecsp_user_parameter, callback) == 2824,
			   "unsupported iSecSP callback offset");

_Static_assert(sizeof(isecsp_multi_method) == 1034,
			   "unsupported iSecSP multi-method ABI");

_Static_assert(offsetof(isecsp_multi_method, server) == 0,
			   "unsupported iSecSP multi-method server offset");

_Static_assert(offsetof(isecsp_multi_method, description) == 513,
			   "unsupported iSecSP multi-method description offset");

_Static_assert(offsetof(isecsp_multi_method, type) == 1026,
			   "unsupported iSecSP multi-method type offset");

_Static_assert(offsetof(isecsp_multi_method, action) == 1030,
			   "unsupported iSecSP multi-method action offset");

_Static_assert(sizeof(isecsp_auth_method) == 6971,
			   "unsupported iSecSP auth-method ABI");

_Static_assert(offsetof(isecsp_auth_method, multi_step_count) == 2321,
			   "unsupported iSecSP multi-step count offset");

_Static_assert(offsetof(isecsp_auth_method, multi_steps) == 2325,
			   "unsupported iSecSP multi-step offset");

_Static_assert(sizeof(isecsp_auth_info) == 91114,
			   "unsupported iSecSP auth-info ABI");

_Static_assert(offsetof(isecsp_auth_info, method_count) == 15,
			   "unsupported iSecSP method-count offset");

_Static_assert(offsetof(isecsp_auth_info, methods) == 20,
			   "unsupported iSecSP methods offset");

_Static_assert(offsetof(isecsp_auth_info, error_message) == 69730,
			   "unsupported iSecSP error-message offset");

_Static_assert(offsetof(isecsp_auth_info, server_certificate_check) == 71842,
			   "unsupported iSecSP certificate-check offset");

_Static_assert(offsetof(isecsp_auth_info, portal_language) == 71843,
			   "unsupported iSecSP portal-language offset");

_Static_assert(offsetof(isecsp_auth_info, access_token) == 71907,
			   "unsupported iSecSP access-token offset");

_Static_assert(offsetof(isecsp_auth_info, login_tips) == 74729,
			   "unsupported iSecSP login-tips offset");

_Static_assert(offsetof(isecsp_auth_info, base64_enabled) == 91113,
			   "unsupported iSecSP base64 flag offset");

_Static_assert(sizeof(isecsp_auth_input) == 35339,
			   "unsupported iSecSP auth-input ABI");

_Static_assert(offsetof(isecsp_auth_input, username) == 513,
			   "unsupported iSecSP username offset");

_Static_assert(offsetof(isecsp_auth_input, password) == 770,
			   "unsupported iSecSP password offset");

_Static_assert(offsetof(isecsp_auth_input, password2) == 4867,
			   "unsupported iSecSP password2 offset");

_Static_assert(offsetof(isecsp_auth_input, password3) == 8964,
			   "unsupported iSecSP password3 offset");

_Static_assert(offsetof(isecsp_auth_input, customer1) == 13061,
			   "unsupported iSecSP customer1 offset");

_Static_assert(offsetof(isecsp_auth_input, verification_code) == 14854,
			   "unsupported iSecSP verification-code offset");

_Static_assert(offsetof(isecsp_auth_input, third_party_random_id) == 31242,
			   "unsupported iSecSP third-party offset");

_Static_assert(sizeof(isecsp_challenge_info) == 512,
			   "unsupported iSecSP challenge ABI");

#endif
