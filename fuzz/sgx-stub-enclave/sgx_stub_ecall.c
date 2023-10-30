#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <rats-tls/api.h>
#include <rats-tls/log.h>
#include "rats-tls/api.h"
#include "sgx_urts.h"
#include "sgx_stub_t.h"

#define FUZZ_IP	  "127.0.0.1"
#define FUZZ_PORT 1234

int ecall_client_startup(rats_tls_log_level_t log_level, char *fuzz_conf_bytes, char *attester_type,
			 char *verifier_type, char *tls_type, char *crypto_type,
			 unsigned long flags, uint32_t s_ip, uint16_t s_port)
{
	rats_tls_conf_t conf;
	memset(&conf, 0, sizeof(rats_tls_conf_t));

	snprintf(conf.attester_type, sizeof(conf.attester_type), "%s", attester_type);
	snprintf(conf.verifier_type, sizeof(conf.verifier_type), "%s", verifier_type);
	snprintf(conf.tls_type, sizeof(conf.tls_type), "%s", tls_type);
	snprintf(conf.crypto_type, sizeof(conf.crypto_type), "%s", crypto_type);
	conf.flags = flags;
	conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;

	RTLS_INFO("Enter the client \n");

	claim_t custom_claims[2] = {
		{ .name = "key_0", .value = (uint8_t *)"value_0", .value_size = sizeof("value_0") },
		{ .name = "key_1", .value = (uint8_t *)"value_1", .value_size = sizeof("value_1") },
	};
	conf.custom_claims = (claim_t *)custom_claims;
	conf.custom_claims_length = 2;

	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol.
	 */

	int64_t sockfd;
	int sgx_status = ocall_socket(&sockfd, RTLS_AF_INET, RTLS_SOCK_STREAM, 0);
	if (sgx_status != SGX_SUCCESS || sockfd < 0) {
		// RTLS_ERR("Failed to call socket() %#x %d\n", sgx_status, sockfd);
		return -1;
	}

	struct rtls_sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = RTLS_AF_INET;
	s_addr.sin_addr.s_addr = s_ip;
	s_addr.sin_port = s_port;

	/* Connect to the server */
	int ocall_ret = 0;
	sgx_status = ocall_connect(&ocall_ret, sockfd, &s_addr, sizeof(s_addr));
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		// RTLS_ERR("failed to call connect() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	// RTLS_INFO("Enter the init \n");
	/* rats-tls init */
	librats_tls_init();
	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	if (ret != RATS_TLS_ERR_NONE) {
		// RTLS_ERR("Failed to initialize rats tls %#x\n", ret);
		return -1;
	}
	// RTLS_INFO("start to negotiate\n");

	ret = rats_tls_negotiate(handle, (int)sockfd);
	if (ret != RATS_TLS_ERR_NONE) {
		// RTLS_ERR("Failed to negotiate %#x\n", ret);
		return -1;
	}

	const char *msg = "Hello and welcome to RATS-TLS!\n";
	size_t len = strlen(msg);
	// RTLS_INFO("Enter the transmit \n");
	ret = rats_tls_transmit(handle, (void *)msg, &len);
	if (ret != RATS_TLS_ERR_NONE || len != strlen(msg)) {
		// RTLS_ERR("Failed to transmit %#x\n", ret);
		goto err;
	}

	ret = rats_tls_cleanup(handle);
	if (ret != RATS_TLS_ERR_NONE)
		// RTLS_ERR("Failed to cleanup %#x\n", ret);

	return 0;

err:
	rats_tls_cleanup(handle);
	return -1;
}

int ecall_server_startup(rats_tls_log_level_t log_level, char *attester_type, char *verifier_type,
			 char *tls_type, char *crypto_type, unsigned long flags, uint32_t s_ip,
			 uint16_t s_port)
{
	rats_tls_conf_t conf;
	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;

	snprintf(conf.attester_type, sizeof(conf.attester_type), "%s", attester_type);
	snprintf(conf.verifier_type, sizeof(conf.verifier_type), "%s", verifier_type);
	snprintf(conf.tls_type, sizeof(conf.tls_type), "%s", tls_type);
	snprintf(conf.crypto_type, sizeof(conf.crypto_type), "%s", crypto_type);

	conf.flags = flags;
	conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;

	claim_t custom_claims[2] = {
		{ .name = "key_0", .value = (uint8_t *)"value_0", .value_size = sizeof("value_0") },
		{ .name = "key_1", .value = (uint8_t *)"value_1", .value_size = sizeof("value_1") },
	};
	conf.custom_claims = (claim_t *)custom_claims;
	conf.custom_claims_length = 2;

	int64_t sockfd;
	int sgx_status = ocall_socket(&sockfd, RTLS_AF_INET, RTLS_SOCK_STREAM, 0);
	if (sgx_status != SGX_SUCCESS || sockfd < 0) {
		// RTLS_ERR("Failed to call socket() %#x %d\n", sgx_status, sockfd);
		return -1;
	}

	int ocall_ret = 0;

	struct rtls_sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = RTLS_AF_INET;
	s_addr.sin_addr.s_addr = s_ip;
	s_addr.sin_port = s_port;

	/* Bind the server socket */
	sgx_status = ocall_bind(&ocall_ret, sockfd, &s_addr, sizeof(s_addr));
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		// RTLS_ERR("Failed to call bind(), %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	sgx_status = ocall_listen(&ocall_ret, sockfd, 5);
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		// RTLS_ERR("Failed to call listen(), %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	librats_tls_init();
	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	if (ret != RATS_TLS_ERR_NONE) {
		// RTLS_ERR("Failed to initialize rats tls %#x\n", ret);
		return -1;
	}

	struct rtls_sockaddr_in c_addr;
	uint32_t addrlen_in = sizeof(c_addr);
	uint32_t addrlen_out;
	while (1) {
		// RTLS_INFO("Waiting for a connection ...\n");

		int64_t connd;
		sgx_status = ocall_accept(&connd, sockfd, &c_addr, addrlen_in, &addrlen_out);
		if (sgx_status != SGX_SUCCESS || connd < 0) {
			// RTLS_ERR("Failed to call accept() %#x %d\n", sgx_status, connd);
			return -1;
		}

		ret = rats_tls_negotiate(handle, connd);
		if (ret != RATS_TLS_ERR_NONE) {
			// RTLS_ERR("Failed to negotiate %#x\n", ret);
			goto err;
		}

		// RTLS_INFO("Client connected successfully\n");

		ocall_close(&ocall_ret, connd);
	}

	return 0;
err:
	/* Ignore the error code of cleanup in order to return the prepositional error */
	rats_tls_cleanup(handle);
	return -1;
}
