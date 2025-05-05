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
		RTLS_ERR("Failed to call socket() %#x %d\n", sgx_status, sockfd);
		return -1;
	}

	int reuse = 1;
	int ocall_ret = 0;
	sgx_status = ocall_setsockopt(&ocall_ret, sockfd, RTLS_SOL_SOCKET, RTLS_SO_REUSEADDR,
				      (const void *)&reuse, sizeof(int));
	if (sgx_status != SGX_SUCCESS || ocall_ret < 0) {
		RTLS_ERR("Failed to call setsockopt() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	int flag = 1;
	int tcp_keepalive_time = 30;
	int tcp_keepalive_intvl = 10;
	int tcp_keepalive_probes = 5;
	sgx_status = ocall_setsockopt(&ocall_ret, sockfd, RTLS_SOL_SOCKET, RTLS_SO_KEEPALIVE, &flag,
				      sizeof(flag));
	if (sgx_status != SGX_SUCCESS || ocall_ret < 0) {
		RTLS_ERR("Failed to call setsockopt() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	sgx_status = ocall_setsockopt(&ocall_ret, sockfd, RTLS_SOL_TCP, RTLS_TCP_KEEPIDLE,
				      &tcp_keepalive_time, sizeof(tcp_keepalive_time));
	if (sgx_status != SGX_SUCCESS || ocall_ret < 0) {
		RTLS_ERR("Failed to call setsockopt() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	sgx_status = ocall_setsockopt(&ocall_ret, sockfd, RTLS_SOL_TCP, RTLS_TCP_KEEPINTVL,
				      &tcp_keepalive_intvl, sizeof(tcp_keepalive_intvl));
	if (sgx_status != SGX_SUCCESS || ocall_ret < 0) {
		RTLS_ERR("Failed to call setsockopt() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	sgx_status = ocall_setsockopt(&ocall_ret, sockfd, RTLS_SOL_TCP, RTLS_TCP_KEEPCNT,
				      &tcp_keepalive_probes, sizeof(tcp_keepalive_probes));
	if (sgx_status != SGX_SUCCESS || ocall_ret < 0) {
		RTLS_ERR("Failed to call setsockopt() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	struct rtls_sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = RTLS_AF_INET;
	s_addr.sin_addr.s_addr = s_ip;
	s_addr.sin_port = s_port;

	sgx_status = ocall_bind(&ocall_ret, sockfd, &s_addr, sizeof(s_addr));
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		RTLS_ERR("Failed to call bind(), %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	sgx_status = ocall_listen(&ocall_ret, sockfd, 5);
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		RTLS_ERR("Failed to call listen(), %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}

	librats_tls_init();
	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to initialize rats tls %#x\n", ret);
		return -1;
	}

	ret = rats_tls_set_verification_callback(&handle, NULL);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to set verification callback %#x\n", ret);
		return -1;
	}

	struct rtls_sockaddr_in c_addr;
	uint32_t addrlen_in = sizeof(c_addr);
	uint32_t addrlen_out;

	while (1) {
		RTLS_INFO("Waiting for a connection ...\n");

		int64_t connd;
		sgx_status = ocall_accept(&connd, sockfd, &c_addr, addrlen_in, &addrlen_out);
		if (sgx_status != SGX_SUCCESS || connd < 0) {
			RTLS_ERR("Failed to call accept() %#x %d\n", sgx_status, connd);
			return -1;
		}
		
		// ret = rats_tls_negotiate(handle, connd);
		// if (ret != RATS_TLS_ERR_NONE) {
		// 	RTLS_ERR("Failed to negotiate %#x\n", ret);
		// }

		// RTLS_DEBUG("Client connected successfully\n");


		// whether it need delete
		ocall_close(&ocall_ret, connd);
	}

	RTLS_ERR("server Quick ecall \n");
	return 0;

}

int ecall_client_startup(rats_tls_log_level_t log_level, char *fuzz_conf_bytes, char *attester_type,
			 char *verifier_type, char *tls_type, char *crypto_type,
			 unsigned long flags, uint32_t s_ip, uint16_t s_port)
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

	int64_t sockfd;
	int sgx_status = ocall_socket(&sockfd, RTLS_AF_INET, RTLS_SOCK_STREAM, 0);
	if (sgx_status != SGX_SUCCESS || sockfd < 0) {
		RTLS_ERR("Failed to call socket() %#x %d\n", sgx_status, sockfd);
		return -1;
	}

	struct rtls_sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = RTLS_AF_INET;
	s_addr.sin_addr.s_addr = s_ip;
	s_addr.sin_port = s_port;

	int ocall_ret = 0;
	sgx_status = ocall_connect(&ocall_ret, sockfd, &s_addr, sizeof(s_addr));
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		RTLS_ERR("failed to call connect() %#x %d\n", sgx_status, ocall_ret);
		return -1;
	}
	// RTLS_ERR("connect success\n");

	/* rats-tls init */
	librats_tls_init();
	// RTLS_ERR("Librats init Ok \n");
	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	// RTLS_ERR("rats_tls_init Ok \n");
	
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to initialize rats tls %#x\n", ret);
		return -1;
	}

	// ret = rats_tls_set_verification_callback(&handle, NULL); 
	// if (ret != RATS_TLS_ERR_NONE) {
	// 	RTLS_ERR("Failed to set verification callback %#x\n", ret);
	// 	return -1;
	// }

	ret = rats_tls_negotiate(handle, (int)sockfd);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to negotiate %#x\n", ret);
	}else{
		RTLS_ERR("Nego Success\n");
	}
	


	// ocall_close(&ocall_ret,sockfd);

	ret = rats_tls_cleanup(handle);
	if (ret != RATS_TLS_ERR_NONE)
		RTLS_ERR("Failed to cleanup %#x\n", ret);

	// return ret;

}