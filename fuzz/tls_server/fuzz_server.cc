/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-1.0
 */

extern "C" {
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "rats-tls/api.h"
#include "rats-tls/log.h"
#include "rats-tls/claim.h"
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/tls_wrapper.h"
}
#define FUZZ_IP	  "127.0.0.1"
#define FUZZ_PORT 1234

int main()
{
	rats_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = RATS_TLS_LOG_LEVEL_INFO;
	strcpy(conf.attester_type, "nullattester");
	strcpy(conf.verifier_type, "nullverifier");
	strcpy(conf.tls_type, "nulltls");
	strcpy(conf.crypto_type, "nullcrypto");

	/* Optional: Set some user-defined custom claims, which will be embedded in the certificate. */
	claim_t custom_claims[2] = {
		{ .name = "key_0", .value = (uint8_t *)"value_0", .value_size = sizeof("value_0") },
		{ .name = "key_1", .value = (uint8_t *)"value_1", .value_size = sizeof("value_1") },
	};
	conf.custom_claims = (claim_t *)custom_claims;
	conf.custom_claims_length = 2;

	conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
	conf.flags |= RATS_TLS_CONF_FLAGS_SERVER;
	conf.flags |= RATS_TLS_CONF_FLAGS_MUTUAL;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		RTLS_ERR("fail to create socket\n");
		return -1;
	}

	int reuse = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuse, sizeof(int)) < 0) {
		RTLS_ERR("Failed to call setsockopt()");
		return -1;
	}

	/* Set keepalive options */
	int flag = 1;
	int tcp_keepalive_time = 1;
	int tcp_keepalive_intvl = 1;
	int tcp_keepalive_probes = 5;
	if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0) {
		RTLS_ERR("Failed to call setsockopt()");
		return -1;
	}
	if (setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &tcp_keepalive_time,
		       sizeof(tcp_keepalive_time)) < 0) {
		RTLS_ERR("Failed to call setsockopt()");
		return -1;
	}
	if (setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepalive_intvl,
		       sizeof(tcp_keepalive_intvl)) < 0) {
		RTLS_ERR("Failed to call setsockopt()");
		return -1;
	}
	if (setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, &tcp_keepalive_probes,
		       sizeof(tcp_keepalive_probes)) < 0) {
		RTLS_ERR("Failed to call setsockopt()");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_addr.s_addr = inet_addr(FUZZ_IP);
	s_addr.sin_port = htons(FUZZ_PORT);

	/* Bind the server socket */
	if (bind(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		return -1;
	}

	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	if (ret != RATS_TLS_ERR_NONE) {
		return -1;
	}

	ret = rats_tls_set_verification_callback(&handle, NULL);
	if (ret != RATS_TLS_ERR_NONE) {
		return -1;
	}

	RTLS_INFO("waiting for socket connection\n");
	while (1) {
		/* Accept client connections */
		struct sockaddr_in c_addr;
		socklen_t size = sizeof(c_addr);

		int connd = accept(sockfd, (struct sockaddr *)&c_addr, &size);
		if (connd < 0) {
			return 0;
		}
		RTLS_INFO("Receive socket connection\n");

		ret = rats_tls_negotiate(handle, connd);
		if (ret != RATS_TLS_ERR_NONE) {
			RTLS_ERR("negotiate failed \n");
			return 0;
		}
		RTLS_INFO("Negotiate successfully\n");

		char buf[256];
		size_t len = sizeof(buf);
		ret = rats_tls_receive(handle, buf, &len);
		if (ret != RATS_TLS_ERR_NONE) {
			RTLS_ERR("Receive failed \n");
			continue;
		}
		len = sizeof(buf) - 1;
		buf[len] = '\0';
		RTLS_INFO("The str is %s\n", buf);

		ret = rats_tls_transmit(handle, buf, &len);
		if (ret != RATS_TLS_ERR_NONE) {
			continue;
		}
		close(connd);
	}
	return 0;
}