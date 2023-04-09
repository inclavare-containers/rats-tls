/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/api.h>
#include <rats-tls/log.h>
#include "internal/core.h"

rats_tls_err_t rats_tls_setup_ssl(rats_tls_handle handle, rats_tls_setup_type setup_type,
				  rats_tls_ssl_obj_type obj_type, void *obj)
{
	rtls_core_context_t *ctx = (rtls_core_context_t *)handle;

	RTLS_DEBUG("handle: %p, setup_type: %#x, obj_type: %#x, obj: %p\n", ctx, setup_type,
		   obj_type, obj);

	if (!handle || !handle->tls_wrapper || !handle->tls_wrapper->opts ||
	    !handle->tls_wrapper->opts->setup_ssl || !obj)
		return RATS_TLS_ERR_INVALID;

	tls_wrapper_err_t err = handle->tls_wrapper->opts->setup_ssl(handle->tls_wrapper,
								     setup_type, obj_type, obj);
	if (err != TLS_WRAPPER_ERR_NONE)
		return RATS_TLS_ERR_INVALID;

	return RATS_TLS_ERR_NONE;
}
