/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/cpu.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
// clang-format off
#ifndef SGX
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <rats-tls/log.h>
#else
#include "rtls_t.h"
#endif
// clang-format on

#ifndef SGX
// clang-format off
static inline void cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
#if defined(__x86_64__)
	asm volatile("cpuid"
		     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
		     : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
		     : "memory");
#else
	/* on 32bit, ebx can NOT be used as PIC code */
	asm volatile("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
		     : "=a"(*eax), "=r"(*ebx), "=c"(*ecx), "=d"(*edx)
		     : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
		     : "memory");
#endif
}
// clang-format on

static inline void __cpuidex(int a[4], int b, int c)
{
	a[0] = b;
	a[2] = c;
	cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_sgx_device(const char *dev)
{
	struct stat st;

	if (!stat(dev, &st)) {
		if ((st.st_mode & S_IFCHR) && (major(st.st_rdev) == SGX_DEVICE_MAJOR_NUM))
			return true;
	}

	return false;
}

static bool is_legacy_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/isgx");
}

/* Prior to DCAP 1.10 release, the DCAP OOT driver uses this legacy
 * name.
 */
static bool is_dcap_1_9_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/sgx/enclave");
}

/* Since DCAP 1.10 release, the DCAP OOT driver uses the same name
 * as in-tree driver.
 */
static bool is_in_tree_kernel_driver(void)
{
	return is_sgx_device("/dev/sgx_enclave");
}
#else
static inline void __cpuidex(int a[4], int b, int c)
{
	a[0] = b;
	a[2] = c;
	ocall_cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_legacy_oot_kernel_driver(void)
{
	bool retval;

	ocall_is_sgx_dev(&retval, "/dev/isgx");

	return retval;
}

/* Prior to DCAP 1.10 release, the DCAP OOT driver uses this legacy
 * name.
 */
static bool is_dcap_1_9_oot_kernel_driver(void)
{
	bool retval;

	ocall_is_sgx_dev(&retval, "/dev/sgx/enclave");

	return retval;
}

/* Since DCAP 1.10 release, the DCAP OOT driver uses the same name
 * as in-tree driver.
 */
static bool is_in_tree_kernel_driver(void)
{
	bool retval;

	ocall_is_sgx_dev(&retval, "/dev/sgx_enclave");

	return retval;
}
#endif

/* return true means in sgx1 enabled */
static bool __is_sgx1_supported(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return !!(cpu_info[0] & SGX1_STRING);
}

static bool __is_sgx2_supported(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return !!(cpu_info[0] & SGX2_STRING);
}

bool is_sgx1_supported(void)
{
	if (!__is_sgx1_supported())
		return false;

	/* SGX2 using ECDSA attestation is not compatible with SGX1
         * which uses EPID attestation.
         */
	if (is_sgx2_supported())
		return false;

	/* Check whether the kernel driver is accessible */
	if (!is_legacy_oot_kernel_driver())
		return false;

	return true;
}

bool is_sgx2_supported(void)
{
	if (!__is_sgx2_supported())
		return false;

	/* Check whether the kernel driver is accessible */
	if (!is_dcap_1_9_oot_kernel_driver() && !is_in_tree_kernel_driver())
		return false;

	return true;
}

/* return true means in td guest */
bool is_tdguest_supported(void)
{
	uint32_t sig[4] = { 0, 0, 0, 0 };

	__cpuidex(sig, TDX_CPUID, 0);

	/* "IntelTDX    " */
	return (sig[1] == 0x65746e49) && (sig[3] == 0x5844546c) && (sig[2] == 0x20202020);
}

#ifndef SGX
/* rdmsr 0xc0010131
 * bit[0]
 * 	0 = Guest SEV is not active;
 * 	1 = Guest SEV is active
 * bit[1]
 * 	0 = Guest SEV-ES is not active
 * 	1 = Guest SEV-ES is active
 * bit[2]
 * 	0 = Guest SEV-SNP is not active;
 * 	1 = Guest SEV-SNP is active
 */
static uint64_t read_msr(uint32_t reg)
{
	int fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (fd < 0) {
		RTLS_ERR("failed to open msr\n");
		return 0;
	}

	uint64_t data;
	if (pread(fd, &data, sizeof(data), reg) != sizeof(data)) {
		close(fd);
		RTLS_DEBUG("failed to read msr %#x\n", reg);
		return 0;
	}

	close(fd);

	return data;
}
#endif

#define X86_CPUID_VENDOR_HygonGenuine_ebx 0x6f677948
#define X86_CPUID_VENDOR_HygonGenuine_ecx 0x656e6975
#define X86_CPUID_VENDOR_HygonGenuine_edx 0x6e65476e

/* check CPU vendor of the guest */
bool is_hygon_cpu(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, 0, 0);

	return (cpu_info[1] == X86_CPUID_VENDOR_HygonGenuine_ebx &&
		cpu_info[2] == X86_CPUID_VENDOR_HygonGenuine_ecx &&
		cpu_info[3] == X86_CPUID_VENDOR_HygonGenuine_edx);
}

/* check whether running in AMD SEV-SNP guest */
bool is_snpguest_supported(void)
{
#ifndef SGX
	return !!(read_msr(SEV_STATUS_MSR) & (1 << SEV_SNP_FLAG));
#else
	return false;
#endif
}

/* check whether running in AMD SEV(-ES) guest */
bool is_sevguest_supported(void)
{
#ifndef SGX
	if (!is_hygon_cpu()) {
		uint64_t data = read_msr(SEV_STATUS_MSR);

		return !!data || !!(data & (1 << SEV_ES_FLAG));
	} else {
		return false;
	}
#else
	return false;
#endif
}

/* check whether running in HYGON CSV guest */
bool is_csvguest_supported(void)
{
#ifndef SGX
	if (is_hygon_cpu()) {
		uint64_t data = read_msr(SEV_STATUS_MSR);

		return !!(data & ((1 << SEV_FLAG) | (1 << SEV_ES_FLAG)));
	} else {
		return false;
	}
#else
	return false;
#endif
}
