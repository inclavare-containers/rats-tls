add_subdirectory(nullattester)

if((EXISTS "/usr/include/linux/sev-guest.h") AND HOST)
    add_subdirectory(sev-snp)
endif()

if(TDX)
    add_subdirectory(tdx-ecdsa)
endif()

if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()
