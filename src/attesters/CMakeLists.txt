add_subdirectory(nullattester)

if(HOST)
    add_subdirectory(sev)
    if(EXISTS "/usr/include/linux/sev-guest.h")
        add_subdirectory(sev-snp)
    endif()
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
