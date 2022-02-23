add_subdirectory(nullverifier)
add_subdirectory(sgx-ecdsa)

if(HOST)
    add_subdirectory(sev-snp)
endif()

if(TDX)
    add_subdirectory(tdx-ecdsa)
endif()

if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa-qve)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()
