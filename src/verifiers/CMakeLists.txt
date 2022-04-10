add_subdirectory(nullverifier)

if(HOST)
    if(SGXDCAPQV_FOUND)
        add_subdirectory(sgx-ecdsa)
    else()
        message(WARNING "It will not generate libverifier_sgx_ecdsa.so due to libsgx_dcap_quoteverify.so not found in host mode")
    endif()
else()
    add_subdirectory(sgx-ecdsa)
endif()

if(HOST)
    add_subdirectory(sev-snp)
    add_subdirectory(sev)
    add_subdirectory(csv)
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
