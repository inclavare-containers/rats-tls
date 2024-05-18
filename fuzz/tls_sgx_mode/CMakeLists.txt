project(fuzz_sgx_mode CXX)

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS "-fsanitize=address,fuzzer -g ${CMAKE_CXX_FLAGS}")
set(RATS_TLS_INSTALL_FUZZ_PATH /usr/share/rats-tls/fuzz)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CustomInstallDirs)
include(FindRatsTls)
if(NOT RATS_TLS_FOUND)
    message(FATAL_ERROR "Failed to find rats_tls!")
endif()

include(FindSGX)
if(NOT SGX_FOUND)
    message(FATAL_ERROR "Failed to find sgx!")
endif()

include(CompilerOptions)
include(SGXCommon)

set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave
                        ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
            )
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/rats-tls
                )
list(APPEND LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src/sgx/untrust
                        ${CMAKE_BINARY_DIR}/fuzz/sgx-stub-enclave
                        )
set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                    )
set(DEPEND_UNTRUSTED_LIBS ${CMAKE_BINARY_DIR}/src/sgx/untrust/librats_tls_u.a)


include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES fuzz_sgx_mode.cc)

# Generate bin file
set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave/sgx_stub.edl)
add_untrusted_executable(${PROJECT_NAME}
                        SRCS ${SOURCES}
                        UNTRUSTED_LIBS ${DEPEND_UNTRUSTED_LIBS}
                        EDL ${EDLS}
                        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_dependencies(${PROJECT_NAME} sgx_stub_enclave-sign)

install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_FUZZ_PATH})
