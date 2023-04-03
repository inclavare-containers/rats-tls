# Project name
project(crypto_wrapper_openssl)

# Set include directory
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_TLS_INSTALL_LIB_PATH}
                 )
if(SGX)
    list(APPEND LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src/external/intel-sgx-ssl/lib)
endif()
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            gen_cert.c
            gen_privkey.c
            gen_pubkey_hash.c
            gen_hash.c
            init.c
            main.c
            pre_init.c
            )

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
    add_dependencies(${PROJECT_NAME} intel-sgx-ssl)
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${RATS_TLS_LDFLAGS} ${RTLS_LIB} crypto.so)
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
install(TARGETS ${PROJECT_NAME}
    DESTINATION ${RATS_TLS_INSTALL_LIBCW_PATH})
