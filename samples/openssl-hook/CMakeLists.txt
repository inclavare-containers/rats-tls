project(openssl-hook)

set(LIB_NAME ${PROJECT_NAME}_lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror=implicit-function-declaration -Wundef -Werror")

set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/rats-tls
                 ${RATS_TLS_INSTALL_INCLUDE_PATH}
                 ${RATS_TLS_INSTALL_INCLUDE_PATH}/edl
                 )
set(LIBRARY_DIRS ${RATS_TLS_INSTALL_LIB_PATH})

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Generate .so file
add_library(${LIB_NAME} SHARED libopenssl-hook.c
                               openssl.c
                               )
# DO NOT link this with rats_tls.so, we will call dlopen to load it
# target_link_libraries(${LIB_NAME} rats_tls)
add_dependencies(${LIB_NAME} rats_tls)

install(TARGETS ${LIB_NAME}
	DESTINATION /usr/share/rats-tls/samples)
