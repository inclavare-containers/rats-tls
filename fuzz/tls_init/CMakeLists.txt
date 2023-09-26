project(fuzz_init CXX)

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS "-fsanitize=address,fuzzer -g ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "-fPIE ${CMAKE_CXX_FLAGS}")
set(RATS_TLS_INSTALL_FUZZ_PATH /usr/share/rats-tls/fuzz)

set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/rats-tls
                    ${RATS_TLS_INSTALL_INCLUDE_PATH}
                    ${RATS_TLS_INSTALL_INCLUDE_PATH}/edl
                    )
set(LIBRARY_DIRS ${RATS_TLS_INSTALL_LIB_PATH})

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES fuzz_init.cc)

# Generate bin file
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} rats_tls)

install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_FUZZ_PATH})
