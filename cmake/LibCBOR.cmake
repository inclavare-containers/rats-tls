project(libcbor)

include(ExternalProject)

set(LIBCBOR_ROOT        ${CMAKE_BINARY_DIR}/external/libcbor)
set(LIBCBOR_SRC_PATH    ${LIBCBOR_ROOT}/src/libcbor)
set(LIBCBOR_LIB_PATH    ${LIBCBOR_SRC_PATH}/lib)
set(LIBCBOR_INC_PATH    ${LIBCBOR_SRC_PATH}/include/)
set(LIBCBOR_LIB_FILES   ${LIBCBOR_LIB_PATH}/libcbor.a)

set(LIBCBOR_URL         https://github.com/PJK/libcbor.git)

set(LIBCBOR_CONFIGURE   cd ${LIBCBOR_SRC_PATH} && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX=${LIBCBOR_SRC_PATH} -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCBOR_PRETTY_PRINTER=OFF -DWITH_EXAMPLES=OFF .)
set(LIBCBOR_MAKE        cd ${LIBCBOR_SRC_PATH} && make)
set(LIBCBOR_INSTALL     cd ${LIBCBOR_SRC_PATH} && make install)

ExternalProject_Add(${PROJECT_NAME}
        GIT_REPOSITORY          ${LIBCBOR_URL}
        GIT_TAG                 e87d5714e69214f187db225f23985aea51c52d28
        PREFIX                  ${LIBCBOR_ROOT}
        CONFIGURE_COMMAND       ${LIBCBOR_CONFIGURE}
        BUILD_COMMAND           ${LIBCBOR_MAKE}
        INSTALL_COMMAND         ${LIBCBOR_INSTALL}
)
