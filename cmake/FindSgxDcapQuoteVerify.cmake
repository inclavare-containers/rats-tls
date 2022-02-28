include(FindPackageHandleStandardArgs)

set(SGXDCAPQV_LIBRARY_PATH /usr/)
find_library(SGXDCAPQV_LIBRARY_DIR NAMES sgx_dcap_quoteverify PATHS ${SGXDCAPQV_LIBRARY_PATH})

# Handle the QUIETLY and REQUIRED arguments and set SGXDCAPQV_FOUND to TRUE if all listed variables are TRUE.
find_package_handle_standard_args(SGXDCAPQV
                                  DEFAULT_MSG
                                  SGXDCAPQV_LIBRARY_DIR)
