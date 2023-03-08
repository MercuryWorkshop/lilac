#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OpenSSL::Crypto" for configuration ""
set_property(TARGET OpenSSL::Crypto APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(OpenSSL::Crypto PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libcrypto.so"
  IMPORTED_SONAME_NOCONFIG "libcrypto.so"
  )

list(APPEND _cmake_import_check_targets OpenSSL::Crypto )
list(APPEND _cmake_import_check_files_for_OpenSSL::Crypto "${_IMPORT_PREFIX}/lib/libcrypto.so" )

# Import target "OpenSSL::SSL" for configuration ""
set_property(TARGET OpenSSL::SSL APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(OpenSSL::SSL PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libssl.so"
  IMPORTED_SONAME_NOCONFIG "libssl.so"
  )

list(APPEND _cmake_import_check_targets OpenSSL::SSL )
list(APPEND _cmake_import_check_files_for_OpenSSL::SSL "${_IMPORT_PREFIX}/lib/libssl.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
