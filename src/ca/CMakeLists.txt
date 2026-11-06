# OpenGDS - the CA slot and the built-in OpenSSL backend
# SPDX-License-Identifier: MPL-2.0
add_library(gds_ca STATIC ca.c ca_x509.c ca_openssl.c ca_crl.c)
target_include_directories(gds_ca PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(gds_ca PUBLIC gds_common)
