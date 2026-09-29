cmake_minimum_required (VERSION 3.10)

if(COMMAND cmake_policy)
      cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project (pkcs11 C)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

option(PKCS11_V32 "Build against the OASIS PKCS#11 v3.2 headers instead of the legacy g10 Code headers" ON)
if(PKCS11_V32)
  message(STATUS "PKCS11: using OASIS v3.2 headers")
  add_definitions(-DPKCS11_USE_V32)
else()
  message(STATUS "PKCS11: using legacy headers")
endif()

set(PKCS11_PROXY_SRCS gck-rpc-module.c gck-rpc-message.c gck-rpc-util.c gck-rpc-params.c egg-buffer.c gck-rpc-tls-psk.c)
set(PKCS11_DAEMON_SRCS egg-buffer.c gck-rpc-daemon-standalone.c gck-rpc-dispatch.c gck-rpc-message.c gck-rpc-util.c gck-rpc-params.c gck-rpc-tls-psk.c)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  option(PKCS11_SECCOMP "Confine pkcs11-daemon with libseccomp syscall filters" ON)
  option(PKCS11_SECCOMP_DEBUG "Report disallowed syscalls instead of killing the daemon (not for production)" OFF)
else()
  set(PKCS11_SECCOMP OFF)
  set(PKCS11_SECCOMP_DEBUG OFF)
endif()
if (PKCS11_SECCOMP)
  message(STATUS "PKCS11: seccomp enabled")
  add_definitions(-DSECCOMP)
  if (PKCS11_SECCOMP_DEBUG)
    add_definitions(-DDEBUG_SECCOMP)
    list(APPEND PKCS11_DAEMON_SRCS syscall-reporter.c syscall-names.h)
  endif()
endif()

add_definitions(-Wall)
add_library(pkcs11-proxy SHARED ${PKCS11_PROXY_SRCS})

# Disable console when building Win32 binary in release mode
if (WIN32)
  if("${CMAKE_BUILD_TYPE}" MATCHES "^Rel.*")
    set(GUI_TYPE WIN32)
  endif()
endif()

add_executable (pkcs11-daemon ${GUI_TYPE} ${PKCS11_DAEMON_SRCS})

set_target_properties(pkcs11-proxy PROPERTIES VERSION 0.1 SOVERSION 0)

if (WIN32)
  include_directories("ext/include")

  add_library(dl STATIC IMPORTED)
  set_property(TARGET dl PROPERTY
               IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/ext/lib/libdl.a)
  target_link_libraries (pkcs11-daemon ws2_32)
  target_link_libraries (pkcs11-proxy ws2_32)
endif (WIN32)

target_link_libraries (pkcs11-proxy pthread ${OPENSSL_LIBRARIES})
target_link_libraries (pkcs11-daemon dl pthread ${OPENSSL_LIBRARIES})
if (PKCS11_SECCOMP)
  target_link_libraries (pkcs11-daemon seccomp)
endif()

install_targets (/lib pkcs11-proxy)
install_targets (/bin pkcs11-daemon)

add_custom_command(
   OUTPUT syscall-names.h 
   COMMAND ${CMAKE_SOURCE_DIR}/mksyscalls.sh
   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Tests: cmake -DPKCS11_TESTS=ON, then "ctest". The PQC test additionally needs
# a SoftHSM built with ML-DSA/ML-KEM:
#   -DPKCS11_TEST_SOFTHSM_MODULE=/path/libsofthsm2.so
#   -DPKCS11_TEST_SOFTHSM_UTIL=/path/softhsm2-util
option(PKCS11_TESTS "Build the tests (needs PKCS11_V32)" OFF)
set(PKCS11_TEST_SOFTHSM_MODULE "" CACHE FILEPATH "SoftHSM module for the PQC test")
set(PKCS11_TEST_SOFTHSM_UTIL "" CACHE FILEPATH "softhsm2-util for the PQC test")
if (PKCS11_TESTS)
  if (NOT PKCS11_V32 OR WIN32)
    message(FATAL_ERROR "PKCS11_TESTS needs PKCS11_V32 and a POSIX system")
  endif()
  enable_testing()
  set(T ${CMAKE_SOURCE_DIR}/tests)

  # A PKCS#11 3.2 module for the daemon to load
  add_library(p11-mock-module MODULE ${T}/mock-module.c)
  target_include_directories(p11-mock-module PRIVATE ${CMAKE_SOURCE_DIR})
  set_target_properties(p11-mock-module PROPERTIES PREFIX "")

  add_executable(message-test ${T}/message-test.c)
  target_include_directories(message-test PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(message-test ${CMAKE_DL_LIBS})

  add_executable(pqc-test ${T}/pqc-test.c)
  target_include_directories(pqc-test PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(pqc-test ${CMAKE_DL_LIBS})

  add_executable(mechanism-test ${T}/mechanism-test.c)
  target_include_directories(mechanism-test PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(mechanism-test ${CMAKE_DL_LIBS})

  add_executable(protocol-test ${T}/protocol-test.c)
  target_include_directories(protocol-test PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(protocol-test ${CMAKE_DL_LIBS})

  add_executable(interface-test ${T}/interface-test.c)
  target_include_directories(interface-test PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(interface-test ${CMAKE_DL_LIBS})

  add_executable(softhsm-test ${T}/softhsm-test.c)
  target_include_directories(softhsm-test PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(softhsm-test ${CMAKE_DL_LIBS})

  # Fuzzes the daemon-side AEAD parameter parser (sanitizers if available)
  add_executable(param-fuzz ${T}/param-fuzz.c gck-rpc-util.c gck-rpc-params.c)
  target_include_directories(param-fuzz PRIVATE ${CMAKE_SOURCE_DIR})
  include(CheckCCompilerFlag)
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=address,undefined")
  check_c_compiler_flag("-fsanitize=address,undefined" PKCS11_HAVE_SANITIZERS)
  unset(CMAKE_REQUIRED_FLAGS)
  if (PKCS11_HAVE_SANITIZERS)
    target_compile_options(param-fuzz PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=undefined -g)
    target_link_libraries(param-fuzz -fsanitize=address,undefined)
  endif()

  # The daemon's own parsers against hostile input (embeds gck-rpc-dispatch.c)
  add_executable(daemon-input ${T}/daemon-input.c egg-buffer.c gck-rpc-message.c
                 gck-rpc-util.c gck-rpc-params.c gck-rpc-tls-psk.c)
  target_include_directories(daemon-input PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(daemon-input ${CMAKE_DL_LIBS} pthread ${OPENSSL_LIBRARIES})
  if (PKCS11_HAVE_SANITIZERS)
    target_compile_options(daemon-input PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=undefined -g)
    target_link_libraries(daemon-input -fsanitize=address,undefined)
  endif()
  add_test(NAME daemon-input COMMAND daemon-input)

  add_test(NAME param-fuzz COMMAND param-fuzz 1500)
  add_test(NAME message-async
    COMMAND ${T}/run-with-daemon.sh $<TARGET_FILE:pkcs11-daemon>
            $<TARGET_FILE:pkcs11-proxy> $<TARGET_FILE:p11-mock-module>
            $<TARGET_FILE:message-test>)
  add_test(NAME mechanism-params
    COMMAND ${T}/run-with-daemon.sh $<TARGET_FILE:pkcs11-daemon>
            $<TARGET_FILE:pkcs11-proxy> $<TARGET_FILE:p11-mock-module>
            $<TARGET_FILE:mechanism-test>)
  add_test(NAME protocol-mechanisms
    COMMAND ${T}/run-with-daemon.sh $<TARGET_FILE:pkcs11-daemon>
            $<TARGET_FILE:pkcs11-proxy> $<TARGET_FILE:p11-mock-module>
            $<TARGET_FILE:protocol-test>)
  add_test(NAME interfaces-init
    COMMAND ${T}/run-with-daemon.sh $<TARGET_FILE:pkcs11-daemon>
            $<TARGET_FILE:pkcs11-proxy> $<TARGET_FILE:p11-mock-module>
            $<TARGET_FILE:interface-test>)
  if (PKCS11_TEST_SOFTHSM_MODULE AND PKCS11_TEST_SOFTHSM_UTIL)
    add_test(NAME pqc-softhsm
      COMMAND ${T}/run-with-daemon.sh $<TARGET_FILE:pkcs11-daemon>
              $<TARGET_FILE:pkcs11-proxy> ${PKCS11_TEST_SOFTHSM_MODULE}
              $<TARGET_FILE:pqc-test> ${PKCS11_TEST_SOFTHSM_UTIL})
    set_tests_properties(pqc-softhsm PROPERTIES SKIP_RETURN_CODE 77)
    add_test(NAME templates-mechanisms-softhsm
      COMMAND ${T}/run-with-daemon.sh $<TARGET_FILE:pkcs11-daemon>
              $<TARGET_FILE:pkcs11-proxy> ${PKCS11_TEST_SOFTHSM_MODULE}
              $<TARGET_FILE:softhsm-test> ${PKCS11_TEST_SOFTHSM_UTIL})
  endif()
endif()
