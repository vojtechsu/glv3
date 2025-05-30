#
# CMake build system design considerations:
#
# - Include directories:
#   + Do not define include directories globally using the include_directories
#     command but rather at the target level using the
#     target_include_directories command. That way, it is easier to guarantee
#     that targets are built using the proper list of include directories.
#   + Use the PUBLIC and PRIVATE keywords to specify the scope of include
#     directories. That way, a target linking to a library (using the
#     target_link_libraries command) inherits from the library PUBLIC include
#     directories and not from the PRIVATE ones.
# - TF_PSA_CRYPTO_TARGET_PREFIX: CMake targets are designed to be alterable by
#   calling CMake in order to avoid target name clashes, via the use of
#   TF_PSA_CRYPTO_TARGET_PREFIX. The value of this variable is prefixed to the
#   tfpsacrypto and apidoc targets.
#

# We specify a minimum requirement of 3.10.2, but for now use 3.5.1 here
# until our infrastructure catches up.
cmake_minimum_required(VERSION 3.5.1)

# https://cmake.org/cmake/help/latest/policy/CMP0011.html
# Setting this policy is required in CMake >= 3.18.0, otherwise a warning is generated. The OLD
# policy setting is deprecated, and will be removed in future versions.
cmake_policy(SET CMP0011 NEW)
# https://cmake.org/cmake/help/latest/policy/CMP0012.html
# Setting the CMP0012 policy to NEW is required for FindPython3 to work with CMake 3.18.2
# (there is a bug in this particular version), otherwise, setting the CMP0012 policy is required
# for CMake versions >= 3.18.3 otherwise a deprecated warning is generated. The OLD policy setting
# is deprecated and will be removed in future versions.
cmake_policy(SET CMP0012 NEW)

if(NOT (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR))

if(LIB_INSTALL_DIR)
    set(CMAKE_INSTALL_LIBDIR "${LIB_INSTALL_DIR}")
endif()

set(TF_PSA_CRYPTO_PYTHON_EXECUTABLE ${MBEDTLS_PYTHON_EXECUTABLE})
set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ${USE_STATIC_MBEDTLS_LIBRARY})
set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY ${USE_SHARED_MBEDTLS_LIBRARY})
set(TF_PSA_CRYPTO_TARGET_PREFIX ${MBEDTLS_TARGET_PREFIX})
option(INSTALL_TF_PSA_CRYPTO_HEADERS "Install TF-PSA-Crypto headers." ${INSTALL_MBEDTLS_HEADERS})

# Set the project root directory.
set(TF_PSA_CRYPTO_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(include)
add_subdirectory(core)
add_subdirectory(drivers)

if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

else(NOT (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR))

if(TEST_CPP)
    project("TF-PSA-Crypto"
        LANGUAGES C CXX
        VERSION 0.1.0
    )
else()
    project("TF-PSA-Crypto"
        LANGUAGES C
        VERSION 0.1.0
    )
endif()

include(TF-PSA-Crypto.cmake)

endif(NOT (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR))
