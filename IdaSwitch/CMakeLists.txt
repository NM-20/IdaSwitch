cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Read the version string from our `IdaSwitch.h` header and use it here.
# The file itself doesn't contain any other numeric characters, so we'll
# use a simple expression.
file(STRINGS "Source/IdaSwitch.h" IDA_SWITCH_VERSION REGEX "[0-9.]+")

# Get rid of leading whitespace, since it seems the line is returned and
# not the matched content.
string(STRIP "${IDA_SWITCH_VERSION}" IDA_SWITCH_VERSION)

project("IdaSwitch"
  VERSION "${IDA_SWITCH_VERSION}"
  DESCRIPTION "A decompilation/rewrite of Peter Garba's SwitchIDAProLoader."
  LANGUAGES C CXX
)
add_library("IdaSwitch" SHARED)

# Building this requires that we have `IDA_SDK` set within the environment.
if (DEFINED ENV{IDA_SDK})
  set(IDA_SDK "$ENV{IDA_SDK}")
else()
  message(FATAL_ERROR "`IDA_SDK` must be set in the environment!")
endif()

if (NOT EXISTS "${IDA_SDK}")
  message(FATAL_ERROR "IDA SDK at \"${IDA_SDK}\" does not exist!")
endif()

target_include_directories("IdaSwitch"
  PRIVATE
  "${IDA_SDK}/include/"
  "${IDA_SDK}/ldr/"
)

function(ida_switch_exit_unsupported_compiler)
  message(FATAL_ERROR "Unsupported compiler for \"${IDA_SWITCH_OS}\"!")
endfunction()

# We've got the includes, but now we must link to the appropriate library.
if (CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(IDA_SWITCH_BITNESS "32")
  set(IDA_SWITCH_USE_64 OFF)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(IDA_SWITCH_BITNESS "64")
  set(IDA_SWITCH_USE_64 ON)
  # Ensure we're using a 64-bit `ea_t`.
  add_compile_definitions("__EA64__")
endif()

# Determine the target architecture.
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR
  CMAKE_SYSTEM_PROCESSOR STREQUAL "x64" OR
  CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")

  if (IDA_SWITCH_USE_64)
    set(IDA_SWITCH_ARCHITECTURE "x64")
  else()
    set(IDA_SWITCH_ARCHITECTURE "x86")
  endif()
  
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR
  CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR
  CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")

  set(IDA_SWITCH_ARCHITECTURE "arm64")
  
else()
  message(FATAL_ERROR "\"${CMAKE_SYSTEM_PROCESSOR}\" is not supported!")
endif()

# Get the IDA library name and the compiler identifier.
if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(IDA_SWITCH_OS "mac")

  if (NOT IDA_SWITCH_USE_64)
    set(IDA_SWITCH_IDA_LIB_NAME "libida.dylib")
  else()
    set(IDA_SWITCH_IDA_LIB_NAME "libida64.dylib")
  endif()

  if (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR
    CMAKE_CXX_COMPILER_ID STREQUAL "Clang")

    set(IDA_SWITCH_COMPILER "clang")

  else()
    ida_switch_exit_unsupported_compiler()
  endif()
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(IDA_SWITCH_OS "linux")

  if (NOT IDA_SWITCH_USE_64)
    set(IDA_SWITCH_IDA_LIB_NAME "libida.so")
  else()
    set(IDA_SWITCH_IDA_LIB_NAME "libida64.so")
  endif()

  if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(IDA_SWITCH_COMPILER "gcc")
  else()
    ida_switch_exit_unsupported_compiler()
  endif()
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(IDA_SWITCH_OS "win")
  set(IDA_SWITCH_IDA_LIB_NAME "ida.lib")

  if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(IDA_SWITCH_COMPILER "vc")
  else()
    ida_switch_exit_unsupported_compiler()
  endif()
else()
  message(FATAL_ERROR "Cannot compile IdaSwitch for \"${CMAKE_SYSTEM_NAME}\"!")
endif()

target_link_libraries(IdaSwitch
  "${IDA_SDK}/lib/${IDA_SWITCH_ARCHITECTURE}_${IDA_SWITCH_OS}_${IDA_SWITCH_COMPILER}_${IDA_SWITCH_BITNESS}/${IDA_SWITCH_IDA_LIB_NAME}"
)

add_subdirectory("Submodules")
add_subdirectory("Source")

set_target_properties(IdaSwitch PROPERTIES OUTPUT_NAME "IdaSwitch.${IDA_SWITCH_BITNESS}" PREFIX "")
