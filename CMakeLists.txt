cmake_minimum_required(VERSION 3.22)
project(DesignJetStatus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable verbose output for debugging
set(CMAKE_VERBOSE_MAKEFILE ON)

# Set compiler-specific options
if(MSVC)
    # MSVC-specific settings
    add_compile_options(/W4 /permissive-)
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
        _CRT_SECURE_NO_WARNINGS
    )
    
    # Find libraries using find_library for MSVC
    find_library(WS2_32_LIB NAMES Ws2_32)
    find_library(WSNMP32_LIB NAMES Wsnmp32)
    find_library(WINSPOOL_LIB NAMES winspool)
    
    if(NOT WS2_32_LIB OR NOT WSNMP32_LIB OR NOT WINSPOOL_LIB)
        message(FATAL_ERROR "Required system libraries not found")
    endif()
    
    set(SYSTEM_LIBS
        ${WS2_32_LIB}
        ${WSNMP32_LIB}
        ${WINSPOOL_LIB}
    )
    
else()
    # MSYS2 MinGW64 settings
    add_compile_options(-Wall -Wextra -pedantic -Wno-unknown-pragmas)
    add_compile_definitions(
        UNICODE
        _UNICODE
    )

    set(SYSTEM_LIBS
        ws2_32        # Winsock2
        winspool      # Win32 Print API
        snmpapi       # SNMP API - MSYS2 MinGW compatible library
    )

    # Note: MSYS2 MinGW doesn't have 'wsnmp32'. Use 'snmpapi' instead or provide external SNMP library if needed.
endif()

# Create the executable
add_executable(DesignJetStatus main.cpp)

# Link system libraries
target_link_libraries(DesignJetStatus PRIVATE ${SYSTEM_LIBS})

# Set target properties
set_target_properties(DesignJetStatus PROPERTIES
    WIN32_EXECUTABLE TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Installation
install(TARGETS DesignJetStatus
    RUNTIME DESTINATION bin
)

# Print configuration information
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "System libraries: ${SYSTEM_LIBS}")