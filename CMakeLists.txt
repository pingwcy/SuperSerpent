# add_compile_definitions(CRYPTOPP_DISABLE_X86ASM)
# Can manually control (Top level) CRYPTOPP_DISABLE_X86ASM (ASM switch), CRYPTOPP_DISABLE_SSSE3 (Instructions), CRYPTOPP_DISABLE_AESNI (AES), CRYPTOPP_NO_UNALIGNED_DATA_ACCESS (non-Aligned access)
# CRYPTOPP_GENERATE_X64_MASM (Enable MASM, not influenced by X86ASM) TC_WINDOWS Series (Not needed in the project)

cmake_minimum_required(VERSION 3.15)
project(SuperSerpent
    VERSION 1.0
    LANGUAGES C CXX
)

# Global Compile Options
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Release)

# Route Variables
set(SOURCE_DIR "${CMAKE_SOURCE_DIR}")
set(CORE_DIR "${SOURCE_DIR}/core")
set(RAND_DIR "${SOURCE_DIR}/rand")
set(PBKDF2_DIR "${SOURCE_DIR}/pbkdf2")
set(SERPENT_DIR "${SOURCE_DIR}/vcserpent")

# Project Options
option(ENC_ONLY_MODE "Encryptor/Creator Only Mode For Unix" OFF)
option(USING_LIBFUSE_V3 "USE LIBFUSE V3" OFF)

if(ENC_ONLY_MODE)
    add_compile_definitions(ENC_ONLY_MODE)
endif()

if(USING_LIBFUSE_V3)
    add_compile_definitions(USING_LIBFUSE_V3)
endif()

# Libs Sources
set(RAND_SOURCES ${RAND_DIR}/rand.c)
set(WHIRLPOOL_SOURCES ${PBKDF2_DIR}/whirlpool/Whirlpool.c)
set(PBKDF2_SOURCES ${PBKDF2_DIR}/pbkdf2.c)
set(SERPENT_SOURCES ${SERPENT_DIR}/SerpentFast.c)
set(SERPENT_SIMD_SOURCES ${SERPENT_DIR}/SerpentFast_simd.cpp)

# Core Sources
set(CORE_SOURCES
    ${CORE_DIR}/crypto_mode_sloth.c
    ${CORE_DIR}/utils_sloth.c
    ${CORE_DIR}/logic_sloth.c
    ${CORE_DIR}/test_sloth.c
    ${CORE_DIR}/bench_sloth.c
    ${CORE_DIR}/makevcvol_sloth.c
)

if(UNIX AND NOT ENC_ONLY_MODE)
    list(APPEND CORE_SOURCES ${CORE_DIR}/slothfuse.c)
    list(APPEND CORE_SOURCES ${CORE_DIR}/slothfuse_vc.c)
endif()

# Create Static Libs
add_library(rand STATIC ${RAND_SOURCES})
add_library(whirlpool STATIC ${WHIRLPOOL_SOURCES})
add_library(pbkdf2 STATIC ${PBKDF2_SOURCES})
add_library(serpent STATIC ${SERPENT_SOURCES})
add_library(serpentsimd STATIC ${SERPENT_SIMD_SOURCES})

# Libs Dependencies
target_link_libraries(pbkdf2 PUBLIC whirlpool)

# Create Executable
add_executable(main ${SOURCE_DIR}/main.c ${CORE_SOURCES})

# Executable Dependencies
target_link_libraries(main PRIVATE 
    rand 
    pbkdf2 
    serpent 
    serpentsimd
)

# Platform Settings
if(WIN32)
    # Windows
    target_compile_options(main PRIVATE "/MT")
    target_compile_options(rand PRIVATE "/MT")
    target_compile_options(whirlpool PRIVATE "/MT")
    target_compile_options(pbkdf2 PRIVATE "/MT")
    target_compile_options(serpent PRIVATE "/MT")
    target_compile_options(serpentsimd PRIVATE "/MT")
    
    target_link_libraries(main PRIVATE AdvAPI32)
elseif(UNIX)
    # Unix/Linux
    find_package(Threads REQUIRED)
    target_link_libraries(main PRIVATE Threads::Threads)

    # Detect MUSL C
    include(CheckSymbolExists)
    set(CMAKE_REQUIRED_DEFINITIONS -dM)
    check_symbol_exists(__MUSL__ "" HAVE_MUSL)
    unset(CMAKE_REQUIRED_DEFINITIONS)

    # Check if Alpine Linux
    execute_process(
        COMMAND grep -q "ID=alpine" /etc/os-release 2>/dev/null
        RESULT_VARIABLE IS_ALPINE
    )

    if(IS_ALPINE EQUAL 0 OR HAVE_MUSL)
        message(STATUS "Detected MUSL C library (Alpine or generic), enabling static linking")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
        
        if(NOT ENC_ONLY_MODE)
            if(USING_LIBFUSE_V3)
                set(FUSE_LIB_NAME "libfuse317_musl.a")
            else()
                set(FUSE_LIB_NAME "libfuse299_musl.a")
            endif()
            target_link_libraries(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/${FUSE_LIB_NAME})
            message(STATUS "Using ${FUSE_LIB_NAME}")
        endif()
    else()
        message(STATUS "Detected glibc (or non-Alpine), keeping dynamic linking")
        if(NOT ENC_ONLY_MODE)
            if(USING_LIBFUSE_V3)
                set(FUSE_LIB_NAME "libfuse317_glibc.a")
            else()
                set(FUSE_LIB_NAME "libfuse299_glibc.a")
            endif()
            target_link_libraries(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/${FUSE_LIB_NAME})
            message(STATUS "Using ${FUSE_LIB_NAME}")
        endif()
    endif()
endif()

# Output Executable Dir
set_target_properties(main PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)