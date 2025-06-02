cmake_minimum_required(VERSION 3.15)
project(SuperSerpent)

# add_compile_definitions(CRYPTOPP_DISABLE_X86ASM)
# Can manually control (Top level) CRYPTOPP_DISABLE_X86ASM (ASM switch), CRYPTOPP_DISABLE_SSSE3 (Instructions), CRYPTOPP_DISABLE_AESNI (AES), CRYPTOPP_NO_UNALIGNED_DATA_ACCESS (non-Aligned access)
# CRYPTOPP_GENERATE_X64_MASM (Enable MASM, not influenced by X86ASM) TC_WINDOWS Series (Not needed in the project)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Release)
set(SOURCE_DIR "${CMAKE_SOURCE_DIR}")

# Add libs
add_library(rand STATIC ${SOURCE_DIR}/rand/rand.c)
add_library(whirlpool STATIC ${SOURCE_DIR}/pbkdf2/whirlpool/Whirlpool.c)
add_library(pbkdf2 STATIC ${SOURCE_DIR}/pbkdf2/pbkdf2.c)
add_library(serpent STATIC ${SOURCE_DIR}/vcserpent/SerpentFast.c)
add_library(serpentsimd STATIC ${SOURCE_DIR}/vcserpent/SerpentFast_simd.cpp)

# Windows Setting
if(WIN32)
	add_executable(main ${SOURCE_DIR}/main.c ${SOURCE_DIR}/core/crypto_mode_sloth.c ${SOURCE_DIR}/core/utils_sloth.c ${SOURCE_DIR}/core/logic_sloth.c ${SOURCE_DIR}/core/test_sloth.c ${SOURCE_DIR}/core/bench_sloth.c ${SOURCE_DIR}/core/makevcvol_sloth.c)

	# Dependencies
	target_link_libraries(pbkdf2 PUBLIC whirlpool)
	target_link_libraries(main PRIVATE rand pbkdf2 serpent serpentsimd)

    # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
    # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")

    target_compile_options(main PRIVATE "/MT")
    target_compile_options(rand PRIVATE "/MT")
    target_compile_options(whirlpool PRIVATE "/MT")
    target_compile_options(pbkdf2 PRIVATE "/MT")
    target_compile_options(serpent PRIVATE "/MT")
    target_compile_options(serpentsimd PRIVATE "/MT")
    target_link_libraries(main PRIVATE AdvAPI32)
endif()

# Linux Settings
if(UNIX)
    option(USING_LIBFUSE_V3 "USE LIBFUSE V3" OFF)
if(USING_LIBFUSE_V3)
    add_compile_definitions(USING_LIBFUSE_V3)
endif()
    add_executable(main ${SOURCE_DIR}/main.c ${SOURCE_DIR}/core/crypto_mode_sloth.c ${SOURCE_DIR}/core/utils_sloth.c ${SOURCE_DIR}/core/logic_sloth.c ${SOURCE_DIR}/core/slothfuse.c ${SOURCE_DIR}/core/test_sloth.c ${SOURCE_DIR}/core/bench_sloth.c ${SOURCE_DIR}/core/makevcvol_sloth.c)
    target_link_libraries(pbkdf2 PUBLIC whirlpool)
	target_link_libraries(main PRIVATE rand pbkdf2 serpent serpentsimd)
    find_package(Threads REQUIRED)
    target_link_libraries(main PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    # Stage 1: Check if Alpine
    execute_process(
        COMMAND grep -q "ID=alpine" /etc/os-release 2>/dev/null
        RESULT_VARIABLE IS_ALPINE
    )

    # Stage 2: Detect MUSL
    file(WRITE "${CMAKE_BINARY_DIR}/musl_test.c" "")
    try_compile(
        HAVE_MUSL
        "${CMAKE_BINARY_DIR}"
        SOURCES "${CMAKE_BINARY_DIR}/musl_test.c"
        COMPILE_DEFINITIONS "-dM -E"
        OUTPUT_VARIABLE MUSL_OUT
    )
    file(REMOVE "${CMAKE_BINARY_DIR}/musl_test.c")

    # Alpine or MUSL symbols
    if(IS_ALPINE EQUAL 0 OR MUSL_OUT MATCHES "__MUSL__")
        message(STATUS "Detected MUSL C library (Alpine or generic), enabling static linking")
if (USING_LIBFUSE_V3)
        target_link_libraries(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libfuse317_musl.a)
        message(STATUS "Using libfuse3.17")
else()
        target_link_libraries(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libfuse299_musl.a)
        message(STATUS "Using libfuse2.99")
endif()
        # Force static link and override possible dynamic linking
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static" CACHE STRING "Linker flags" FORCE)
        # Optional: Static link to libgcc and libstdc++
        # set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -static-libgcc -static-libstdc++")
    else()
        message(STATUS "Detected glibc (or non-Alpine), keeping dynamic linking")
if (USING_LIBFUSE_V3)
        target_link_libraries(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libfuse317_glibc.a)
        message(STATUS "Using libfuse3.17")
else()
        target_link_libraries(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libfuse299_glibc.a)
        message(STATUS "Using libfuse2.99")
endif()

    endif()
endif()

# Output bin path
set_target_properties(main PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
