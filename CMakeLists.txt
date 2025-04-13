cmake_minimum_required(VERSION 3.10)
project(SuperSerpent)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE Release)
set(SOURCE_DIR "${CMAKE_SOURCE_DIR}")

# 添加库
add_library(rand STATIC ${SOURCE_DIR}/rand/rand.c)
add_library(whirlpool STATIC ${SOURCE_DIR}/pbkdf2/whirlpool/Whirlpool.c)
add_library(pbkdf2 STATIC ${SOURCE_DIR}/pbkdf2/pbkdf2.c)
add_library(serpent STATIC ${SOURCE_DIR}/vcserpent/SerpentFast.c)
add_library(serpentsimd STATIC ${SOURCE_DIR}/vcserpent/SerpentFast_simd.cpp)

add_executable(main ${SOURCE_DIR}/main.c ${SOURCE_DIR}/core/crypto_mode_sloth.c ${SOURCE_DIR}/core/utils_sloth.c ${SOURCE_DIR}/core/logic_sloth.c)

# 关键依赖
target_link_libraries(pbkdf2 PUBLIC whirlpool)
target_link_libraries(main PRIVATE rand pbkdf2 serpent serpentsimd)

# Windows 设置
if(WIN32)
    target_compile_options(main PRIVATE "/MT")
    target_compile_options(rand PRIVATE "/MT")
    target_compile_options(whirlpool PRIVATE "/MT")
    target_compile_options(pbkdf2 PRIVATE "/MT")
    target_compile_options(serpent PRIVATE "/MT")
    target_compile_options(serpentsimd PRIVATE "/MT")
    target_link_libraries(main PRIVATE AdvAPI32)
endif()

# Linux 设置
if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(main PRIVATE ${CMAKE_THREAD_LIBS_INIT})

    # 检测是否为 musl
    execute_process(
        COMMAND ldd --version
        OUTPUT_VARIABLE LDD_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    if(LDD_OUTPUT MATCHES "musl")
        message(STATUS "Detected musl C library, enabling static linking")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    else()
        message(STATUS "Detected glibc, keeping dynamic linking")
        # 动态链接，无需加 -static
    endif()
endif()

# 输出路径
set_target_properties(main PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
