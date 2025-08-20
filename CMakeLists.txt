cmake_minimum_required(VERSION 3.23)

project(fadec LANGUAGES C)
enable_testing()

# TODO: make this actually optional
enable_language(CXX OPTIONAL)

# Options
set(FADEC_ARCHMODE "both" CACHE STRING "Support only 32-bit x86, 64-bit x86 or both")
set_property(CACHE FADEC_ARCHMODE PROPERTY STRINGS both only32 only64)

option(FADEC_UNDOC "Include undocumented instructions" FALSE)
option(FADEC_DECODE "Include support for decoding" TRUE)
option(FADEC_ENCODE "Include support for encoding" TRUE)
option(FADEC_ENCODE2 "Include support for new encoding API" FALSE)

set(CMAKE_C_STANDARD 11)

if (MSVC)
    add_compile_options(/W4 -D_CRT_SECURE_NO_WARNINGS /wd4018 /wd4146 /wd4244 /wd4245 /wd4267 /wd4310)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Zc:preprocessor>)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-overlength-strings)
endif()

find_package(Python3 3.9 REQUIRED)

add_library(fadec)
add_library(fadec::fadec ALIAS fadec)
set_target_properties(fadec PROPERTIES
    LINKER_LANGUAGE C
)

set(GEN_ARGS "")
if (NOT FADEC_ARCHMODE STREQUAL "only64")
    list(APPEND GEN_ARGS "--32")
endif ()
if (NOT FADEC_ARCHMODE STREQUAL "only32")
    list(APPEND GEN_ARGS "--64")
endif ()
if (FADEC_UNDOC)
    list(APPEND GEN_ARGS "--with-undoc")
endif ()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include")

function(fadec_component)
    cmake_parse_arguments(ARG "" "NAME" "HEADERS;SOURCES" ${ARGN})

    set(PRIV_INC ${CMAKE_CURRENT_BINARY_DIR}/include/fadec-${ARG_NAME}-private.inc)
    set(PUB_INC ${CMAKE_CURRENT_BINARY_DIR}/include/fadec-${ARG_NAME}-public.inc)

    add_custom_command(
        OUTPUT ${PRIV_INC} ${PUB_INC}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/parseinstrs.py ${ARG_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/instrs.txt
        ${PUB_INC} ${PRIV_INC} ${GEN_ARGS}
        DEPENDS instrs.txt parseinstrs.py
        COMMENT "Building table for ${ARG_NAME}"
    )

    list(APPEND FADEC_HEADERS ${PUB_INC})
    target_sources(fadec PRIVATE
        ${ARG_SOURCES}

        PUBLIC
        FILE_SET HEADERS
        BASE_DIRS .
        FILES
            ${ARG_HEADERS}

        PUBLIC
        FILE_SET generated_public TYPE HEADERS
        BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/include
        FILES
            ${PUB_INC}

        PRIVATE
        FILE_SET generated_private TYPE HEADERS
        BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/include
        FILES
            ${PRIV_INC}
    )

    add_executable(fadec-${ARG_NAME}-test ${ARG_NAME}-test.c)
    target_link_libraries(fadec-${ARG_NAME}-test PRIVATE fadec)
    add_test(NAME ${ARG_NAME} COMMAND fadec-${ARG_NAME}-test)

    if (CMAKE_CXX_COMPILER AND ${ARG_NAME} STREQUAL "encode2")
        add_executable(fadec-${ARG_NAME}-test-cpp ${ARG_NAME}-test.cc)
        target_link_libraries(fadec-${ARG_NAME}-test-cpp PRIVATE fadec)
        add_test(NAME ${ARG_NAME}-cpp COMMAND fadec-${ARG_NAME}-test-cpp)
    endif()
endfunction()

if (FADEC_DECODE)
    fadec_component(NAME decode SOURCES decode.c format.c HEADERS fadec.h)
endif ()
if (FADEC_ENCODE)
    fadec_component(NAME encode SOURCES encode.c HEADERS fadec-enc.h)
endif ()
if (FADEC_ENCODE2)
    fadec_component(NAME encode2 SOURCES encode2.c HEADERS fadec-enc2.h)
endif ()

install(TARGETS fadec EXPORT fadec
    LIBRARY
    ARCHIVE
    FILE_SET HEADERS FILE_SET generated_public)
