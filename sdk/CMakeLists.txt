cmake_minimum_required(VERSION 3.22)
project(sdk)
message(STATUS "Project Name: ${PROJECT_NAME}")
message(STATUS "Project Source: ${SDK_DIR}")
message(STATUS "Project Binary: ${PROJECT_BINARY_DIR}")
message(STATUS "编译类型: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 11)

# 设置相关包含目录
set(SOURCE_DIR_TRI ${SDK_DIR}/src)

aux_source_directory(${SOURCE_DIR_TRI} SOURCE_FILES)

include_directories("${SDK_DIR}/inc" "${SDK_DIR}/3rdpart/gmssl/include" "${SDK_DIR}/inc")

link_directories("${SDK_DIR}/3rdpart/gmssl/lib")

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})

target_sources(${PROJECT_NAME}  PRIVATE ${SOURCE_FILES})

target_include_directories(
        ${PROJECT_NAME}
        PRIVATE
        ${INCLUDE_DIR}
)

#set_target_properties(${PROJECT_NAME} PROPERTIES
#        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}
#        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}
#)

target_link_libraries(
        ${PROJECT_NAME}
        ssl
        crypto
)

