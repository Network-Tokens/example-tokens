cmake_minimum_required(VERSION 3.0)
project(cose-test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

# Debug
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ggdb -O0")

# Release
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

# TODO: Fix the COSE-C CMake script so it generates cose-cTargets.cmake
# find_package(cose-c REQUIRED)

set(COSE_PREFIX "$ENV{HOME}/cose-wg/COSE-C/build")

include_directories(
    "${COSE_PREFIX}/include"
    "${COSE_PREFIX}/_deps/project_cn_cbor-src/include"
)

add_executable( cose-test main.cc )
add_executable( cose-test-ec2 ec2.cc )
target_link_libraries(
    cose-test
    "-L${COSE_PREFIX}/lib"
    "-L${COSE_PREFIX}/dist/lib"
)
target_link_libraries( cose-test -lcose-c -lcn-cbor )
target_link_libraries( cose-test-ec2 -lcose-c -lcn-cbor )
