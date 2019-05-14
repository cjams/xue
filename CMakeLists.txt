#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.14)
project(xue)

add_library(xue INTERFACE)
target_include_directories(xue INTERFACE ${PROJECT_SOURCE_DIR}/include)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ DESTINATION include)

find_program(FORMAT NAMES clang-format REQUIRED)
add_custom_target(format COMMAND
    ${PROJECT_SOURCE_DIR}/scripts/format.sh
    ${PROJECT_SOURCE_DIR}
    ${FORMAT}
)

option(BUILD_TESTS "Build unit tests")

if(BUILD_TESTS)
    enable_testing()
    find_package(Catch2 REQUIRED)
    add_library(catch test/catch.cpp)

    add_executable(test_xue test/test_xue.cpp)
    target_link_libraries(test_xue catch)
    target_include_directories(test_xue PRIVATE ${PROJECT_SOURCE_DIR}/include)

    add_test(NAME test_xue COMMAND test_xue)
endif()
