cmake_minimum_required(VERSION 3.0.0)
project(ast-bcrypt VERSION 0.1.0)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CTest)
enable_testing()

add_executable(ast-bcrypt main.cpp)

target_link_libraries (${PROJECT_NAME} -lbcrypt)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
