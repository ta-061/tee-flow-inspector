cmake_minimum_required(VERSION 3.5)
project(ta_project C)

# ソースファイルをまとめてライブラリ化
file(GLOB TA_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
add_library(ta_lib STATIC ${TA_SRCS})

# include ディレクトリを指定
target_include_directories(ta_lib PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)