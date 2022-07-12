# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

if (NOT BOARD STREQUAL unit_testing)
  message(FATAL_ERROR "This project can only be used with '-DBOARD=unit_testing'.")
endif()

if (CONFIG_BT_CTLR_CONN_PARAM_REQ)
  FILE(GLOB SOURCES
    src/main.c
    src/test_param_req.c
  )
else()
  FILE(GLOB SOURCES
    src/main.c
    src/test_no_param_req.c
  )
endif()

project(bluetooth_ctrl_ull_conn_update)
find_package(Zephyr COMPONENTS unittest HINTS $ENV{ZEPHYR_BASE})
include(${ZEPHYR_BASE}/tests/bluetooth/controller/common/defaults_cmake.txt)
target_sources(testbinary PRIVATE ${ll_sw_sources} ${mock_sources} ${common_sources})
