/*
 * Common functions and helpers for connection stress tests
 *
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/check.h>
#include <zephyr/sys/printk.h>
#include <zephyr/types.h>

#include "bstests.h"
#include "bs_types.h"
#include "bs_tracing.h"
#include "bstests.h"
#include "bs_pc_backchannel.h"

#define TERM_PRINT(fmt, ...)   printk("\e[39m[%s] : " fmt "\e[39m\n", LOG_DEV_TYPE, ##__VA_ARGS__)
#define TERM_INFO(fmt, ...)    printk("\e[94m[%s] : " fmt "\e[39m\n", LOG_DEV_TYPE, ##__VA_ARGS__)
#define TERM_SUCCESS(fmt, ...) printk("\e[92m[%s] : " fmt "\e[39m\n", LOG_DEV_TYPE, ##__VA_ARGS__)
#define TERM_WARN(fmt, ...)                                                                        \
	printk("\e[93m[%s] %s:%d : " fmt "\e[39m\n", LOG_DEV_TYPE, __func__, __LINE__,             \
	       ##__VA_ARGS__)
#define TERM_FAIL(fmt, ...)                                                                        \
	printk("\e[91m[%s] %s:%d : " fmt "\e[39m\n", LOG_DEV_TYPE, __func__, __LINE__,             \
	       ##__VA_ARGS__)

#define DEFAULT_CONN_INTERVAL	   20

#define DISCONNECT_TIMEOUT_S	   70
#define DISCONNECT_TIMEOUT_MS	   (DISCONNECT_TIMEOUT_S * 1000)

#define PERIPHERAL_DEVICE_NAME	   "Zephyr Peripheral"
#define PERIPHERAL_DEVICE_NAME_LEN (sizeof(PERIPHERAL_DEVICE_NAME) - 1)

#define NOTIFICATION_DATA_PREFIX     "cnt:"
#define NOTIFICATION_DATA_PREFIX_LEN (sizeof(NOTIFICATION_DATA_PREFIX) - 1)

#define CHARACTERISTIC_DATA_MAX_LEN 260
#define NOTIFICATION_DATA_LEN	    MAX(200, (CONFIG_BT_L2CAP_TX_MTU - 3))
BUILD_ASSERT(NOTIFICATION_DATA_LEN <= CHARACTERISTIC_DATA_MAX_LEN);

#define SERVICE_UUID_VAL BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcdef0)

#define CHARACTERISTIC_UUID_VAL                                                                    \
	BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x5678, 0x1234, 0x56789abcdef1)

#define SERVICE_UUID	    BT_UUID_DECLARE_128(SERVICE_UUID_VAL)
#define CHARACTERISTIC_UUID BT_UUID_DECLARE_128(CHARACTERISTIC_UUID_VAL)

#define CREATE_FLAG(flag) static atomic_t flag = (atomic_t)false
#define SET_FLAG(flag) (void)atomic_set(&flag, (atomic_t)true)
#define UNSET_FLAG(flag) (void)atomic_set(&flag, (atomic_t)false)
#define TEST_FLAG(flag) (atomic_get(&flag) == (atomic_t)true)
#define WAIT_FOR_FLAG_SET(flag)		   \
	while (!(bool)atomic_get(&flag)) { \
		(void)k_sleep(K_MSEC(1));  \
	}
#define WAIT_FOR_FLAG_UNSET(flag)	  \
	while ((bool)atomic_get(&flag)) { \
		(void)k_sleep(K_MSEC(1)); \
	}

#define FAIL(fmt, ...)                                                                             \
	do {                                                                                       \
		bst_result = Failed;                                                               \
		bs_trace_error_time_line("[%s] " fmt "\n", LOG_DEV_TYPE, ##__VA_ARGS__);           \
	} while (0)

#define PASS(...)                                                                                  \
	do {                                                                                       \
		bst_result = Passed;                                                               \
		bs_trace_info_time(1, __VA_ARGS__);                                                \
	} while (0)

#define ASSERT(expr, fmt, ...)                                                                     \
	if (!(expr)) {                                                                             \
		FAIL(fmt, __VA_ARGS__);                                                            \
	}

enum {
	CONN_INFO_SECURITY_LEVEL_UPDATED,
	CONN_INFO_CONN_PARAMS_UPDATED,
	CONN_INFO_LL_DATA_LEN_TX_UPDATED,
	CONN_INFO_LL_DATA_LEN_RX_UPDATED,
	CONN_INFO_INITIATE_MTU_EXCHANGE_REQ,
	CONN_INFO_MTU_EXCHANGED,
	CONN_INFO_INITIATE_SUBSCRIBTION_REQ,
	CONN_INFO_SUBSCRIBED_TO_SERVICE,
	/* Total number of flags - must be at the end of the enum */
	CONN_INFO_NUM_FLAGS,
};

extern enum bst_result_t bst_result;

/**
 * @brief Get primary service attribute
 */
struct bt_gatt_attr *common_get_prim_srvc_attr(void);
