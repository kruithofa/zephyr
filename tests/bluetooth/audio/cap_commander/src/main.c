/* main.c - Application main entry point */

/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <zephyr/bluetooth/audio/cap.h>
#include <zephyr/bluetooth/audio/vcp.h>
#include <zephyr/fff.h>

#include "bluetooth.h"
#include "cap_commander.h"
#include "conn.h"
#include "expects_util.h"
#include "cap_mocks.h"

DEFINE_FFF_GLOBALS;

static void mock_init_rule_before(const struct ztest_unit_test *test, void *fixture)
{
	mock_cap_commander_init();
	mock_bt_csip_init();
	mock_bt_vcp_init();
	mock_bt_vocs_init();
}

static void mock_destroy_rule_after(const struct ztest_unit_test *test, void *fixture)
{
	mock_cap_commander_cleanup();
	mock_bt_csip_cleanup();
	mock_bt_vcp_cleanup();
	mock_bt_vocs_cleanup();
}

ZTEST_RULE(mock_rule, mock_init_rule_before, mock_destroy_rule_after);


