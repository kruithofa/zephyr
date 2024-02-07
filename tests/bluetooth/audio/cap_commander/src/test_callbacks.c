/* test_callbacks.c - unit tests for callback related functionality */

/*
 * Copyright (c) 2023 - 2024 Nordic Semiconductor ASA
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

static struct cap_commander_test_cb_fixture {
	struct bt_conn conns[CONFIG_BT_MAX_CONN];
};

static void test_conn_init(struct bt_conn *conn)
{
	conn->index = 0;
	conn->info.type = BT_CONN_TYPE_LE;
	conn->info.role = BT_CONN_ROLE_PERIPHERAL;
	conn->info.state = BT_CONN_STATE_CONNECTED;
	conn->info.security.level = BT_SECURITY_L2;
	conn->info.security.enc_key_size = BT_ENC_KEY_SIZE_MAX;
	conn->info.security.flags = BT_SECURITY_FLAG_OOB | BT_SECURITY_FLAG_SC;
}

static void cap_commander_test_cb_fixture_init(struct cap_commander_test_cb_fixture *fixture)
{
	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		test_conn_init(&fixture->conns[i]);
	}
}

static void *cap_commander_test_cb_setup(void)
{
	struct cap_commander_test_cb_fixture *fixture;

	fixture = malloc(sizeof(*fixture));
	zassert_not_null(fixture);

	return fixture;
}

static void cap_commander_test_cb_before(void *f)
{
	memset(f, 0, sizeof(struct cap_commander_test_cb_fixture));
	cap_commander_test_cb_fixture_init(f);
}

static void cap_commander_test_cb_after(void *f)
{
	struct cap_commander_test_cb_fixture *fixture = f;

	bt_cap_commander_unregister_cb(&mock_cap_commander_cb);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		mock_bt_conn_disconnected(&fixture->conns[i], BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void cap_commander_test_cb_teardown(void *f)
{
	free(f);
}

ZTEST_SUITE(cap_commander_test_cb, NULL, cap_commander_test_cb_setup,
	    cap_commander_test_cb_before, cap_commander_test_cb_after,
	    cap_commander_test_cb_teardown);

ZTEST_F(cap_commander_test_cb, test_commander_register_cb)
{
	int err;

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_cb, test_commander_register_cb_inval_param_null)
{
	int err;

	err = bt_cap_commander_register_cb(NULL);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_cb, test_commander_register_cb_inval_double_register)
{
	int err;

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(-EALREADY, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_cb, test_commander_unregister_cb)
{
	int err;

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_unregister_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_cb, test_commander_unregister_cb_inval_param_null)
{
	int err;

	err = bt_cap_commander_unregister_cb(NULL);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_cb, test_commander_unregister_cb_inval_double_unregister)
{
	int err;

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_unregister_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_unregister_cb(&mock_cap_commander_cb);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_cb, test_commander_discover)
{
	int err;

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	zexpect_call_count("bt_cap_commander_cb.discovery_complete", ARRAY_SIZE(fixture->conns),
			   mock_cap_commander_discovery_complete_cb_fake.call_count);
}

ZTEST_F(cap_commander_test_cb, test_commander_discover_inval_param_null)
{
	int err;

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_discover(NULL);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

