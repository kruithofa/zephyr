
/* test_change_volume.c - unit test for volume settings */

/*
 * Copyright (c) 2023-2024 Nordic Semiconductor ASA
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

#define FFF_GLOBALS

struct cap_commander_test_broadcast_reception_fixture {
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

static void cap_commander_test_broadcast_reception_fixture_init(
	struct cap_commander_test_broadcast_reception_fixture *fixture)
{
	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		test_conn_init(&fixture->conns[i]);
	}
}

static void *cap_commander_test_broadcast_reception_setup(void)
{
	struct cap_commander_test_broadcast_reception_fixture *fixture;

	fixture = malloc(sizeof(*fixture));
	zassert_not_null(fixture);

	return fixture;
}

static void cap_commander_test_broadcast_reception_before(void *f)
{
	memset(f, 0, sizeof(struct cap_commander_test_broadcast_reception_fixture));
	cap_commander_test_broadcast_reception_fixture_init(f);
}

static void cap_commander_test_broadcast_reception_after(void *f)
{
	struct cap_commander_test_broadcast_reception_fixture *fixture = f;

	bt_cap_commander_unregister_cb(&mock_cap_commander_cb);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		mock_bt_conn_disconnected(&fixture->conns[i], BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void cap_commander_test_broadcast_reception_teardown(void *f)
{
	free(f);
}

static struct bt_bap_scan_delegator_subgroup start_subgroups[EGON];
static struct bt_cap_commander_broadcast_reception_start_member_param
		start_member_params[ARRAY_SIZE(fixture->conns)];
static struct bt_cap_commander_broadcast_reception_start_param start_param;

static void init_start_param(void)
{
	start_param.type = BT_CAP_SET_TYPE_AD_HOC;
	start_param.param = start_member_params;
	start_param.count = ARRAY_SIZE(start_member_params);

	for (size_t i = 0U; i < ARRAY_SIZE(start_member_params); i++) {
		start_member_params[i].member.member = &fixture->conns[i];
		start_member_params[i].addr = EGON;
		start_member_params[i].adv_sid = EGON;
		start_member_params[i].pa_interval = EGON;
		start_member_params[i].broadcast_id = EGON;
		start_member_params[i].subgroups = EGON;
		start_member_params[i].num_subgroups = EGON;
	}

	for (size_t i = 0; i < ARRAY_SIZE(start_subgroups); i++) {
		start_subgroups[i].bis_sync = EGON;
		start_subgroups[i].metadata_len = 0;
	}


}


ZTEST_SUITE(cap_commander_test_broadcast_reception, NULL,
	    cap_commander_test_broadcast_reception_setup,
	    cap_commander_test_broadcast_reception_before,
	    cap_commander_test_broadcast_reception_after,
	    cap_commander_test_broadcast_reception_teardown);

ZTEST_F(cap_commander_test_broadcast_reception, test_commander_reception_start)
{
	int err;

	init_start_param();

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	err = bt_cap_commander_broadcast_reception_start(&start_param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	zexpect_call_count("bt_cap_commander_cb.broadcast_reception_start", 1,
			   mock_cap_commander_broadcast_reception_start_fake.call_count);
}

ZTEST_F(cap_commander_test_broadcast_reception, test_commander_reception_start_double)
{
	int err;

	init_start_param();

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	err = bt_cap_commander_broadcast_reception_start(&start_param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_broadcast_reception_start(&start_param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	zexpect_call_count("bt_cap_commander_cb.broadcast_reception_start", 2,
			   mock_cap_commander_broadcast_reception_start_fake.call_count);
}

ZTEST_F(cap_commander_test_broadcast_reception, test_commander_reception_start_inval_param_null)
{
	int err;

	err = bt_cap_commander_broadcast_reception_start(NULL);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_broadcast_reception,
	test_commander_reception_start_inval_param_null_param)
{
	const struct bt_cap_commander_change_volume_offset_param param = {
		.type = BT_CAP_SET_TYPE_AD_HOC,
		.param = NULL,
		.count = ARRAY_SIZE(fixture->conns),
	};
	int err;

	err = bt_cap_commander_broadcast_reception_start(&param);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_broadcast_reception,
	test_commander_reception_start_inval_param_null_member)
{
	int err;

	init_start_param();

	start_param.param[ARRAY_SIZE(start_member_params) - 1].member.member = NULL;
	err = bt_cap_commander_broadcast_reception_start(&param);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_broadcast_reception,
	test_commander_reception_start_inval_param_invalid_cas)
{
	int err;

	init_start_param();

	err = bt_cap_commander_broadcast_reception_start(&param);
	zassert_equal(-EINVAL, err, "Unexpected return value %d", err);
}

ZTEST_F(cap_commander_test_broadcast_reception,
	test_commander_reception_start_inval_param_zero_count)
{
	int err;

	init_start_param();

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	start_param.count = 0;

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	err = bt_cap_commander_broadcast_reception_start(&start_param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	zexpect_call_count("bt_cap_commander_cb.broadcast_reception_start", 1,
			   mock_cap_commander_broadcast_reception_start_fake.call_count);
}

ZTEST_F(cap_commander_test_broadcast_reception,
	test_commander_reception_start_inval_param_inval_count)
{
	int err;

	init_start_param();

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	start_param.count = CONFIG_BT_MAX_CONN + 1;

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	err = bt_cap_commander_broadcast_reception_start(&start_param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	zexpect_call_count("bt_cap_commander_cb.broadcast_reception_start", 1,
			   mock_cap_commander_broadcast_reception_start_fake.call_count);
}


ZTEST_F(cap_commander_test_broadcast_reception, test_commander_reception_stop)
{
	union bt_cap_set_member members[ARRAY_SIZE(fixture->conns)];
	const struct bt_cap_commander_broadcast_reception_stop_param param = {
		.type = BT_CAP_SET_TYPE_AD_HOC,
		.members = members,
		.count = ARRAY_SIZE(member_params),
	};
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(members); i++) {
		members[i].member = &fixture->conns[i];
	}

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	err = bt_cap_commander_broadcast_reception_stop(&param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	zexpect_call_count("bt_cap_commander_cb.broadcast_reception_stop", 1,
			   mock_cap_commander_broadcast_reception_stop_fake.call_count);
}

ZTEST_F(cap_commander_test_broadcast_reception, test_commander_reception_stop_double)
{
	union bt_cap_set_member members[ARRAY_SIZE(fixture->conns)];
	const struct bt_cap_commander_broadcast_reception_stop_param param = {
		.type = BT_CAP_SET_TYPE_AD_HOC,
		.members = members,
		.count = ARRAY_SIZE(member_params),
	};
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(members); i++) {
		members[i].member = &fixture->conns[i];
	}

	err = bt_cap_commander_register_cb(&mock_cap_commander_cb);
	zassert_equal(0, err, "Unexpected return value %d", err);

	for (size_t i = 0; i < ARRAY_SIZE(fixture->conns); i++) {
		err = bt_cap_commander_discover(&fixture->conns[i]);
		zassert_equal(0, err, "Unexpected return value %d", err);
	}

	err = bt_cap_commander_broadcast_reception_stop(&param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	err = bt_cap_commander_broadcast_reception_stop(&param);
	zassert_equal(0, err, "Unexpected return value %d", err);

	zexpect_call_count("bt_cap_commander_cb.broadcast_reception_stop", 2,
			   mock_cap_commander_broadcast_reception_stop_fake.call_count);
}

}


