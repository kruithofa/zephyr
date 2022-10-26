/* main.c - Application main entry point */

/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h"

#define LOG_DEV_TYPE "Peripheral"

struct active_conn_info {
	ATOMIC_DEFINE(flags, CONN_INFO_NUM_FLAGS);
	struct bt_conn *conn_ref;
	uint32_t rcvd_notify_counter;
};

static uint32_t connections_rounds;
static uint32_t notification_size;
static uint8_t simulate_vnd;
static int64_t uptime_ref;
static int64_t tx_notify_time_ref;
static uint32_t tx_notify_counter;
static struct active_conn_info conn_info;
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
static struct bt_conn_le_data_len_param le_data_len_param;
#endif
static uint8_t vnd_value[CHARACTERISTIC_DATA_MAX_LEN];

static struct bt_uuid_128 uuid = BT_UUID_INIT_128(0);
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;

void vnd_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	simulate_vnd = (value == BT_GATT_CCC_NOTIFY) ? 1 : 0;
	if (simulate_vnd) {
		tx_notify_counter = 0;
		tx_notify_time_ref = 0;
	}
}

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
};

void mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
	TERM_INFO("Updated MTU: TX: %d RX: %d bytes", tx, rx);

	if (tx == CONFIG_BT_L2CAP_TX_MTU && rx == CONFIG_BT_L2CAP_TX_MTU) {
		char addr[BT_ADDR_LE_STR_LEN];

		bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

		atomic_set_bit(conn_info.flags, CONN_INFO_MTU_EXCHANGED);
		TERM_SUCCESS("Updating MTU succeeded %s", addr);
	}
}

static struct bt_gatt_cb gatt_callbacks = {.att_mtu_updated = mtu_updated};

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	if (err) {
		memset(&conn_info, 0x00, sizeof(struct active_conn_info));
		FAIL("Connection failed (err 0x%02x)", err);
		return;
	}

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	connections_rounds++;
	conn_info.conn_ref = conn;
	TERM_SUCCESS("Connection %p established : %s", conn, addr);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	memset(&conn_info, 0x00, sizeof(struct active_conn_info));

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	TERM_WARN("Connection @ %p with Peer %s terminated (reason 0x%02x)", conn, addr, reason);

	if (connections_rounds >= 10) {
		TERM_INFO("Connection rounds completed, stopping advertising...");
		bt_le_adv_stop();
	}
}

static bool le_param_req(struct bt_conn *conn, struct bt_le_conn_param *param)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	TERM_PRINT("LE conn param req: %s int (0x%04x (~%u ms), 0x%04x (~%u ms)) lat %d to %d",
		   addr, param->interval_min, (uint32_t)(param->interval_min * 1.25),
		   param->interval_max, (uint32_t)(param->interval_max * 1.25), param->latency,
		   param->timeout);

	return true;
}

static void le_param_updated(struct bt_conn *conn, uint16_t interval, uint16_t latency,
			     uint16_t timeout)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	TERM_INFO("LE conn param updated: %s int 0x%04x (~%u ms) lat %d to %d", addr, interval,
		  (uint32_t)(interval * 1.25), latency, timeout);

	atomic_set_bit(conn_info.flags, CONN_INFO_CONN_PARAMS_UPDATED);
}

#if defined(CONFIG_BT_SMP)
static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		TERM_FAIL("Security for %p failed: %s level %u err %d", conn, addr, level, err);
		return;
	}

	TERM_INFO("Security for %p changed: %s level %u", conn, addr, level);
	atomic_set_bit(conn_info.flags, CONN_INFO_SECURITY_LEVEL_UPDATED);
}
#endif /* CONFIG_BT_SMP */

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
static void le_data_len_updated(struct bt_conn *conn, struct bt_conn_le_data_len_info *info)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	TERM_PRINT("Data length updated: %s max tx %u (%u us) max rx %u (%u us)", addr,
		   info->tx_max_len, info->tx_max_time, info->rx_max_len, info->rx_max_time);

	if (info->rx_max_len == BT_GAP_DATA_LEN_MAX) {
		TERM_INFO("RX Data length flag updated for %s", addr);
		atomic_set_bit(conn_info.flags, CONN_INFO_LL_DATA_LEN_RX_UPDATED);
	}
	if (info->tx_max_len == BT_GAP_DATA_LEN_MAX) {
		TERM_INFO("TX Data length flag updated for %s", addr);
		atomic_set_bit(conn_info.flags, CONN_INFO_LL_DATA_LEN_TX_UPDATED);
	}
}
#endif /* CONFIG_BT_USER_DATA_LEN_UPDATE */

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.le_param_req = le_param_req,
	.le_param_updated = le_param_updated,
#if defined(CONFIG_BT_SMP)
	.security_changed = security_changed,
#endif /* CONFIG_BT_SMP */
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
	.le_data_len_updated = le_data_len_updated,
#endif /* CONFIG_BT_USER_DATA_LEN_UPDATE */
};

static void bt_ready(void)
{
	int err;

	TERM_PRINT("Bluetooth initialized");

	err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		FAIL("Advertising failed to start (err %d)", err);
		return;
	}

	TERM_SUCCESS("Advertising successfully started");
}

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
static uint16_t tx_time_calc(uint8_t phy, uint16_t max_len)
{
	/* Access address + header + payload + MIC + CRC */
	uint16_t total_len = 4 + 2 + max_len + 4 + 3;

	switch (phy) {
	case BT_GAP_LE_PHY_1M:
		/* 1 byte preamble, 8 us per byte */
		return 8 * (1 + total_len);
	case BT_GAP_LE_PHY_2M:
		/* 2 byte preamble, 4 us per byte */
		return 4 * (2 + total_len);
	case BT_GAP_LE_PHY_CODED:
		/* S8: Preamble + CI + TERM1 + 64 us per byte + TERM2 */
		return 80 + 16 + 24 + 64 * (total_len) + 24;
	default:
		return 0;
	}
}

static void update_ll_max_data_length(struct bt_conn *conn, void *data)
{
	if (atomic_test_bit(conn_info.flags, CONN_INFO_LL_DATA_LEN_TX_UPDATED) == false) {
		int err;
		char addr[BT_ADDR_LE_STR_LEN];

		le_data_len_param = *BT_LE_DATA_LEN_PARAM_DEFAULT;

		/* Update LL transmission payload size in bytes*/
		le_data_len_param.tx_max_len = BT_GAP_DATA_LEN_MAX;
		/* Update LL transmission payload time in us*/
		le_data_len_param.tx_max_time =
			tx_time_calc(BT_GAP_LE_PHY_2M, le_data_len_param.tx_max_len);
		TERM_PRINT("Calculated tx time: %d", le_data_len_param.tx_max_time);

		bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

		TERM_PRINT("Updating LL data length for %s...", addr);
		err = bt_conn_le_data_len_update(conn, &le_data_len_param);
		if (err) {
			FAIL("Updating LL data length failed %s", addr);
			return;
		}

		while (atomic_test_bit(conn_info.flags, CONN_INFO_LL_DATA_LEN_TX_UPDATED) ==
		       false) {
			k_sleep(K_MSEC(10));
		}

		TERM_SUCCESS("Updating LL data length succeeded %s", addr);
	}
}
#endif /* CONFIG_BT_USER_DATA_LEN_UPDATE */

static uint8_t notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
			   const void *data, uint16_t length)
{
	const char *data_ptr = (const char *)data + NOTIFICATION_DATA_PREFIX_LEN;
	uint32_t received_counter;
	char addr[BT_ADDR_LE_STR_LEN];

	if (!data) {
		TERM_INFO("[UNSUBSCRIBED]");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	received_counter = strtoul(data_ptr, NULL, 0);

	if ((conn_info.rcvd_notify_counter % 100) == 0) {
		TERM_PRINT("[NOTIFICATION] addr %s conn %p data %s length %u cnt %u", addr, conn,
			   data, length, received_counter);
	}

	__ASSERT(conn_info.rcvd_notify_counter == received_counter,
		 "expected counter : %u , received counter : %u", conn_info.rcvd_notify_counter,
		 received_counter);
	conn_info.rcvd_notify_counter++;

	return BT_GATT_ITER_CONTINUE;
}

static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	int err;
	char uuid_str[BT_UUID_STR_LEN];

	if (!attr) {
		TERM_INFO("Discover complete");
		(void)memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	bt_uuid_to_str(params->uuid, uuid_str, sizeof(uuid_str));

	if (discover_params.type == BT_GATT_DISCOVER_PRIMARY) {
		TERM_PRINT("Primary Service Found");
		memcpy(&uuid, CHARACTERISTIC_UUID, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

		err = bt_gatt_discover(conn, &discover_params);
		if (err) {
			FAIL("Discover failed (err %d)", err);
		}
	} else if (discover_params.type == BT_GATT_DISCOVER_CHARACTERISTIC) {
		TERM_PRINT("Service Characteristic Found");
		memcpy(&uuid, BT_UUID_GATT_CCC, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params.value_handle = bt_gatt_attr_value_handle(attr);

		err = bt_gatt_discover(conn, &discover_params);
		if (err) {
			FAIL("Discover failed (err %d)", err);
		}
	} else {
		subscribe_params.notify = notify_func;
		subscribe_params.value = BT_GATT_CCC_NOTIFY;
		subscribe_params.ccc_handle = attr->handle;

		err = bt_gatt_subscribe(conn, &subscribe_params);
		if (err && err != -EALREADY) {
			FAIL("Subscribe failed (err %d)", err);
		} else {
			char addr[BT_ADDR_LE_STR_LEN];

			bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

			atomic_set_bit(conn_info.flags, CONN_INFO_SUBSCRIBED_TO_SERVICE);
			TERM_INFO("[SUBSCRIBED] addr %s", addr);
		}
	}

	return BT_GATT_ITER_STOP;
}

static void subscribe_to_service(struct bt_conn *conn)
{
#if defined(CONFIG_BT_SMP)
	/* Characterstic subscription requires secuirty level update */
	if (atomic_test_bit(conn_info.flags, CONN_INFO_SECURITY_LEVEL_UPDATED) == false) {
		return;
	}
#endif

	if (atomic_test_bit(conn_info.flags, CONN_INFO_SUBSCRIBED_TO_SERVICE) == false &&
	    atomic_test_bit(conn_info.flags, CONN_INFO_INITIATE_SUBSCRIBTION_REQ) == false) {
		int err;
		char addr[BT_ADDR_LE_STR_LEN];

		bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

		TERM_PRINT("Discovering peer %s primary service", addr);

		memcpy(&uuid, SERVICE_UUID, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.func = discover_func;
		discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
		discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
		discover_params.type = BT_GATT_DISCOVER_PRIMARY;

		err = bt_gatt_discover(conn, &discover_params);
		if (err) {
			FAIL("Discover failed(err %d)", err);
			return;
		}

		atomic_set_bit(conn_info.flags, CONN_INFO_INITIATE_SUBSCRIBTION_REQ);
	}
}

void notify_peer(struct bt_gatt_attr *vnd_ind_attr)
{
	int err;
	bt_addr_le_t local_addr;
	char addr[BT_ADDR_LE_STR_LEN];
	uint32_t dyn_data_size, addr_count;

	/* Check if the peer has subscribed to the service */
	if (bt_gatt_is_subscribed(conn_info.conn_ref, vnd_ind_attr, BT_GATT_CCC_NOTIFY) == false) {
		return;
	}

#if defined(CONFIG_BT_SMP)
	/* Characterstic subscription requires secuirty level update */
	if (atomic_test_bit(conn_info.flags, CONN_INFO_SECURITY_LEVEL_UPDATED) == false) {
		return;
	}
#endif

	/* Control the interval between notifications */
	if (tx_notify_time_ref == 0) {
		tx_notify_time_ref = k_uptime_get();
		return;
	}

	if (tx_notify_counter == 0) {
		if ((k_uptime_get() - tx_notify_time_ref) < 1000) {
			return;
		}
	}

	if ((k_uptime_get() - tx_notify_time_ref) < 100) {
		return;
	}

	dyn_data_size = MIN((bt_gatt_get_mtu(conn_info.conn_ref) - 3), notification_size);
	if (dyn_data_size == 0) {
		TERM_WARN("Invalid MTU size");
		return;
	}

	memset(vnd_value, 0x00, sizeof(vnd_value));

	bt_id_get(&local_addr, &addr_count);
	bt_addr_le_to_str(&local_addr, addr, sizeof(addr));

	snprintk(vnd_value, notification_size, "%s%u %.5s", NOTIFICATION_DATA_PREFIX,
		 tx_notify_counter, addr);
	err = bt_gatt_notify(NULL, vnd_ind_attr, vnd_value, dyn_data_size);
	if (err) {
		TERM_WARN("Couldn't send GATT notification conn %p", conn_info.conn_ref);
		return;
	}

	tx_notify_counter++;
	tx_notify_time_ref = k_uptime_get();
}

void disconnect(void)
{
	int err;

	if (conn_info.conn_ref != NULL) {
		err = bt_conn_disconnect(conn_info.conn_ref, BT_HCI_ERR_REMOTE_POWER_OFF);

		if (err) {
			FAIL("Terminating conn failed (err %d)", err);
		}

		while (conn_info.conn_ref != NULL) {
			k_sleep(K_MSEC(10));
		}
	}
}

void test_peripheral_main(void)
{
	int err;
	struct bt_gatt_attr *vnd_ind_attr;

	connections_rounds = 0;
	memset(&conn_info, 0x00, sizeof(struct active_conn_info));

	err = bt_enable(NULL);
	if (err) {
		FAIL("Bluetooth init failed (err %d)", err);
		return;
	}

	bt_ready();

	bt_gatt_cb_register(&gatt_callbacks);

	vnd_ind_attr = common_get_prim_srvc_attr();

	while (true) {

		/* wait for connection from central */
		while (conn_info.conn_ref == NULL) {
			k_sleep(K_MSEC(10));
			uptime_ref = k_uptime_get();
		}

		subscribe_to_service(conn_info.conn_ref);
		notify_peer(vnd_ind_attr);

		if (uptime_ref && (k_uptime_get() - uptime_ref) >= DISCONNECT_TIMEOUT_MS) {
			uptime_ref = 0;
			disconnect();
		}

		k_sleep(K_MSEC(10));
		continue;

		if (conn_info.conn_ref == NULL) {
			k_sleep(K_MSEC(10));
			continue;
		}

#if defined(CONFIG_BT_SMP)
		if (atomic_test_bit(conn_info.flags, CONN_INFO_SECURITY_LEVEL_UPDATED) == false) {
			k_sleep(K_MSEC(10));
			continue;
		}
#endif

		if (atomic_test_bit(conn_info.flags, CONN_INFO_CONN_PARAMS_UPDATED) == false) {
			k_sleep(K_MSEC(10));
			continue;
		}

		if (atomic_test_bit(conn_info.flags, CONN_INFO_MTU_EXCHANGED) == false) {
			k_sleep(K_MSEC(10));
			continue;
		}

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
		bt_conn_foreach(BT_CONN_TYPE_LE, update_ll_max_data_length, NULL);
#endif /* CONFIG_BT_USER_DATA_LEN_UPDATE */

		subscribe_to_service(conn_info.conn_ref);

		if (atomic_test_bit(conn_info.flags, CONN_INFO_SUBSCRIBED_TO_SERVICE) == false) {
			k_sleep(K_MSEC(10));
			continue;
		}

		k_sleep(K_SECONDS(1));

		/* Vendor indication simulation */
		if (simulate_vnd && vnd_ind_attr) {
			if (tx_notify_counter == 0) {
				uptime_ref = k_uptime_get();
			}

			notify_peer(vnd_ind_attr);

			if ((k_uptime_get() - uptime_ref) >= DISCONNECT_TIMEOUT_MS) {
				disconnect();
			}
		}
	}
}

void test_init(void)
{
	extern enum bst_result_t bst_result;

	TERM_INFO("Initializing Test");
	bst_result = Passed;
}

static void test_args(int argc, char **argv)
{
	notification_size = NOTIFICATION_DATA_LEN;

	if (argc >= 1) {
		char const *ptr;

		ptr = strstr(argv[0], "notify_size=");
		if (ptr != NULL) {
			ptr += strlen("notify_size=");
			notification_size = atol(ptr);
			notification_size = MIN(NOTIFICATION_DATA_LEN, notification_size);
		}
	}

	bs_trace_raw(0, "Notification data size : %d\n", notification_size);
}

static const struct bst_test_instance test_def[] = {
	{
		.test_id = "peripheral",
		.test_descr = "Peripheral Connection Stress",
		.test_args_f = test_args,
		.test_post_init_f = test_init,
		.test_main_f = test_peripheral_main
	},
	BSTEST_END_MARKER
};

struct bst_test_list *test_main_conn_stress_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, test_def);
}

extern struct bst_test_list *test_main_conn_stress_install(struct bst_test_list *tests);

bst_test_install_t test_installers[] = {
	test_main_conn_stress_install,
	NULL
};

void main(void)
{
	bst_main();
}
