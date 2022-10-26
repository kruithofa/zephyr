/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h"

/* Custom Service Variables */
static struct bt_uuid_128 vnd_uuid = BT_UUID_INIT_128(SERVICE_UUID_VAL);
static struct bt_uuid_128 vnd_enc_uuid = BT_UUID_INIT_128(CHARACTERISTIC_UUID_VAL);

__weak void vnd_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
}

/* Vendor Primary Service Declaration */
#if defined(CONFIG_BT_SMP)
BT_GATT_SERVICE_DEFINE(
	vnd_svc, BT_GATT_PRIMARY_SERVICE(&vnd_uuid),
	BT_GATT_CHARACTERISTIC(&vnd_enc_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ_ENCRYPT | BT_GATT_PERM_WRITE_ENCRYPT, NULL, NULL,
			       NULL),
	BT_GATT_CCC(vnd_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE_ENCRYPT),
);
#else
BT_GATT_SERVICE_DEFINE(
	vnd_svc, BT_GATT_PRIMARY_SERVICE(&vnd_uuid),
	BT_GATT_CHARACTERISTIC(&vnd_enc_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE, NULL, NULL,
			       NULL),
	BT_GATT_CCC(vnd_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);
#endif

struct bt_gatt_attr *common_get_prim_srvc_attr(void)
{
	struct bt_gatt_attr *attr;

	attr = bt_gatt_find_by_uuid(vnd_svc.attrs, vnd_svc.attr_count, &vnd_enc_uuid.uuid);

	return attr;
}
