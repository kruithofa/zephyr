/*
 * Copyright (c) 2020 Demant
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <zephyr/ztest.h>

#define ULL_LLCP_UNITTEST

#include <zephyr/bluetooth/hci.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>
#include "hal/ccm.h"

#include "util/util.h"
#include "util/mem.h"
#include "util/memq.h"
#include "util/dbuf.h"

#include "pdu.h"
#include "ll.h"
#include "ll_settings.h"

#include "lll.h"
#include "lll_df_types.h"
#include "lll_conn.h"
#include "lll_conn_iso.h"

#include "ull_tx_queue.h"

#include "isoal.h"
#include "ull_iso_types.h"
#include "ull_conn_iso_types.h"
#include "ull_conn_types.h"
#include "ull_llcp.h"
#include "ull_conn_internal.h"
#include "ull_llcp_internal.h"

#include "helper_pdu.h"
#include "helper_util.h"

struct ll_conn conn;
static void conn_update_setup(void *data)
{
	test_setup(&conn);

	/* Initialize lll conn parameters (different from new) */
	struct lll_conn *lll = &conn.lll;

	lll->interval = 0;
	lll->latency = 0;
	conn.supervision_reload = 1U;
}

/*
 * we can not skip the internal tests,
 * which are testing static procedures in
 * ull_llcp_*
 * therefor we need to repeat them here
 */
ZTEST_SUITE(internal, NULL, NULL, NULL, NULL, NULL);
ZTEST_SUITE(central_loc, NULL, NULL, conn_update_setup, NULL, NULL);
ZTEST_SUITE(central_rem, NULL, NULL, conn_update_setup, NULL, NULL);
ZTEST_SUITE(periph_loc, NULL, NULL, conn_update_setup, NULL, NULL);
ZTEST_SUITE(periph_rem, NULL, NULL, conn_update_setup, NULL, NULL);
