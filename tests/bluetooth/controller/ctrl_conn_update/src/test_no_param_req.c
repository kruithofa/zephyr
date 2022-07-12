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

/* Default connection values */
#define INTVL_MIN 6U /* multiple of 1.25 ms (min 6, max 3200) */
#define INTVL_MAX 6U /* multiple of 1.25 ms (min 6, max 3200) */
#define LATENCY 1U
#define TIMEOUT 10U /* multiple of 10 ms (min 10, max 3200) */

/* Default conn_update_ind PDU */
struct pdu_data_llctrl_conn_update_ind conn_update_ind = { .win_size = 1U,
							   .win_offset = 0U,
							   .interval = INTVL_MAX,
							   .latency = LATENCY,
							   .timeout = TIMEOUT,
							   .instant = 6U };

/* Default conn_param_req PDU */
struct pdu_data_llctrl_conn_param_req conn_param_req = { .interval_min = INTVL_MIN,
							 .interval_max = INTVL_MAX,
							 .latency = LATENCY,
							 .timeout = TIMEOUT,
							 .preferred_periodicity = 0U,
							 .reference_conn_event_count = 0u,
							 .offset0 = 0x0000U,
							 .offset1 = 0xffffU,
							 .offset2 = 0xffffU,
							 .offset3 = 0xffffU,
							 .offset4 = 0xffffU,
							 .offset5 = 0xffffU };


/* Default conn_update_ind PDU (B) */
struct pdu_data_llctrl_conn_update_ind conn_update_ind_B = {
	.win_size = 1U,
	.win_offset = 0U,
	.interval = INTVL_MAX,
	.latency = LATENCY + 1U, /* differentiate parameter */
	.timeout = TIMEOUT + 1U, /* differentiate parameter */
	.instant = 6U
};

struct pdu_data_llctrl_conn_update_ind *cu_ind_B = &conn_update_ind_B;

extern struct ll_conn conn;

static bool is_instant_reached(struct ll_conn *conn, uint16_t instant)
{
	return ((event_counter(conn) - instant) & 0xFFFF) <= 0x7FFF;
}

/*
 * Parameter Request Procedure not supported.
 * Central-initiated Connection Update procedure.
 * Central requests update of LE connection.
 *
 * +-----+                    +-------+                    +-----+
 * | UT  |                    | LL_C  |                    | LT  |
 * +-----+                    +-------+                    +-----+
 *    |                           |                           |
 *    | LE Connection Update      |                           |
 *    |-------------------------->|                           |
 *    |                           | LL_CONNECTION_UPDATE_IND  |
 *    |                           |-------------------------->|
 *    |                           |                           |
 *    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *    |                           |                           |
 *    |      LE Connection Update |                           |
 *    |                  Complete |                           |
 *    |<--------------------------|                           |
 *    |                           |                           |
 *    | (If conn. parameters are  |                           |
 *    |  unchanged, host should   |                           |
 *    |  not receive a ntf.)      |                           |
 *    |                           |                           |
 */
ZTEST(central_loc, test_conn_update_central_loc_accept_no_param_req)
{
	uint8_t err;
	struct node_tx *tx;
	struct node_rx_pdu *ntf;
	struct pdu_data *pdu;
	uint16_t instant;

	/* Test with and without parameter change  */
	uint8_t parameters_changed = 1U;

	struct node_rx_pu cu = { .status = BT_HCI_ERR_SUCCESS };

	/* Role */
	test_set_role(&conn, BT_HCI_ROLE_CENTRAL);

	/* Connect */
	ull_cp_state_set(&conn, ULL_CP_CONNECTED);

	do {
		/* Initiate a Connection Update Procedure */
		err = ull_cp_conn_update(&conn, INTVL_MIN, INTVL_MAX, LATENCY, TIMEOUT);
		zassert_equal(err, BT_HCI_ERR_SUCCESS, NULL);

		/* Prepare */
		event_prepare(&conn);

		/* Tx Queue should have one LL Control PDU */
		conn_update_ind.instant = event_counter(&conn) + 6U;
		lt_rx(LL_CONNECTION_UPDATE_IND, &conn, &tx, &conn_update_ind);
		lt_rx_q_is_empty(&conn);

		/* Done */
		event_done(&conn);

		/* Release Tx */
		ull_cp_release_tx(&conn, tx);

		/* Save Instant */
		pdu = (struct pdu_data *)tx->pdu;
		instant = sys_le16_to_cpu(pdu->llctrl.conn_update_ind.instant);

		/* */
		while (!is_instant_reached(&conn, instant)) {
			/* Prepare */
			event_prepare(&conn);

			/* Tx Queue should NOT have a LL Control PDU */
			lt_rx_q_is_empty(&conn);

			/* Done */
			event_done(&conn);

			/* There should NOT be a host notification */
			ut_rx_q_is_empty();
		}

		/* Prepare */
		event_prepare(&conn);

		/* Tx Queue should NOT have a LL Control PDU */
		lt_rx_q_is_empty(&conn);

		/* Done */
		event_done(&conn);

		if (parameters_changed == 0U) {
			/* There should NOT be a host notification */
			ut_rx_q_is_empty();
		} else {
			/* There should be one host notification */
			ut_rx_node(NODE_CONN_UPDATE, &ntf, &cu);
			ut_rx_q_is_empty();

			/* Release Ntf */
			ull_cp_release_ntf(ntf);
		}
	} while (parameters_changed-- > 0U);

	zassert_equal(ctx_buffers_free(), test_ctx_buffers_cnt(),
		      "Free CTX buffers %d", ctx_buffers_free());
}

/*
 * Parameter Request Procedure not supported.
 * Peripheral-initiated Connection Update/Connection Parameter Request procedure
 * Central receives Connection Update parameters.
 *
 * +-----+                    +-------+                    +-----+
 * | UT  |                    | LL_C  |                    | LT  |
 * +-----+                    +-------+                    +-----+
 *    |                           |                           |
 *    |                           |  LL_CONNECTION_UPDATE_IND |
 *    |                           |<--------------------------|
 *    |                           |                           |
 *    |                           |           LL_UNKNOWN_RSP  |
 *    |                           |-------------------------->|
 *    |                           |                           |
 *    |                           |                           |
 *    |                           |  LL_CONNECTION_PARAM_REQ  |
 *    |                           |<--------------------------|
 *    |                           |                           |
 *    |                           |           LL_UNKNOWN_RSP  |
 *    |                           |-------------------------->|
 *    |                           |                           |
 *    |                           |                           |
 */
ZTEST(central_rem, test_conn_update_central_rem_unknown_no_param_req)
{
	struct node_tx *tx;

	struct pdu_data_llctrl_unknown_rsp unknown_rsp = {
		.type = PDU_DATA_LLCTRL_TYPE_CONN_UPDATE_IND
	};

	/* Role */
	test_set_role(&conn, BT_HCI_ROLE_CENTRAL);

	/* Connect */
	ull_cp_state_set(&conn, ULL_CP_CONNECTED);

	/* Prepare */
	event_prepare(&conn);

	/* Rx */
	lt_tx(LL_CONNECTION_UPDATE_IND, &conn, &conn_update_ind);

	/* Done */
	event_done(&conn);

	/* Prepare */
	event_prepare(&conn);

	/* Tx Queue should have one LL Control PDU */
	lt_rx(LL_UNKNOWN_RSP, &conn, &tx, &unknown_rsp);
	lt_rx_q_is_empty(&conn);

	/* Done */
	event_done(&conn);

	/* There should NOT be a host notification */
	ut_rx_q_is_empty();

	zassert_equal(ctx_buffers_free(), test_ctx_buffers_cnt(),
		      "Free CTX buffers %d", ctx_buffers_free());

	/* Check UNKNOWN_RSP on Connection Parameter Request */
	unknown_rsp.type = PDU_DATA_LLCTRL_TYPE_CONN_PARAM_REQ;
	/* Prepare */
	event_prepare(&conn);

	/* Rx */
	lt_tx(LL_CONNECTION_PARAM_REQ, &conn, &conn_param_req);

	/* Done */
	event_done(&conn);

	/* Prepare */
	event_prepare(&conn);

	/* Tx Queue should have one LL Control PDU */
	lt_rx(LL_UNKNOWN_RSP, &conn, &tx, &unknown_rsp);
	lt_rx_q_is_empty(&conn);

	/* Done */
	event_done(&conn);

	/* There should NOT be a host notification */
	ut_rx_q_is_empty();

	zassert_equal(ctx_buffers_free(), test_ctx_buffers_cnt(),
		      "Free CTX buffers %d", ctx_buffers_free());

}

/*
 * Parameter Request Procedure not supported.
 * Peripheral-initiated Connection Update/Connection Parameter Request procedure
 * Central receives Connection Update parameters.
 *
 * +-----+                    +-------+                    +-----+
 * | UT  |                    | LL_M  |                    | LT  |
 * +-----+                    +-------+                    +-----+
 *    |                           |                           |
 *    |                           |                           |
 *    |                           |  LL_CONNECTION_PARAM_REQ  |
 *    |                           |<--------------------------|
 *    |                           |                           |
 *    |                           |           LL_UNKNOWN_RSP  |
 *    |                           |-------------------------->|
 *    |                           |                           |
 *    |                           |                           |
 */
ZTEST(periph_rem, test_conn_update_periph_rem_unknown_no_param_req)
{
	struct node_tx *tx;

	struct pdu_data_llctrl_unknown_rsp unknown_rsp = {
		.type = PDU_DATA_LLCTRL_TYPE_CONN_PARAM_REQ
	};

	/* Role */
	test_set_role(&conn, BT_HCI_ROLE_PERIPHERAL);

	/* Connect */
	ull_cp_state_set(&conn, ULL_CP_CONNECTED);

	/* Prepare */
	event_prepare(&conn);

	/* Rx */
	lt_tx(LL_CONNECTION_PARAM_REQ, &conn, &conn_param_req);

	/* Done */
	event_done(&conn);

	/* Prepare */
	event_prepare(&conn);

	/* Tx Queue should have one LL Control PDU */
	lt_rx(LL_UNKNOWN_RSP, &conn, &tx, &unknown_rsp);
	lt_rx_q_is_empty(&conn);

	/* Done */
	event_done(&conn);

	/* There should NOT be a host notification */
	ut_rx_q_is_empty();

	zassert_equal(ctx_buffers_free(), test_ctx_buffers_cnt(),
		      "Free CTX buffers %d", ctx_buffers_free());

}

/*
 * Parameter Request Procedure not supported.
 * Central-initiated Connection Update procedure.
 * Peripheral receives Connection Update parameters.
 *
 * +-----+                    +-------+                    +-----+
 * | UT  |                    | LL_P  |                    | LT  |
 * +-----+                    +-------+                    +-----+
 *    |                           |                           |
 *    |                           |  LL_CONNECTION_UPDATE_IND |
 *    |                           |<--------------------------|
 *    |                           |                           |
 *    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *    |                           |                           |
 *    |      LE Connection Update |                           |
 *    |                  Complete |                           |
 *    |<--------------------------|                           |
 *    |                           |                           |
 *    | (If conn. parameters are  |                           |
 *    |  unchanged, host should   |                           |
 *    |  not receive a ntf.)      |                           |
 *    |                           |                           |
 */
ZTEST(periph_rem, test_conn_update_periph_rem_accept_no_param_req)
{
	struct node_rx_pdu *ntf;
	uint16_t instant;

	/* Test with and without parameter change  */
	uint8_t parameters_changed = 1U;

	struct node_rx_pu cu = { .status = BT_HCI_ERR_SUCCESS };

	/* Role */
	test_set_role(&conn, BT_HCI_ROLE_PERIPHERAL);

	/* Connect */
	ull_cp_state_set(&conn, ULL_CP_CONNECTED);

	do {
		/* Prepare */
		event_prepare(&conn);

		/* Rx */
		conn_update_ind.instant = event_counter(&conn) + 6U;
		instant = conn_update_ind.instant;
		lt_tx(LL_CONNECTION_UPDATE_IND, &conn, &conn_update_ind);

		/* Done */
		event_done(&conn);

		/* */
		while (!is_instant_reached(&conn, instant)) {
			/* Prepare */
			event_prepare(&conn);

			/* Tx Queue should NOT have a LL Control PDU */
			lt_rx_q_is_empty(&conn);

			/* Done */
			event_done(&conn);

			/* There should NOT be a host notification */
			ut_rx_q_is_empty();
		}

		/* Prepare */
		event_prepare(&conn);

		/* Tx Queue should NOT have a LL Control PDU */
		lt_rx_q_is_empty(&conn);

		/* Done */
		event_done(&conn);

		if (parameters_changed == 0U) {
			/* There should NOT be a host notification */
			ut_rx_q_is_empty();
		} else {
			/* There should be one host notification */
			ut_rx_node(NODE_CONN_UPDATE, &ntf, &cu);
			ut_rx_q_is_empty();

			/* Release Ntf */
			ull_cp_release_ntf(ntf);
		}
	} while (parameters_changed-- > 0U);

	zassert_equal(ctx_buffers_free(), test_ctx_buffers_cnt(),
		      "Free CTX buffers %d", ctx_buffers_free());
}

/*
 * Parameter Request Procedure not supported.
 * Peripheral-initiated Connection Update procedure (not allowed).
 *
 * +-----+                    +-------+                    +-----+
 * | UT  |                    | LL_P  |                    | LT  |
 * +-----+                    +-------+                    +-----+
 *    |                           |                           |
 *    | LE Connection Update      |                           |
 *    |-------------------------->|                           |
 *    |                           |                           |
 *    |      ERR CMD Disallowed   |                           |
 *    |<--------------------------|                           |
 *    |                           |                           |
 */
ZTEST(periph_loc, test_conn_update_periph_loc_disallowed_no_param_req)
{
	uint8_t err;

	/* Role */
	test_set_role(&conn, BT_HCI_ROLE_PERIPHERAL);

	/* Connect */
	ull_cp_state_set(&conn, ULL_CP_CONNECTED);

	/* Initiate a Connection Update Procedure */
	err = ull_cp_conn_update(&conn, INTVL_MIN, INTVL_MAX, LATENCY, TIMEOUT);
	zassert_equal(err, BT_HCI_ERR_CMD_DISALLOWED, NULL);

	/* Prepare */
	event_prepare(&conn);

	/* Tx Queue should have no LL Control PDU */
	lt_rx_q_is_empty(&conn);

	/* Done */
	event_done(&conn);

	/* There should be no host notification */
	ut_rx_q_is_empty();

	zassert_equal(ctx_buffers_free(), test_ctx_buffers_cnt(),
		      "Free CTX buffers %d", ctx_buffers_free());
}
