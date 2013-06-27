/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013 Jolla Ltd
 *  Contact: Jussi Kangas <jussi.kangas@tieto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/call-forwarding.h>

#include "gril.h"
#include "grilutil.h"

#include "rilmodem.h"

#include "ril_constants.h"
#include "common.h"

struct forw_data {
	GRil *ril;
};

enum call_forward_cmd {
	CF_ACTION_DISABLE,
	CF_ACTION_ENABLE,
	CF_ACTION_UNUSED,
	CF_ACTION_REGISTRATION,
	CF_ACTION_ERASURE,
};

static void ril_erasure_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_call_forwarding_set_cb_t cb = cbd->cb;

	if (message->error == RIL_E_SUCCESS)
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	else
		CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void ril_erasure(struct ofono_call_forwarding *cf,
				int type, int cls,
				ofono_call_forwarding_set_cb_t cb, void *data)
{
	struct forw_data *fd = ofono_call_forwarding_get_data(cf);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	int ret = 0;

	parcel_init(&rilp);

	parcel_w_int32(&rilp, CF_ACTION_ERASURE);

	parcel_w_int32(&rilp, type);

	/* Modem seems to respond with error to all queries
	 * or settings made with bearer class
	 * BEARER_CLASS_DEFAULT. Design decision: If given
	 * class is BEARER_CLASS_DEFAULT let's map it to
	 * SERVICE_CLASS_VOICE effectively making it the
	 * default bearer. This in line with API which is
	 * contains only voice anyways. TODO: Checkout
	 * the behaviour with final modem
	*/

	if (cls == BEARER_CLASS_DEFAULT)
		cls = BEARER_CLASS_VOICE;

	parcel_w_int32(&rilp, cls);			/* Service class */

	/* Following 3 values have no real meaning in erasure
	 * but apparently RIL expects them so fields need to
	 * be filled. Otherwise there is no response
	 * */

	parcel_w_int32(&rilp, 0x81);		/* TOA unknown */

	parcel_w_string(&rilp, "1234567890");

	parcel_w_int32(&rilp, 60);

	ret = g_ril_send(fd->ril, RIL_REQUEST_SET_CALL_FORWARD,
			rilp.data, rilp.size, ril_erasure_cb, cbd, g_free);

	parcel_free(&rilp);

	/* In case of error free cbd and return the cb with failure */
	if (ret <= 0) {
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, data);
	}
}

static void ril_query_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_call_forwarding_query_cb_t cb = cbd->cb;
	struct ofono_call_forwarding_condition *list = NULL;
	struct parcel rilp;
	int nmbr_of_resps = 0;
	int i;

	if (message->error == RIL_E_SUCCESS) {

		ril_util_init_parcel(message, &rilp);

		nmbr_of_resps = parcel_r_int32(&rilp);

		list = g_new0(
				struct ofono_call_forwarding_condition,
				nmbr_of_resps);

		for (i = 0; i < nmbr_of_resps; i++) {
			const char *str;

			list[i].status =  parcel_r_int32(&rilp);

			parcel_r_int32(&rilp);

			list[i].cls = parcel_r_int32(&rilp);

			list[i].phone_number.type = parcel_r_int32(&rilp);

			str = parcel_r_string(&rilp);

			if (str) {

				strncpy(list[i].phone_number.number,
					str,
					OFONO_MAX_PHONE_NUMBER_LENGTH);

				list[i].phone_number.number[
					OFONO_MAX_PHONE_NUMBER_LENGTH] = '\0';

				list[i].time = parcel_r_int32(&rilp);
			}

		}

		CALLBACK_WITH_SUCCESS(cb, 1, list, cbd->data);

		g_free(list);
	} else
		CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
}

static void ril_query(struct ofono_call_forwarding *cf, int type, int cls,
				ofono_call_forwarding_query_cb_t cb,
				void *data)
{
	struct forw_data *fd = ofono_call_forwarding_get_data(cf);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct parcel rilp;
	int ret = 0;

	parcel_init(&rilp);

	parcel_w_int32(&rilp, 2);

	parcel_w_int32(&rilp, type);

	/* Modem seems to respond with error to all queries
	 * or settings made with bearer class
	 * BEARER_CLASS_DEFAULT. Design decision: If given
	 * class is BEARER_CLASS_DEFAULT let's map it to
	 * SERVICE_CLASS_VOICE effectively making it the
	 * default bearer. This in line with API which is
	 * contains only voice anyways. TODO: Checkout
	 * the behaviour with final modem
	*/

	if (cls == BEARER_CLASS_DEFAULT)
		cls = BEARER_CLASS_VOICE;

	parcel_w_int32(&rilp, cls);

	/* Following 3 values have no real meaning in query
	 * but apparently RIL expects them so fields need to
	 * be filled. Otherwise there is no response
	*/

	parcel_w_int32(&rilp, 0x81);		/* TOA unknown */

	parcel_w_string(&rilp, "1234567890");

	parcel_w_int32(&rilp, 60);

	ret = g_ril_send(fd->ril, RIL_REQUEST_QUERY_CALL_FORWARD_STATUS,
			rilp.data, rilp.size, ril_query_cb, cbd, g_free);

	parcel_free(&rilp);

	/* In case of error free cbd and return the cb with failure */
	if (ret <= 0) {
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, 0, NULL, data);
	}
}

static gboolean ril_delayed_register(gpointer user_data)
{
	struct ofono_call_forwarding *cf = user_data;
	ofono_call_forwarding_register(cf);
	return FALSE;
}

static int ril_call_forwarding_probe(struct ofono_call_forwarding *cf,
					unsigned int vendor, void *user)
{
	GRil *ril = user;
	struct forw_data *fd = g_try_new0(struct forw_data, 1);
	fd->ril = g_ril_clone(ril);
	ofono_call_forwarding_set_data(cf, fd);
	g_timeout_add_seconds(2, ril_delayed_register, cf);

	return 0;
}

static void ril_call_forwarding_remove(struct ofono_call_forwarding *cf)
{
	struct forw_data *data = ofono_call_forwarding_get_data(cf);
	ofono_call_forwarding_set_data(cf, NULL);
	g_ril_unref(data->ril);
	g_free(data);
}

static struct ofono_call_forwarding_driver driver = {
	.name			= "rilmodem",
	.probe			= ril_call_forwarding_probe,
	.remove			= ril_call_forwarding_remove,
	.erasure		= ril_erasure,
	.query			= ril_query
};

void ril_call_forwarding_init(void)
{
	ofono_call_forwarding_driver_register(&driver);
}

void ril_call_forwarding_exit(void)
{
	ofono_call_forwarding_driver_unregister(&driver);
}
