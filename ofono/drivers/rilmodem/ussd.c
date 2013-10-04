/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013 Jolla Ltd
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
#include <ofono/ussd.h>
#include <smsutil.h>
#include <util.h>

#include "gril.h"
#include "grilutil.h"

#include "rilmodem.h"

#include "ril_constants.h"

struct ussd_data {
	GRil *ril;
};

static void ril_ussd_cb(struct ril_msg *message, gpointer user_data)
{
	/*
	 * Calling oFono callback function at this point may lead to
	 * segmentation fault. There is theoretical possibility that no
	 * RIL_UNSOL_ON_USSD is received and therefore the original request
	 * is not freed in oFono.
	 */
}

static void ril_ussd_request(struct ofono_ussd *ussd, int dcs,
			const unsigned char *pdu, int len,
			ofono_ussd_cb_t cb, void *data)
{
	struct ussd_data *ud = ofono_ussd_get_data(ussd);
	struct cb_data *cbd = cb_data_new(cb, data);
	enum sms_charset charset;
	int ret = -1;

	if (cbs_dcs_decode(dcs, NULL, NULL, &charset,
					NULL, NULL, NULL)) {
		if (charset == SMS_CHARSET_7BIT) {
			unsigned char unpacked_buf[182] = "";
			long written;

			unpack_7bit_own_buf(pdu, len, 0, TRUE,
					sizeof(unpacked_buf), &written, 0,
					unpacked_buf);

			if (written >= 1) {
				struct parcel rilp;
				parcel_init(&rilp);
				parcel_w_string(&rilp, (char *)unpacked_buf);
				ret = g_ril_send(ud->ril,
						RIL_REQUEST_SEND_USSD,
						rilp.data, rilp.size,
						ril_ussd_cb, cbd, g_free);
				parcel_free(&rilp);
			}
		}
	}

	/*
	 * It cannot be guaranteed that response is received before notify or
	 * user-activity request so we must complete the request now and later
	 * ignore the actual response.
	 */
	if (ret <= 0) {
		g_free(cbd);
		CALLBACK_WITH_FAILURE(cb, data);
	} else {
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	}

}
static void ril_ussd_cancel_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_ussd_cb_t cb = cbd->cb;
	struct ofono_error error;

	DBG("%d", message->error);

	if (message->error == RIL_E_SUCCESS)
		decode_ril_error(&error, "OK");
	else
		decode_ril_error(&error, "FAIL");

	cb(&error, cbd->data);
}

static void ril_ussd_cancel(struct ofono_ussd *ussd,
				ofono_ussd_cb_t cb, void *user_data)
{
	struct ussd_data *ud = ofono_ussd_get_data(ussd);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	cbd->user = ud;

	if (g_ril_send(ud->ril, RIL_REQUEST_CANCEL_USSD, NULL, 0,
				ril_ussd_cancel_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void ril_ussd_notify(struct ril_msg *message, gpointer user_data)
{
	struct ofono_ussd *ussd = user_data;
	struct parcel rilp;
	gchar *ussd_from_network;
	gchar *type;
	gint ussdtype;
	int valid = 0;
	long items_written = 0;
	unsigned char pdu[200];

	ril_util_init_parcel(message, &rilp);
	parcel_r_int32(&rilp);
	type = parcel_r_string(&rilp);
	ussdtype = g_ascii_xdigit_value(*type);
	ussd_from_network = parcel_r_string(&rilp);

	if (ussd_from_network)
		if (ussd_encode(ussd_from_network, &items_written, pdu)
							&& items_written > 0)
			valid = 1;

	if (valid)
		ofono_ussd_notify(ussd, ussdtype, 0, pdu, items_written);
	else
		ofono_ussd_notify(ussd, ussdtype, 0, NULL, 0);

	return;
}

static gboolean ril_delayed_register(gpointer user_data)
{
	struct ofono_ussd *ussd = user_data;
	ofono_ussd_register(ussd);

	struct ussd_data *ud = ofono_ussd_get_data(ussd);
	/* Register for USSD responses */
	g_ril_register(ud->ril, RIL_UNSOL_ON_USSD,
			ril_ussd_notify, ussd);

	return FALSE;
}

static int ril_ussd_probe(struct ofono_ussd *ussd,
					unsigned int vendor,
					void *user)
{
	GRil *ril = user;
	struct ussd_data *ud = g_try_new0(struct ussd_data, 1);
	ud->ril = g_ril_clone(ril);
	ofono_ussd_set_data(ussd, ud);
	g_timeout_add_seconds(2, ril_delayed_register, ussd);

	return 0;
}

static void ril_ussd_remove(struct ofono_ussd *ussd)
{
	struct ussd_data *ud = ofono_ussd_get_data(ussd);
	ofono_ussd_set_data(ussd, NULL);
	g_ril_unref(ud->ril);
	g_free(ud);
}

static struct ofono_ussd_driver driver = {
	.name				= "rilmodem",
	.probe				= ril_ussd_probe,
	.remove				= ril_ussd_remove,
	.request			= ril_ussd_request,
	.cancel				= ril_ussd_cancel
};

void ril_ussd_init(void)
{
	ofono_ussd_driver_register(&driver);
}

void ril_ussd_exit(void)
{
	ofono_ussd_driver_unregister(&driver);
}

