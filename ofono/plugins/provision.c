/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013 Jolla Ltd.
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
#include <errno.h>
#include <string.h>

#include <glib.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/types.h>
#include <ofono/log.h>
#include <ofono/plugin.h>
#include <ofono/modem.h>
#include <ofono/gprs-provision.h>

#include "provision.h"
#include "mbpi.h"

/* Returns the list containing exactly one INTERNET and one MMS access point */
static GSList *provision_normalize_apn_list(GSList *apns, const char* spn)
{
	struct mbpi_provision_data *best_internet = NULL;
	struct mbpi_provision_data *best_mms = NULL;
	struct mbpi_provision_data *second_best_internet = NULL;
	struct mbpi_provision_data *second_best_mms = NULL;
	GSList *best_apns = NULL;
	GSList *l;

	/* 1. save the first found internet APN and the first MMS APN */
	l = apns;
	while (l != NULL) {
		GSList *next = l->next;
		struct mbpi_provision_data *ap = l->data;

		if (ap->provision_data.type == OFONO_GPRS_CONTEXT_TYPE_INTERNET && !best_internet) {
			best_internet = ap;
		} else if (ap->provision_data.type == OFONO_GPRS_CONTEXT_TYPE_MMS && !best_mms) {
			best_mms = ap;
		}
		l = next;
	}

	/*
	 * 2. if there is an SPN given, save the first internet APN and the
	 * first MMS APN matching the SPN (partially, case-insensitively)
	 * */
	if (spn) {
		second_best_internet = best_internet;
		best_internet = NULL;
		second_best_mms = best_mms;
		best_mms = NULL;

		l = apns;
		while (l != NULL) {
			GSList *next = l->next;
			struct mbpi_provision_data *ap = l->data;

			if ((ap->provider_name && strcasestr(ap->provider_name, spn))
				|| (ap->provision_data.name && strcasestr(ap->provision_data.name, spn))
				|| (ap->provision_data.apn && strcasestr(ap->provision_data.apn, spn))) {
				if (ap->provision_data.type == OFONO_GPRS_CONTEXT_TYPE_INTERNET && !best_internet) {
					best_internet = ap;
				} else if (ap->provision_data.type == OFONO_GPRS_CONTEXT_TYPE_MMS && !best_mms) {
					best_mms = ap;
				}
			}
			l = next;
		}

		/* no better match found */
		if (!best_internet)
			best_internet = second_best_internet;
		if (!best_mms)
			best_mms = second_best_mms;
	}

	/* 3. if none found yet, create APNs with default values */
	if (!best_internet) {
		best_internet = g_try_new0(struct mbpi_provision_data, 1);
		if (best_internet) {
			best_internet->provision_data.type = OFONO_GPRS_CONTEXT_TYPE_INTERNET;
			best_internet->provision_data.name = g_strdup("Internet");
			best_internet->provision_data.apn = g_strdup("internet");
		}
	}

	if (!best_mms) {
		best_mms = g_try_new0(struct mbpi_provision_data, 1);
		if (best_mms) {
			best_mms->provision_data.type = OFONO_GPRS_CONTEXT_TYPE_MMS;
			best_mms->provision_data.name = g_strdup("MMS");
			best_mms->provision_data.apn = g_strdup("mms");
		}
	}

	best_apns = g_slist_append(best_apns, best_internet);
	best_apns = g_slist_append(best_apns, best_mms);
	return best_apns;
}

int provision_get_settings(const char *mcc, const char *mnc,
				const char *spn,
				struct ofono_gprs_provision_data **settings,
				int *count)
{
	GSList *l;
	GSList *apns;
	GError *error = NULL;
	int ap_count;
	int i;

	DBG("Provisioning for MCC %s, MNC %s, SPN '%s'", mcc, mnc, spn);

	/*
	 * Passing FALSE to mbpi_lookup_apn() would return
	 * an empty list if duplicates are found.
	 */
	apns = mbpi_lookup_apn(mcc, mnc, TRUE, &error);
	if (error != NULL) {
		ofono_error("%s", error->message);
		g_error_free(error);
	}

	DBG("Found %d APs (in MBPI)", g_slist_length(apns));
	apns = provision_normalize_apn_list(apns, spn);
	if (apns == NULL)
		return -ENOENT;

	ap_count = g_slist_length(apns);

	DBG("Found %d APs", ap_count);

	*settings = g_try_new0(struct ofono_gprs_provision_data, ap_count);
	if (*settings == NULL) {
		ofono_error("Provisioning failed: %s", g_strerror(errno));

		for (l = apns; l; l = l->next)
			mbpi_ap_free(l->data);

		g_slist_free(apns);

		return -ENOMEM;
	}

	*count = ap_count;

	for (l = apns, i = 0; l; l = l->next, i++) {
		struct mbpi_provision_data *ap = l->data;

		DBG("Name: '%s'", ap->provision_data.name);
		DBG("APN: '%s'", ap->provision_data.apn);
		DBG("Type: %s", mbpi_ap_type(ap->provision_data.type));
		DBG("Username: '%s'", ap->provision_data.username);
		DBG("Password: '%s'", ap->provision_data.password);

		memcpy(*settings + i, ap,
			sizeof(struct mbpi_provision_data));

		g_free(ap);
	}

	g_slist_free(apns);

	return 0;
}

static struct ofono_gprs_provision_driver provision_driver = {
	.name		= "Provisioning",
	.get_settings	= provision_get_settings
};

static int provision_init(void)
{
	return ofono_gprs_provision_driver_register(&provision_driver);
}

static void provision_exit(void)
{
	ofono_gprs_provision_driver_unregister(&provision_driver);
}

OFONO_PLUGIN_DEFINE(provision, "Provisioning Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT,
			provision_init, provision_exit)
