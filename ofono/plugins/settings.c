/* Copyright (C) 2013 Jolla Ltd.
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Nemo Mobile nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gdbus.h>
#include <ofono.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/dbus.h>
#include "storage.h"

#define SETTINGS_INTERFACE "org.ofono.Settings"
#define SETTINGS_CHANGED_SIGNAL "Changed"
#define DEFAULT_DIR STORAGEDIR "/default"
#define STORE_FILE "settings"

static unsigned int modemwatch_id;

struct settings_modem {
	struct ofono_modem *modem;
	struct ofono_sim *sim;
	char *imsi;
	GKeyFile *settings;
};

static void settings_sync(struct settings_modem *s)
{
	storage_sync(s->imsi, STORE_FILE, s->settings);
}

static gboolean settings_equal_value(const char *v1, const char *v2)
{
	if (!v1 && !v2)
		return TRUE;

	if (!v1 || !v2)
		return FALSE;

	return !strcmp(v1, v2);
}

static void settings_merge_settings_group(GKeyFile *dest, GKeyFile *src,
						const char *g, GKeyFile *chng)
{
	gsize i, nk = 0;
	char **k = g_key_file_get_keys(src, g, &nk, NULL);

	for (i = 0; i < nk; i++) {
		const char *key = k[i];
		char *v = g_key_file_get_value(src, g, key, NULL);

		if (v) {
			if (chng) {
				char *v1 = g_key_file_get_value(dest,
								g, key, NULL);
				if (!settings_equal_value(v, v1))
					g_key_file_set_value(chng, g, key, v);

				g_free(v1);
			}
			g_key_file_set_value(dest, g, key, v);
			g_free(v);
		}
	}

	g_strfreev(k);
}

static GKeyFile *settings_merge_settings(GKeyFile *dest, GKeyFile *src,
							GKeyFile *changes)
{
	gsize i, ng;
	char **g = g_key_file_get_groups(src, &ng);

	if (g) {
		for (i = 0; i < ng; i++)
			settings_merge_settings_group(dest, src, g[i], changes);

		g_strfreev(g);
	}

	return dest;
}

static void settings_read_default_group(GKeyFile *defaults, GKeyFile *f,
								const char *g)
{
	gsize i, nk = 0;
	char **k = g_key_file_get_keys(f, g, &nk, NULL);

	for (i = 0; i < nk; i++) {
		const char *key = k[i];
		char *v = g_key_file_get_value(f, g, key, NULL);

		if (v) {
			g_key_file_set_value(defaults, g, key, v);
			g_free(v);
		}
	}

	g_strfreev(k);
}

static void settings_read_defaults_file(GKeyFile *defaults, GKeyFile *f,
							const char *group)
{
	gsize i, ng = 0;
	char **g = g_key_file_get_groups(f, &ng);

	for (i = 0; i < ng; i++)
		if (!group || !group[0] || !strcmp(group, g[i]))
			settings_read_default_group(defaults, f, g[i]);

	g_strfreev(g);
}

static GKeyFile *settings_read_defaults(const char *group)
{
	GDir *dir = g_dir_open(DEFAULT_DIR, 0, NULL);
	GKeyFile *defaults = g_key_file_new();

	if (dir) {
		const char *file;

		while ((file = g_dir_read_name(dir)) != NULL) {
			GKeyFile *f = g_key_file_new();
			char *path = g_strconcat(DEFAULT_DIR "/", file, NULL);

			if (g_key_file_load_from_file(f, path, 0, NULL)) {
				DBG("merging %s", path);
				settings_read_defaults_file(defaults, f, group);
			}

			g_key_file_free(f);
			g_free(path);
		}

		g_dir_close(dir);
	}

	return defaults;
}

static char *settings_reset_key(struct settings_modem *s, const char *group,
							const char *key)
{
	GKeyFile *defaults = settings_read_defaults(group);
	char *changed = g_key_file_get_value(defaults, group, key, NULL);
	char *v = g_key_file_get_value(s->settings, group, key, NULL);

	if (settings_equal_value(v, changed)) {
		g_free(changed);
		changed = NULL;
	} else {
		g_key_file_set_value(s->settings, group, key, changed);
	}

	g_free(v);
	g_key_file_free(defaults);

	return changed;
}

static gboolean settings_reset_default_group(struct settings_modem *s,
			GKeyFile *defaults, const char *g, GKeyFile *changes)
{
	gboolean changed = FALSE;
	gsize i, nk = 0;
	char **k = g_key_file_get_keys(defaults, g, &nk, NULL);

	for (i = 0; i < nk; i++) {
		const char *key = k[i];
		char *def = g_key_file_get_value(defaults, g, key, NULL);
		char *v = g_key_file_get_value(s->settings, g, key, NULL);

		if (!settings_equal_value(v, def)) {
			if (changes)
				g_key_file_set_value(changes, g, key, def);

			DBG("resetting %s:%s", g, key);
			g_key_file_set_value(s->settings, g, key, def);
			changed = TRUE;
		}

		g_free(v);
		g_free(def);
	}

	g_strfreev(k);
	return changed;
}

static gboolean settings_reset_group(struct settings_modem *s,
					const char *group, GKeyFile *changes)
{
	GKeyFile *defs = settings_read_defaults(group);
	gboolean ret = settings_reset_default_group(s, defs, group, changes);

	g_key_file_free(defs);
	return ret;
}

static gboolean settings_reset(struct settings_modem *s, GKeyFile *changes)
{
	gboolean changed = FALSE;
	GKeyFile *defaults = settings_read_defaults(NULL);
	gsize i, ng = 0;
	char **g = g_key_file_get_groups(defaults, &ng);

	for (i = 0; i < ng; i++) {
		if (settings_reset_default_group(s, defaults, g[i], changes))
			changed = TRUE;
	}

	g_strfreev(g);
	g_key_file_free(defaults);

	return changed;
}

static void settings_dbus_signal_value_changed(struct settings_modem *s,
		DBusConnection *conn, const char *group, const char *key,
		const char *value)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	DBG("%s:%s = %s", group, key, value);
	signal = dbus_message_new_signal(ofono_modem_get_path(s->modem),
				SETTINGS_INTERFACE, SETTINGS_CHANGED_SIGNAL);
	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &group);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &value);
	g_dbus_send_message(conn, signal);
}

static void settings_dbus_signal_group_changed(struct settings_modem *s,
		DBusConnection *conn, GKeyFile *changes, const char *g)
{
	gsize i, nk = 0;
	char **k = g_key_file_get_keys(changes, g, &nk, NULL);

	for (i = 0; i < nk; i++) {
		const char *key = k[i];
		char *v = g_key_file_get_value(changes, g, key, NULL);
		settings_dbus_signal_value_changed(s, conn, g, key, v);
		g_free(v);
	}

	g_strfreev(k);
}

static void settings_dbus_signal_settings_changed(struct settings_modem *s,
		DBusConnection *conn, GKeyFile *changes)
{
	gsize i, ng = 0;
	char **g = g_key_file_get_groups(changes, &ng);

	for (i = 0; i < ng; i++)
		settings_dbus_signal_group_changed(s, conn, changes, g[i]);

	g_strfreev(g);
}

static void settings_dbus_append_group(GKeyFile *f, const char *g,
							DBusMessageIter *itr)
{
	gsize i, nk = 0;
	char **keys = g_key_file_get_keys(f, g, &nk, NULL);
	DBusMessageIter dic;

	dbus_message_iter_open_container(itr, DBUS_TYPE_ARRAY, "{ss}", &dic);
	for (i = 0; i < nk; i++) {
		DBusMessageIter e;
		const char *k = keys[i];
		char *v = g_key_file_get_value(f, g, k, NULL);

		dbus_message_iter_open_container(&dic, DBUS_TYPE_DICT_ENTRY,
								NULL, &e);
		dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
		dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &v);
		dbus_message_iter_close_container(&dic, &e);
		g_free(v);
	}

	dbus_message_iter_close_container(itr, &dic);
	g_strfreev(keys);
}

static DBusMessage *settings_dbus_get_all(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	DBusMessageIter iter, array;
	DBusMessage *reply;
	gsize i, ng = 0;
	char **groups;

	if (dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	DBG("");
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sa{ss})",
									&array);
	groups = g_key_file_get_groups(s->settings, &ng);
	for (i = 0; i < ng; i++) {
		DBusMessageIter group;
		const char *g = groups[i];

		dbus_message_iter_open_container(&array, DBUS_TYPE_STRUCT,
							NULL, &group);
		dbus_message_iter_append_basic(&group, DBUS_TYPE_STRING, &g);
		settings_dbus_append_group(s->settings, g, &group);
		dbus_message_iter_close_container(&array, &group);
	}

	dbus_message_iter_close_container(&iter, &array);
	g_strfreev(groups);
	return reply;
}

static DBusMessage *settings_dbus_get_group(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	const char *group;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &group);
	dbus_message_iter_next(&iter);

	if (!group[0])
		return __ofono_error_invalid_args(msg);

	DBG("%s", group);
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	settings_dbus_append_group(s->settings, group, &iter);

	return reply;
}

static DBusMessage *settings_dbus_get(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	DBusMessageIter iter;
	const char *group;
	const char *key;
	char *value;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &group);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &key);
	dbus_message_iter_next(&iter);

	if (!group[0])
		return __ofono_error_invalid_args(msg);

	if (!key[0])
		return __ofono_error_invalid_args(msg);

	value = g_key_file_get_value(s->settings, group, key, NULL);
	DBG("%s:%s = %s", group, key, value);

	if (value) {
		DBusMessage *reply = dbus_message_new_method_return(msg);
		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &value);
		g_free(value);
		return reply;
	} else {
		return __ofono_error_not_found(msg);
	}
}

static DBusMessage *settings_dbus_set(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	DBusMessageIter iter;
	const char *group;
	const char *key;
	const char *value;
	char *prev;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &group);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &key);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &value);
	dbus_message_iter_next(&iter);

	if (!group[0])
		return __ofono_error_invalid_args(msg);

	if (!key[0])
		return __ofono_error_invalid_args(msg);

	prev = g_key_file_get_value(s->settings, group, key, NULL);
	DBG("%s:%s = %s", group, key, value);

	if (!settings_equal_value(prev, value)) {
		g_key_file_set_value(s->settings, group, key, value);
		settings_dbus_signal_value_changed(s, conn, group, key, value);
		settings_sync(s);
	}

	g_free(prev);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *settings_dbus_reset_all(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	GKeyFile *changes = g_key_file_new();

	DBG("");
	if (settings_reset(s, changes)) {
		settings_dbus_signal_settings_changed(s, conn, changes);
		settings_sync(s);
	}

	g_key_file_free(changes);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *settings_dbus_reset_group(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	DBusMessageIter iter;
	GKeyFile *changes;
	const char *group;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &group);
	dbus_message_iter_next(&iter);

	if (!group[0])
		return __ofono_error_invalid_args(msg);

	DBG("%s", group);
	changes = g_key_file_new();

	if (settings_reset_group(s, group, changes)) {
		settings_dbus_signal_settings_changed(s, conn, changes);
		settings_sync(s);
	}

	g_key_file_free(changes);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *settings_dbus_reset(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct settings_modem *s = data;
	DBusMessageIter iter;
	const char *group;
	const char *key;
	char *newval;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &group);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &key);
	dbus_message_iter_next(&iter);

	if (!group[0])
		return __ofono_error_invalid_args(msg);

	if (!key[0])
		return __ofono_error_invalid_args(msg);

	DBG("%s:%s", group, key);
	newval = settings_reset_key(s, group, key);

	if (newval) {
		settings_dbus_signal_value_changed(s, conn, group, key, newval);
		settings_sync(s);
		g_free(newval);
	}

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable settings_methods[] = {
	{ GDBUS_METHOD("GetAll",
		NULL,
		GDBUS_ARGS({ "settings", "a(sa{ss})" }),
		settings_dbus_get_all)},
	{ GDBUS_METHOD("GetGroup",
		GDBUS_ARGS({ "group", "s" }),
		GDBUS_ARGS({ "settings", "a{ss}" }),
		settings_dbus_get_group)},
	{ GDBUS_METHOD("Get",
		GDBUS_ARGS({ "group", "s"}, {"key", "s" }),
		GDBUS_ARGS({ "value", "s" }),
		settings_dbus_get)},
	{ GDBUS_METHOD("Set",
		GDBUS_ARGS({ "group", "s"}, {"key", "s" }, {"value", "s" }),
		NULL,
		settings_dbus_set)},
	{ GDBUS_METHOD("ResetAll",
		NULL,
		NULL,
		settings_dbus_reset_all)},
	{ GDBUS_METHOD("ResetGroup",
		GDBUS_ARGS({ "group", "s" }),
		NULL,
		settings_dbus_reset_group)},
	{ GDBUS_METHOD("Reset",
		GDBUS_ARGS({ "group", "s"}, {"key", "s" }),
		NULL,
		settings_dbus_reset)},
	{ }
};

static const GDBusSignalTable settings_signals[] = {
	{ GDBUS_SIGNAL(SETTINGS_CHANGED_SIGNAL,
		GDBUS_ARGS({ "group", "s"}, {"key", "s" }, {"value", "s" })) },
	{ }
};

static void settings_cleanup(gpointer user)
{
	struct settings_modem *s = user;

	DBG("unregistered %s", ofono_modem_get_path(s->modem));
	if (s->settings) {
		storage_close(s->imsi, STORE_FILE, s->settings, FALSE);
		s->settings = NULL;
	}

	g_free(s->imsi);
	s->imsi = NULL;
}

static void settings_register(struct settings_modem *s, const char *imsi)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(s->modem);

	if (g_dbus_register_interface(conn, path, SETTINGS_INTERFACE,
					settings_methods, settings_signals,
					NULL, s, settings_cleanup)) {
		GKeyFile *settings = storage_open(imsi, STORE_FILE);
		GKeyFile *defaults = settings_read_defaults(NULL);

		s->imsi = g_strdup(imsi);
		s->settings = settings_merge_settings(defaults, settings, NULL);
		g_key_file_free(settings);
		ofono_modem_add_interface(s->modem, SETTINGS_INTERFACE);
		DBG("registered %s for %s", SETTINGS_INTERFACE, path);
	} else {
		ofono_error("Could not register %s", SETTINGS_INTERFACE);
	}
}

static void settings_unregister(struct settings_modem *s)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(s->modem);

	ofono_modem_remove_interface(s->modem, SETTINGS_INTERFACE);
	g_dbus_unregister_interface(conn, path, SETTINGS_INTERFACE);
}

static void settings_sim_state_watch(enum ofono_sim_state state, void *data)
{
	struct settings_modem *s = data;
	const char *imsi = (state == OFONO_SIM_STATE_NOT_PRESENT) ? NULL :
						ofono_sim_get_imsi(s->sim);

	DBG("%d %s", state, imsi ? imsi : "");
	if (imsi) {
		if (!s->imsi) {
			settings_register(s, imsi);
		} else if (strcmp(s->imsi, imsi)) {
			settings_unregister(s);
			settings_register(s, imsi);
		}
	} else if (s->imsi) {
		settings_unregister(s);
	}
}

static void settings_sim_watch(struct ofono_atom *atom,
			enum ofono_atom_watch_condition cond, void *data)
{
	struct settings_modem *s = data;
	const char *imsi;

	DBG("%d", cond);
	if (cond == OFONO_ATOM_WATCH_CONDITION_UNREGISTERED) {
		settings_unregister(s);
		s->sim = NULL;
		return;
	}

	s->sim = __ofono_atom_get_data(atom);
	if (!s->sim) {
		DBG("Could not find SIM atom");
		return;
	}

	imsi = ofono_sim_get_imsi(s->sim);
	if (imsi && ofono_sim_get_state(s->sim) != OFONO_SIM_STATE_NOT_PRESENT)
		settings_register(s, imsi);

	ofono_sim_add_state_watch(s->sim, settings_sim_state_watch, s, NULL);
}

static void settings_modem_watch(struct ofono_modem *modem, gboolean added,
								void *user)
{
	DBG("modem: %p, added: %d", modem, added);

	if (added) {
		struct settings_modem *s = g_new0(struct settings_modem, 1);
		s->modem = modem;
		__ofono_modem_add_atom_watch(modem, OFONO_ATOM_TYPE_SIM,
					settings_sim_watch, s, g_free);
	}
}

static void settings_add_modem(struct ofono_modem *modem, void *user)
{
	settings_modem_watch(modem, TRUE, user);
}

static int settings_plugin_init()
{
	DBG("");
	modemwatch_id = __ofono_modemwatch_add(settings_modem_watch,
								NULL, NULL);
	__ofono_modem_foreach(settings_add_modem, NULL);
	return 0;
}

static void settings_plugin_exit()
{
	DBG("");
	__ofono_modemwatch_remove(modemwatch_id);
}

OFONO_PLUGIN_DEFINE(settings, "Settings Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT,
			settings_plugin_init, settings_plugin_exit)
