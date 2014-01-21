/*
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <string.h>
#include <wspcodec.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono.h>
#include <plugin.h>

/*
 * Push forwarder plugin is looking for configuration files in
 * /etc/ofono/push_forwarder.d directory. Confiration files are
 * glib key files that look like this:
 *
 *   [Jolla MMS Handler]
 *   ContentType = application/vnd.wap.mms-message
 *   Interface = com.jolla.MmsEngine.
 *   Service = com.jolla.MmsEngine
 *   Method = HandlePush
 *   Path = /
 *
 * Only files with .conf suffix are loaded. In addition to the keys
 * from the above example, SourcePort and DestinationPort port keys
 * are supported. All other keys are ignored. One file may describe
 * several push handlers. See push_forwarder_parse_config() function
 * for details.
 *
 * When push fowarder receives a WAP push, it goes through the list
 * of registered handlers and invokes all of them that match content
 * type and/or port numbers. The rest is up to the D-Bus service
 * handling the call.
 */

#define PUSH_FORWARDER_CONFIG_DIR CONFIGDIR "/push_forwarder.d"

typedef struct push_forwarder_plugin push_forwarder_plugin;
typedef struct push_forwarder_modem {
    push_forwarder_plugin* plugin;
    struct ofono_modem* modem;
    struct ofono_sms* sms;
    struct ofono_sim* sim;
    unsigned int sim_watch_id;
    unsigned int sms_watch_id;
    unsigned int push_watch_id;
} push_forwarder_modem;

typedef struct push_datagram_handler {
    char* name;
    char* content_type;
    char* interface;
    char* service;
    char* method;
    char* path;
    int dst_port;
    int src_port;
} push_datagram_handler;

struct push_forwarder_plugin {
    GSList* handlers;
    GSList* modems;
    unsigned int modem_watch_id;
};

static
void
push_forwarder_notify_handler(
    push_datagram_handler* handler,
    const char* imsi,
    const char* from,
    const struct tm* remote,
    const struct tm* local,
    int dst_port,
    int src_port,
    const void* data,
    unsigned int len)
{
    struct tm remote_tm = *remote;
    struct tm local_tm = *local;
    dbus_uint32_t remote_time_arg = mktime(&remote_tm);
    dbus_uint32_t local_time_arg = mktime(&local_tm);
    dbus_int32_t dst_port_arg = dst_port;
    dbus_int32_t src_port_arg = src_port;
    DBusMessageIter iter, array;
    DBusMessage* msg = dbus_message_new_method_call(handler->service,
        handler->path, handler->interface, handler->method);

    dbus_message_append_args(msg,
        DBUS_TYPE_STRING, &imsi,
        DBUS_TYPE_STRING, &from,
        DBUS_TYPE_UINT32, &remote_time_arg,
        DBUS_TYPE_UINT32, &local_time_arg,
        DBUS_TYPE_INT32,  &dst_port_arg,
        DBUS_TYPE_INT32,  &src_port_arg,
        DBUS_TYPE_INVALID);

    dbus_message_iter_init_append(msg, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
        DBUS_TYPE_BYTE_AS_STRING, &array);
    dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE, &data, len);
    dbus_message_iter_close_container(&iter, &array);

    dbus_message_set_no_reply(msg, TRUE);
    dbus_connection_send(ofono_dbus_get_connection(), msg, NULL);
    dbus_message_unref(msg);
}

static
gboolean
push_forwarder_match_port(
    int datagram_port,
    int expected_port)
{
    return expected_port < 0 || expected_port == datagram_port;
}

static
gboolean
push_forwarder_match_handler(
    push_datagram_handler* h,
    const char* content_type,
    int dst_port,
    int src_port)
{
    return push_forwarder_match_port(dst_port, h->dst_port) &&
           push_forwarder_match_port(src_port, h->src_port) &&
           (!h->content_type || !strcmp(h->content_type, content_type));
}

static
void
push_forwarder_handle_datagram(
    const char* from,
    const struct tm* remote,
    const struct tm* local,
    int dst_port,
    int src_port,
    const unsigned char* buffer,
    unsigned int len,
    void* userdata)
{
    push_forwarder_modem* pm = userdata;
    DBG("received push of size: %u", len);
    /* First two bytes are Transaction ID and PDU Type */
    if (len >= 3 && buffer[1] == 6 /* Push PDU */) {
        guint remain = len - 2;
        const guint8* data = buffer + 2;
        unsigned int hdrlen = 0;
        unsigned int off = 0;
        if (wsp_decode_uintvar(data, remain, &hdrlen, &off) &&
            (off + hdrlen) <= remain) {
            const void* ct = NULL;
            data += off;
            remain -= off;
            DBG("WAP header %u bytes", hdrlen);
            if (wsp_decode_content_type(data, hdrlen, &ct, &off, NULL)) {
                const char* imsi = pm->sim ? ofono_sim_get_imsi(pm->sim) : NULL;
                DBG("content type %s", (char*)ct);
                DBG("imsi %s", imsi);
                if (imsi) {
                    GSList* link = pm->plugin->handlers;
                    while (link) {
                        push_datagram_handler* handler = link->data;
                        if (push_forwarder_match_handler(handler, ct,
                            dst_port, src_port)) {
                            DBG("notifying %s", handler->name);
                            push_forwarder_notify_handler(handler, imsi,
                                from, remote, local, dst_port, src_port,
                                buffer, len);
                        }
                        link = link->next;
                    }
                }
            }
        }
    }
}

static
void
push_forwarder_sms_watch(
    struct ofono_atom* atom,
    enum ofono_atom_watch_condition cond,
    void* userdata)
{
    push_forwarder_modem* pm = userdata;
    if (cond == OFONO_ATOM_WATCH_CONDITION_REGISTERED) {
        DBG("registered");
        pm->sms = __ofono_atom_get_data(atom);
        pm->push_watch_id = __ofono_sms_datagram_watch_add(pm->sms,
            push_forwarder_handle_datagram, -1, -1, pm, NULL);
    } else if (cond == OFONO_ATOM_WATCH_CONDITION_UNREGISTERED) {
        DBG("unregistered");
        pm->sms = NULL;
        pm->push_watch_id = 0;
    }
}

static
void
push_forwarder_sms_watch_done(
    void* userdata)
{
    push_forwarder_modem* pm = userdata;
    pm->sms_watch_id = 0;
}

static
void
push_forwarder_sim_watch(
    struct ofono_atom* atom,
    enum ofono_atom_watch_condition cond,
    void* userdata)
{
    push_forwarder_modem* pm = userdata;
    if (cond == OFONO_ATOM_WATCH_CONDITION_REGISTERED) {
        DBG("registered");
        pm->sim = __ofono_atom_get_data(atom);
    } else if (cond == OFONO_ATOM_WATCH_CONDITION_UNREGISTERED) {
        DBG("unregistered");
        pm->sim = NULL;
    }
}

static
void
push_forwarder_sim_watch_done(
    void* userdata)
{
    push_forwarder_modem* pm = userdata;
    pm->sim_watch_id = 0;
}

static
void
push_forwarder_free_modem(
    push_forwarder_modem* pm)
{
    if (pm) {
        if (pm->sms && pm->push_watch_id) {
            __ofono_sms_datagram_watch_remove(pm->sms, pm->push_watch_id);
        }
        if (pm->modem) {
            if (pm->sim_watch_id) {
                __ofono_modem_remove_atom_watch(pm->modem, pm->sim_watch_id);
            }
            if (pm->sms_watch_id) {
                __ofono_modem_remove_atom_watch(pm->modem, pm->sms_watch_id);
            }
        }
        g_free(pm);
    }
}

static
void
push_forwarder_free_modem_cb(
    gpointer data)
{
    push_forwarder_free_modem(data);
}

static
void
push_forwarder_modem_watch(
    struct ofono_modem* modem,
    gboolean added,
    void* userdata)
{
    push_forwarder_plugin* plugin = userdata;
    DBG("modem: %p, added: %d", modem, added);
    if (added) {
        push_forwarder_modem* pm = g_new0(push_forwarder_modem,1);
        pm->plugin = plugin;
        pm->modem = modem;
        pm->sim_watch_id = __ofono_modem_add_atom_watch(modem,
            OFONO_ATOM_TYPE_SMS, push_forwarder_sms_watch, pm,
            push_forwarder_sms_watch_done);
        pm->sms_watch_id = __ofono_modem_add_atom_watch(modem,
            OFONO_ATOM_TYPE_SIM, push_forwarder_sim_watch, pm,
            push_forwarder_sim_watch_done);
        g_assert(pm->sim_watch_id);
        g_assert(pm->sms_watch_id);
        plugin->modems = g_slist_append(plugin->modems, pm);
    } else {
        GSList* link = plugin->modems;
        while (link) {
            push_forwarder_modem* pm = link->data;
            if (pm->modem == modem) {
                plugin->modems = g_slist_delete_link(plugin->modems, link);
                push_forwarder_free_modem(pm);
                break;
            }
            link = link->next;
        }
    }
}

static
void
push_forwarder_modem_init(
    struct ofono_modem* modem,
    void* userdata)
{
    push_forwarder_modem_watch(modem, TRUE, userdata);
}

static
void
push_forwarder_free_handler(
    void* data)
{
    push_datagram_handler* handler = data;
    g_free(handler->content_type);
    g_free(handler->interface);
    g_free(handler->service);
    g_free(handler->method);
    g_free(handler->path);
    g_free(handler->name);
    g_free(handler);
}

static
void
push_forwarder_parse_handler(
    push_forwarder_plugin* plugin,
    GKeyFile* conf,
    const char* g)
{
    /* These are required */
    char* interface = g_key_file_get_string(conf, g, "Interface", NULL);
    char* service = g_key_file_get_string(conf, g, "Service", NULL);
    char* method = g_key_file_get_string(conf, g, "Method", NULL);
    char* path = g_key_file_get_string(conf, g, "Path", NULL);
    if (interface && service && method && path) {
        GError* err = NULL;
        push_datagram_handler* h = g_new0(push_datagram_handler,1);
        h->name = g_strdup(g);
        h->interface = interface;
        h->service = service;
        h->method = method;
        h->path = path;

        /* Content type and ports are optional */
        h->content_type = g_key_file_get_string(conf, g, "ContentType", NULL);
        h->dst_port = g_key_file_get_integer(conf, g, "DestinationPort", &err);
        if (!h->dst_port && err) {
            h->dst_port = -1;
            g_error_free(err);
            err = NULL;
        }
        h->src_port = g_key_file_get_integer(conf, g, "SourcePort", &err);
        if (!h->src_port && err) {
            h->src_port = -1;
            g_error_free(err);
            err = NULL;
        }

        DBG("registered %s", h->name);
        if (h->content_type) DBG("  ContentType: %s", h->content_type);
        if (h->dst_port >= 0) DBG("  DestinationPort: %d", h->dst_port);
        if (h->src_port >= 0) DBG("  SourcePort: %d", h->src_port);        
        DBG("  Interface: %s", interface);
        DBG("  Service: %s", service);
        DBG("  Method: %s", method);
        DBG("  Path: %s", path);

        plugin->handlers = g_slist_append(plugin->handlers, h);
    } else {
        g_free(interface);
        g_free(service);
        g_free(method);
        g_free(path);
    }
}

static
void
push_forwarder_parse_config(
    push_forwarder_plugin* plugin)
{
    const char* dirname = PUSH_FORWARDER_CONFIG_DIR;
    GDir* dir = g_dir_open(dirname, 0, NULL);
    if (dir) {
        const gchar* fn;
        DBG("checking %s", dirname);
        while ((fn = g_dir_read_name(dir)) != NULL) {
            if (g_str_has_suffix(fn, ".conf")) {
                GError* err = NULL;
                GKeyFile* conf = g_key_file_new();
                char* path = g_strconcat(dirname, "/", fn, NULL);
                DBG("reading %s", fn);
                if (g_key_file_load_from_file(conf, path, 0, &err)) {
                    gsize i, n = 0;
                    char** names = g_key_file_get_groups(conf, &n);
                    for (i=0; i<n; i++) {
                        push_forwarder_parse_handler(plugin, conf, names[i]);
                    }
                    g_strfreev(names);
                } else {
                    ofono_warn("Reading of %s failed: %s", path, err->message);
                    g_error_free(err);
                }
                g_key_file_free(conf);
                g_free(path);
            }
        }
        g_dir_close(dir);
    } else {
        DBG(PUSH_FORWARDER_CONFIG_DIR " not found.");
    }
}

static
push_forwarder_plugin*
push_forwarder_plugin_new()
{
    push_forwarder_plugin* plugin = g_new0(push_forwarder_plugin,1);
    push_forwarder_parse_config(plugin);
    plugin->modem_watch_id = __ofono_modemwatch_add(
        push_forwarder_modem_watch, plugin, NULL);
    __ofono_modem_foreach(push_forwarder_modem_init, plugin);
    return plugin;
}

static
void
push_forwarder_plugin_free(
    push_forwarder_plugin* plugin)
{
    if (plugin) {
        __ofono_modemwatch_remove(plugin->modem_watch_id);
        g_slist_free_full(plugin->modems, push_forwarder_free_modem_cb);
        g_slist_free_full(plugin->handlers, push_forwarder_free_handler);
        g_free(plugin);
    }
}

/*
 * Plugin registration
 */

static push_forwarder_plugin* push_forwarder_plugin_instance = NULL;

static
int
push_forwarder_plugin_init()
{
    DBG("");
    g_assert(!push_forwarder_plugin_instance);
    push_forwarder_plugin_instance = push_forwarder_plugin_new();
    return 0;
}

static
void
push_forwarder_plugin_exit()
{
    DBG("");
    push_forwarder_plugin_free(push_forwarder_plugin_instance);
    push_forwarder_plugin_instance = NULL;
}

OFONO_PLUGIN_DEFINE(
    push_forwarder,
    "Push Forwarder Plugin",
    VERSION,
    OFONO_PLUGIN_PRIORITY_DEFAULT,
    push_forwarder_plugin_init,
    push_forwarder_plugin_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
