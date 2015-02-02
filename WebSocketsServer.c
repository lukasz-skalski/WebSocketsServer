/*
 * Copyright (C) Lukasz Skalski <lukasz.skalski@op.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE
#include <gio/gio.h>
#include <glib-unix.h>
#include <string.h>
#include <syslog.h>
#include <jansson.h>
#include <libwebsockets.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#endif

#define MAX_PAYLOAD 10000


/*
 * Global variables
 */
static struct libwebsocket_context *context;
char *notification;

gboolean opt_no_daemon = FALSE;
gboolean exit_loop = FALSE;
gboolean send_notification = FALSE;
gint port = 8080;


/*
 * Commandline options
 */
GOptionEntry entries[] =
{
  { "no-daemon", 'n', 0, G_OPTION_ARG_NONE, &opt_no_daemon, "Don't detach WebSocketsServer into the background", NULL},
  { "port", 'p', 0, G_OPTION_ARG_INT, &port, "Port number [default: 8080]", NULL },
  { NULL }
};


/*
 * Static buffer
 */
struct per_session_data {
  unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
  unsigned int len;
  unsigned int index;
};


/*
 *  print_log()
 */
static void
print_log (gint msg_priority, const gchar *msg, ...)
{
  va_list arg;
  va_start(arg, msg);

  GString *log = g_string_new(NULL);
  g_string_vprintf (log, msg, arg);

#ifdef DEBUG
  g_print ("%s", log->str);
#endif

#ifdef HAVE_SYSTEMD
  sd_journal_print (msg_priority, log->str);
#else
  syslog (msg_priority, log->str);
#endif

  g_string_free(log, TRUE);
  va_end(arg);
}


/*
 * SIGINT handler
 */
static gboolean
sigint_handler ()
{
  libwebsocket_cancel_service (context);
  exit_loop = TRUE;
  return TRUE;
}


/*
 * dbus_notification_callback()
 */
void dbus_notification_callback (GDBusConnection  *connection,
                                 const gchar      *sender_name,
                                 const gchar      *object_path,
                                 const gchar      *interface_name,
                                 const gchar      *signal_name,
                                 GVariant         *parameters,
                                 gpointer          user_data)
{
  json_t *notification_obj;
  char *notification_msg;

  print_log (LOG_INFO, "(notification) NOTIFICATION\n");

  send_notification = FALSE;
  notification_msg = NULL;
  free (notification);

  /* UDisk - 'DeviceAdded' */
  if ((strcmp(interface_name, "org.freedesktop.UDisks") == 0) &&
      (strcmp(signal_name, "DeviceAdded") == 0))
      asprintf (&notification_msg, "[UDisks] %s", signal_name);

  if (!notification_msg)
    asprintf (&notification_msg, "(not set)");

  notification_obj = json_pack ("{s:s, s:s}", "Type", "notification", "Message", notification_msg);
  notification = json_dumps (notification_obj, 0);

  free (notification_msg);
  json_decref (notification_obj);
  send_notification = TRUE;
}


/*
 * prepare_reply()
 */
unsigned int
prepare_reply (struct libwebsocket  *wsi,
               unsigned char        *data,
               unsigned char        *buffer)
{
  json_t *reply_obj;
  char *reply_str;
  char *reply;
  int reply_len;

  asprintf (&reply, "You typed \"%s\"", data);

  reply_obj = json_pack ("{s:s, s:s}", "Type", "standard", "Message", reply);
  reply_str = json_dumps (reply_obj, 0);

  reply_len = strlen (reply_str);
  memcpy (buffer, reply_str, reply_len);

  json_decref (reply_obj);
  free (reply);
  free (reply_str);
  return reply_len;
}


/*
 * my_callback()
 */
static int
my_callback (struct libwebsocket_context *context,
             struct libwebsocket *wsi,
             enum libwebsocket_callback_reasons reason,
             void *user, void *in, size_t len)
{
  struct per_session_data *psd = (struct per_session_data*) user;
  int nbytes;

  switch (reason)
    {

      case LWS_CALLBACK_ESTABLISHED:
        print_log (LOG_INFO, "(%p) (callback) connection established\n", wsi);
      break;

      case LWS_CALLBACK_CLOSED:
        print_log (LOG_INFO, "(%p) (callback) connection closed\n", wsi);
      break;

      case LWS_CALLBACK_SERVER_WRITEABLE:

        /* broadcast message */
        if (psd->buf[LWS_SEND_BUFFER_PRE_PADDING] == 0)
          {
            psd->len = strlen (notification);
            if (psd->len == 0)
              return 0;
            memcpy (&psd->buf[LWS_SEND_BUFFER_PRE_PADDING], notification, psd->len);
          }

        nbytes = libwebsocket_write(wsi, &psd->buf[LWS_SEND_BUFFER_PRE_PADDING], psd->len, LWS_WRITE_TEXT);
        memset (&psd->buf[LWS_SEND_BUFFER_PRE_PADDING], 0, psd->len);
        print_log (LOG_INFO, "(%p) (callback) %d bytes written\n", wsi, nbytes);
        if (nbytes < 0)
          {
            print_log (LOG_ERR, "(%p) (callback) %d bytes writing to socket, hanging up\n", wsi, nbytes);
            return 1;
          }
        if (nbytes < (int)psd->len)
          {
            print_log (LOG_ERR, "(%p) (callback) partial write\n", wsi);
            return -1; /*TODO*/
          }
      break;

      case LWS_CALLBACK_RECEIVE:
        print_log (LOG_INFO, "(%p) (callback) received %d bytes\n", wsi, (int) len);
        if (len > MAX_PAYLOAD)
          {
            print_log (LOG_ERR, "(%p) (callback) packet bigger than %u, hanging up\n", wsi, MAX_PAYLOAD);
            return 1;
          }

        psd->len = prepare_reply (wsi, in, &psd->buf[LWS_SEND_BUFFER_PRE_PADDING]);
        if (psd->len > 0)
          {
            libwebsocket_callback_on_writable (context, wsi);
          }
      break;

      default:
      break;
    }

  return 0;
}


/*
 * Defined protocols
 */
static struct libwebsocket_protocols protocols[] = {
  {
    "my_protocol",                    /* protocol name */
    my_callback,                      /* callback */
    sizeof(struct per_session_data)   /* max frame size / rx buffer */
  },
  {
    NULL, NULL, 0
  }
};


/*
 * main function
 */
int
main(int argc, char **argv)
{
  GDBusConnection *connection = NULL;
  GOptionContext *option_context = NULL;
  GError *error = NULL;

  gint cnt = 0;
  gint signal_id = 0;
  gint exit_value = EXIT_SUCCESS;
  struct lws_context_creation_info info;

  /* parse commandline options */
  option_context = g_option_context_new ("- WebSocketsServer");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_printerr ("%s: %s\n", argv[0], error->message);
      exit_value = EXIT_FAILURE;
      goto out;
    }

  /* deamonize */
  if (!opt_no_daemon && lws_daemonize("/var/run/lock/.websocketsserver-lock"))
    {
      g_printerr ("%s: failed to daemonize\n", argv[0]);
      exit_value = EXIT_FAILURE;
      goto out;
    }

  /* open syslog */
#ifndef HAVE_SYSTEMD
  openlog("WebSocketsServer", LOG_NOWAIT|LOG_PID, LOG_USER);
#endif

  /* fill 'lws_context_creation_info' struct */
  memset (&info, 0, sizeof info);
  info.port = port;
  info.iface = NULL;
  info.protocols = protocols;
  info.extensions = libwebsocket_get_internal_extensions();
  info.gid = -1;
  info.uid = -1;
  info.options = 0;
  info.ssl_cert_filepath = NULL;
  info.ssl_private_key_filepath = NULL;

  /* connect to the bus */
  connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  if (connection == NULL)
    {
      print_log (LOG_ERR, "(main) Error connecting to D-Bus: %s - some notification won't be available\n", error->message);
      g_error_free (error);
    }
  else
    {
      print_log (LOG_INFO, "(main) Connected to D-Bus\n");

      /* UDisks - 'DeviceAdded' */
      g_dbus_connection_signal_subscribe (connection,
                                          "org.freedesktop.UDisks",
                                          NULL,
                                          "DeviceAdded",
                                          NULL,
                                          NULL,
                                          G_DBUS_SIGNAL_FLAGS_NONE,
                                          dbus_notification_callback,
                                          NULL,
                                          NULL);
    }

  /* handle SIGINT */
  signal_id = g_unix_signal_add (SIGINT, sigint_handler, NULL);

  /* create context */
  context = libwebsocket_create_context (&info);
  if (context == NULL)
    {
      print_log (LOG_ERR, "(main) libwebsocket context init failed\n");
      goto out;
    }
  print_log (LOG_INFO, "(main) context - %p\n", context);

  /* main loop */
  while (cnt >= 0 && !exit_loop)
    {
      cnt = libwebsocket_service (context, 10);

      if (send_notification)
        {
          libwebsocket_callback_on_writable_all_protocol (&protocols[0]);
          send_notification = FALSE;
        }

      g_main_context_iteration (NULL, FALSE);
    }

out:

  if (context != NULL)
    libwebsocket_context_destroy (context);
  if (signal_id > 0)
    g_source_remove (signal_id);
  if (option_context != NULL)
    g_option_context_free (option_context);

#ifndef HAVE_SYSTEMD
  closelog();
#endif

  return exit_value;
}
