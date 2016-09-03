#include <strophe.h>

struct message {
  const char * to;
  const char * message;
};

static void xmpp_send_message(xmpp_conn_t *conn, struct message * const msg) {
   xmpp_stanza_t *x_msg, *x_body, *x_text;
   xmpp_ctx_t *ctx = xmpp_conn_get_context(conn);

   x_msg = xmpp_stanza_new(ctx);
   xmpp_stanza_set_name(x_msg, "message");
   xmpp_stanza_set_type(x_msg, "chat");
   xmpp_stanza_set_attribute(x_msg, "to", msg->to);

   x_body = xmpp_stanza_new(ctx);
   xmpp_stanza_set_name(x_body, "body");

   x_text = xmpp_stanza_new(ctx);
   xmpp_stanza_set_text(x_text, msg->message);
   xmpp_stanza_add_child(x_body, x_text);
   xmpp_stanza_add_child(x_msg, x_body);

   xmpp_send(conn, x_msg);
   xmpp_stanza_release(x_msg);
}

static void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status,
                  const int error, xmpp_stream_error_t * const stream_error,
                  void * const userdata) {
    if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: connected\n");
        xmpp_send_message(conn, (struct message*) userdata);
        xmpp_disconnect(conn);
    } else {
        xmpp_ctx_t * ctx = xmpp_conn_get_context(conn);
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

void send_message(const char * jid,
                  const char * password,
                  const char * message,
                  const char * to) {
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_ctx_t * ctx;
    struct message * const msg = (struct message *)alloca(sizeof(struct message));
    msg->to = to;
    msg->message = message;

    // TODO: Wait for version 0.8.9
//    long flags = XMPP_CONN_FLAG_MANDATORY_TLS;

    /* init library */
    xmpp_initialize();

    /* create a context */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG); /* pass NULL instead to silence output */
    ctx = xmpp_ctx_new(NULL, log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* configure connection properties (optional) */
    // TODO: Wait for version 0.8.9
//    xmpp_conn_set_flags(conn, flags);

    /* setup authentication information */
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, password);

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, (void*)msg);

    /* enter the event loop -
       our connect handler will trigger an exit */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();
}
