#include <event2/event.h>
#include <signal.h>

#include "log.h"

static void signal_shutdown_cb(evutil_socket_t sig, short events, void* data) {
  LOG("Caught shutdown signal; terminating...");
  event_base_loopexit((struct event_base*)data, NULL);
}

static void signal_termstop_cb(evutil_socket_t sig, short events, void* data) {
  LOG("Caught SIGTSTP; pausing I/O...");
  event_base_loopbreak((struct event_base*)data);
}

static void signal_continue_cb(evutil_socket_t sig, short events, void* data) {
  LOG("Caught SIGCONT; resuming I/O...");
  event_base_loopcontinue((struct event_base*)data);
}

static void signal_ignore_cb(evutil_socket_t sig, short events, void* data) {}

typedef struct {
  event_callback_fn cb;
  short signal;
} sigcb_t;

static sigcb_t callbacks[] = {{signal_shutdown_cb, SIGINT},
                              {signal_ignore_cb, SIGPIPE},
                              {signal_shutdown_cb, SIGTERM},
                              {signal_termstop_cb, SIGTSTP},
                              {signal_continue_cb, SIGCONT}};

typedef struct event* event_ptr_t;

static void add_signal_handlers(event_ptr_t** events, struct event_base* base) {
  int cb_count = sizeof(callbacks) / sizeof(sigcb_t);
  *events = (event_ptr_t*)malloc(cb_count * sizeof(event_ptr_t));
  for (int i = 0; i < cb_count; ++i) {
    (*events)[i] =
        evsignal_new(base, callbacks[i].signal, callbacks[i].cb, base);
    evsignal_add((*events)[i], NULL);
  }
}

event_ptr_t* init_signal_handlers(struct event_base* evtbase) {
  event_ptr_t* evts;
  add_signal_handlers(&evts, evtbase);
  return evts;
}

void cleanup_signal_handlers(event_ptr_t* evts) {
  if (evts == NULL) {
    return;
  }

  for (int i = 0; i < sizeof(callbacks) / sizeof(sigcb_t); ++i) {
    if (evts[i] != NULL) {
      event_free(evts[i]);
    }
  }

  free(evts);
}
