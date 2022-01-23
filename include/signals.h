#ifndef SIGNALS_H
#define SIGNALS_H

struct event_base;  // defined in libevent2
struct event;       // defined in libevent2

struct event** init_signal_handlers(struct event_base* evtbase);

void cleanup_signal_handlers(struct event** evts);

#endif
