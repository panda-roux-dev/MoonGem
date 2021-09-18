#include "runtime.h"

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "log.h"

static volatile sig_atomic_t terminate = 0;
static volatile sig_atomic_t stop = 0;

static void block_sigstop(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGSTOP);
  pthread_sigmask(SIG_BLOCK, &set, NULL);
}

static void unblock_sigstop(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGSTOP);
  pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}

static void wait_until_continue(void) {
  block_sigstop();

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGABRT);
  sigaddset(&set, SIGINT);

  int sig;
  sigwait(&set, &sig);

  unblock_sigstop();

  stop = 0;
  switch (sig) {
    case SIGKILL:
      LOG("Caught KILL signal, exiting immediately...");
      exit(EXIT_FAILURE);
    case SIGTERM:
    case SIGABRT:
    case SIGINT:
      LOG("Caught TERM/ABRT/INT signal, shutting-down gracefully...");
      terminate = 1;
      break;
    case SIGCONT:
      LOG("Caught CONT signal while paused, continuing...");
      break;
  }
}

static void* signal_handler_routine(void* ptr) {
  ((void)ptr);

  pthread_detach(pthread_self());
  pthread_setname_np(pthread_self(), "signal-handler");

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGABRT);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGSTOP);

  pthread_sigmask(SIG_UNBLOCK, &set, NULL);

  int sig;
  while (!terminate) {
    sigwait(&set, &sig);
    switch (sig) {
      case SIGKILL:
        LOG("Caught KILL signal, exiting immediately...");
        exit(EXIT_FAILURE);
      case SIGTERM:
      case SIGABRT:
      case SIGINT:
        LOG("Caught TERM/ABRT/INT signal, shutting-down gracefully...");
        terminate = 1;
        break;
      case SIGSTOP:
      case SIGTSTP:
        LOG("Caught STOP/TSTP signal, pausing...");
        stop = 1;
        wait_until_continue();
        break;
      default:
        break;
    }
  }

  return NULL;
}

bool should_terminate(void) { return terminate == 1; }

bool is_stopped(void) { return stop == 1; }

void begin_signal_handler(void) {
  pthread_t handler_thread;
  pthread_create(&handler_thread, NULL, signal_handler_routine, NULL);
}
