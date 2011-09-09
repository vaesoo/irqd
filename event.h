/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Holger Eitzenberger <holger@eitzenberger.org>, Sophos, 2010.
 */
#ifndef EVENT_H
#define EVENT_H

#include <sys/epoll.h>

enum EvReturn {
	EvError = -1,
	EvOk,
	EvStop,
};

struct ev;

typedef enum EvReturn (* ev_cb_t)(struct ev *, unsigned short);
typedef int (* ev_cb_done_t)(void *, int);

#define EV_ID			0xdeadbeaf

struct ev {
	int fd;
	unsigned short when;
	/**
	 * Returns %EvOk, %EvStop to stop event processing, or %EvError
	 * on error.  Receives error events.
	 */
	ev_cb_t cb_read;
	/**
	 * Returns %EvOk, %EvStop to stop event processing, or %EvError
	 * on error.
	 */
	ev_cb_t cb_write;
	/**
	 * cb_done() - inform higher layer about destruction
	 */
	ev_cb_done_t cb_done;
	void *arg;
	int id;
	struct {
		unsigned nhandled;
	} stat;
};

#define EV_READ			EPOLLIN
#define EV_WRITE		EPOLLOUT

int ev_init(void);
void ev_fini(void);
struct ev *ev_new(void);
int ev_del(struct ev *);
void ev_free(struct ev *);
void ev_set(struct ev *, int, ev_cb_done_t, void *);
int ev_add(struct ev *, unsigned short);
int ev_mod(struct ev *, unsigned short);
int ev_clear(struct ev *, unsigned short);
void ev_done(struct ev *, int);
int ev_dispatch(void);

#endif /* EVENT_H */
