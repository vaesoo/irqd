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
 * Holger Eitzenberger <holger@eitzenberger.org>, Sophos, 2011.
 */
#include "irqd.h"
#include "event.h"

#include <signal.h>
#include <sys/epoll.h>

#define EPOLL_MAX_EVENTS		10

/* events allowed to be set by ev_add() */
#define EV_MASK_ALLOW			(EV_READ | EV_WRITE)

/* events handled by user */
#define EV_MASK_USER_HANDLER	(EV_READ | EV_WRITE)

static int epoll_fd;


int
ev_init(void)
{
	if ((epoll_fd = epoll_create1(O_CLOEXEC)) < 0) {
		err("epoll_create: %m");
		return -1;
	}

	return 0;
}

void
ev_fini(void)
{
	close(epoll_fd);
}

struct ev *
ev_new(void)
{
	struct ev *ev;

	if ((ev = g_malloc0(sizeof(struct ev))) == NULL) {
		OOM();
		return NULL;
	}

	ev->fd = -1;
	ev->id = EV_ID;

	return ev;
}

void
ev_free(struct ev *ev)
{
	if (ev) {
		if (ev->fd >= 0)
			close(ev->fd);
		g_free(ev);
	}
}

/**
 * ev_set() - initialize event
 *
 * @arg ev
 * @arg fd
 * @arg cb_io		callback used for IO
 * @arg cb_done		callback to inform higher layers (or %NULL)
 * @arg arg
 */
void
ev_set(struct ev *ev, int fd, ev_cb_done_t cb_done, void *arg)
{
	ev->fd = fd;
	ev->cb_done = cb_done;
	ev->arg = arg;
	ev->id = EV_ID;
}

int
ev_add(struct ev *ev, unsigned short when)
{
	struct epoll_event eev;

	BUG_ON(ev->fd < 0);
	BUG_ON(when & ~EV_MASK_ALLOW);

	id_set_fd_flags(ev->fd, O_NONBLOCK);
	eev.data.ptr = ev;
	eev.events = when | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev->fd, &eev) < 0) {
		err("%s: %m", __func__);
		goto err;
	}

	ev->when |= when;

	return 0;

err:
	return -1;
}

int
ev_mod(struct ev *ev, unsigned short when)
{
	struct epoll_event eev = {
		.data.ptr = ev,
	};
	int ret;

	if (ev->when & when)
		return 0;
	eev.events = ev->when | when | EPOLLET;
	if (ev->when)
		ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ev->fd, &eev);
	else
		ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev->fd, &eev);
	if (ret < 0)
		err("%s: %m", __func__);
	ev->when |= when;

	return ret;
}

int
ev_clear(struct ev *ev, unsigned short when)
{
	struct epoll_event eev = {
		.data.ptr = ev,
	};
	int ret;

	if ((ev->when & when) == 0)
		return 0;
	ev->when &= ~when;
	eev.events = ev->when;
	if (!ev->when)
		ret = ev_del(ev);
	else
		ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ev->fd, &eev);
	if (ret < 0)
		err("%s: %m", __func__);

	return ret;
}

/**
 * ev_del() - remove an event descriptor
 *
 * The event is not freed, just in case
 */
int
ev_del(struct ev *ev)
{
	if (ev->fd >= 0) {
		if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ev->fd, NULL) < 0) {
			err("epoll_ctl: %m\n");
			return -1;
		}

		dbg("%s: ev=%p", __func__, ev);
	}

	return 0;
}

void
ev_done(struct ev *ev, int why)
{
	if (ev->cb_done)
		ev->cb_done(ev, why);
	else
		ev_del(ev);
}

int
ev_dispatch(void)
{
	struct epoll_event events[EPOLL_MAX_EVENTS];

	for (;;) {
		int nfds, i;

		nfds = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			dbg("epoll_wait: %m");
		}

		dbg("%s: nfds=%d", __func__, nfds);
		for (i = 0; i < nfds; i++) {
			struct epoll_event *eev = &events[i];
			struct ev *ev = events[i].data.ptr;
			enum EvReturn ret;

			BUG_ON(ev->id != EV_ID);
			if (eev->events & EPOLLIN) {
				BUG_ON(!ev->cb_read);
				ret = ev->cb_read(ev, eev->events & EV_MASK_USER_HANDLER);
				ev->stat.nhandled++;
				if (ret != EvOk)
					goto ev_err;
			}
			if (eev->events & EPOLLOUT) {
				BUG_ON(!ev->cb_write);
				ret = ev->cb_write(ev, eev->events & EV_MASK_USER_HANDLER);
				ev->stat.nhandled++;
				if (ret != EvOk)
					goto ev_err;
			}
			continue;

		ev_err:
			if (ret == EvStop)
				ev_done(ev, 0);
			else if (ret == EvError)
				ev_done(ev, 0);
		}
	}

	return 0;
}
