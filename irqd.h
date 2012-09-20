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
#ifndef IRQD_H
#define IRQD_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <paths.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <glib-2.0/glib.h>

#define CPU_MAX			64

/* number of per-NIC queues supported */
#define QUEUE_MAX		128

#define __PRINTF(idx, first)	__attribute__((format (printf, idx, first)))
#define __NORETURN				__attribute__((noreturn))
#define __COLD					__attribute__((cold))
#define __UNUSED				__attribute__((unused))
#define __WARN_UNUSED_RESULT	__attribute__((warn_unused_result))

#define likely(expr)	__builtin_expect(!!(expr), 1)
#define unlikely(expr)	__builtin_expect(!!(expr), 0)

#define ARRAY_SIZE(arr)			(sizeof(arr) / sizeof(arr[0]))

#define min(x, y) ({ \
			typeof(x) _x = (x);  typeof(y) _y = (y);	\
			_x < _y ? _x : _y; })
#define max(x, y) ({ \
			typeof(x) _x = (x);  typeof(y) _y = (y);	\
			_x > _y ? _x : _y; })

#define ENV_BUF_SIZE			4096

struct interface;
struct cpu_info;

struct balance_strategy {
	const char *name;
	/**
	 * Strategy handler to balance an interface queue, called once
	 * the interface becomes %IFF_UP.
	 */
	int (* balance_queue)(struct interface *, int);

	/**
	 * Strategy handler to rebalance in case of a softirq becoming
	 * too busy.
	 */
	int (* softirq_busy)(struct cpu_info *);

	/**
	 * Strategy handler to eventually rebalance in case of an interface
	 * going down.  The handler is called before the queues are removed
	 * from the CPUs.
	 */
	int (* interface_down)(struct interface *);
};

int strategy_init(void);
struct balance_strategy *strategy_find(const char *);

/* logging */
int log_init(void);
void id_log(const char *fmt, ...) __PRINTF(1, 2);
void id_err(const char *file, int line, const char *, ...) __PRINTF(3, 4);
void id_err_status(const char *file, int line, const char *, int,
				   ...) __PRINTF(3, 5);
void id_bug(const char *file, int line) __NORETURN __COLD;
void id_oom(const char *file, int line) __COLD;

#define log(fmt, args...)	id_log(fmt, ##args)
#define err(fmt, args...)	id_err(__FILE__, __LINE__, fmt, ##args)	
#define err_status(fmt, status, args...) id_err_status(__FILE__, __LINE__, \
													   fmt, status, ##args)
#define OOM()			id_oom(__FILE__, __LINE__)

#define WARN()			id_err(__FILE__, __LINE__, "warning");
#define BUG()			id_bug(__FILE__, __LINE__)
#define BUG_ON(expr)	do { if (unlikely(expr)) BUG(); } while (0)
#define WARN_ON(expr)	do { if (unlikely(expr)) WARN(); } while (0)

#ifdef DEBUG
#define dbg(fmt, args...)	id_log(fmt, ##args)
#else
#define dbg(fmt, args...)
#endif /* DEBUG */

extern enum RpsStatus {
	RPS_S_NEED_CHECK = 0,
	RPS_S_DISABLED,
	RPS_S_ENABLED,
} g_rps_status;

extern enum XpsStatus {
	XPS_S_NEED_CHECK = 0,
	XPS_S_DISABLED,
	XPS_S_ENABLED,
} g_xps_status;

extern bool config_is_read;
extern char *irqd_prefix;
extern bool no_daemon;
extern int verbose;

int id_set_fd_flags(int, int);
char *id_path(const char *path);
FILE *id_fopen(const char *, const char *);

int irq_set_affinity(int, uint64_t);

char *xstrncpy(char *, const char *, size_t);

#endif /* IRQD_H */
