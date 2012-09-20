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
#ifndef CPU_H
#define CPU_H

#include <glib-2.0/glib.h>

#define HT_PER_CPU		2
#define HT_MASK			((1 << HT_PER_CPU) - 1)

#define OLD		0
#define NEW		1

struct proc_stat_cpu {
	unsigned long long psc_user;
	unsigned long long psc_nice;
	unsigned long long psc_system;
	unsigned long long psc_idle;
	unsigned long long psc_iowait;
	unsigned long long psc_irq;
	unsigned long long psc_softirq;
	unsigned long long psc_steal;
	unsigned long long psc_guest;
	unsigned long long psc_softirq_ctr;
};

/* /proc/stat */
struct proc_stat {
	size_t ps_len;
	unsigned long long ps_ctxt;
	unsigned long ps_btime;
	unsigned long ps_procs;
	unsigned long ps_procs_running;
	unsigned long ps_procs_blocked;
	struct proc_stat_cpu ps_cpu_total;
};

struct if_queue_info;
struct cpuset;

struct cpu_info {
	unsigned ci_num;
	GSList *ci_queues;
	unsigned ci_num_queues;
	unsigned ci_load;			/* in percent */
	unsigned ci_si_load;		/* softirq load (in percent) */

	struct cpuset *ci_cpuset;	/* or NULL */

	/* /proc/net/softnet_stat */
	struct softnet_stat {
		unsigned total;
		unsigned dropped;
		unsigned time_squeeze;
		unsigned cpu_collision;
	} ci_ss[2];
	struct proc_stat_cpu ci_psc;
	struct proc_stat_cpu ci_psc_old;
};

#define CPU_SS_DIFF(ci, var) ((ci)->ci_ss[NEW].var - (ci)->ci_ss[OLD].var)

extern GSList *cpu_lru_list;
extern GSList *cpu_si_load_lru_list;

extern GSList *cpuset_list;

int cpu_init(void);
void cpu_fini(void);
unsigned cpu_count(void);
struct cpu_info *cpu_add_queue(int, struct interface *, int);
struct cpu_info *cpu_add_queue_lru(struct interface *, int);
int cpu_del_queue(int, struct if_queue_info *qi);
struct cpu_info *cpu_nth(int);

int cpu_read_stat(void);
int cpu_do_stat(void);
void cpu_dump_map(void);

/* a contigous range of CPUs */
struct cpu_bitmask {
	struct cpuset *cpuset;
	unsigned len;
	int nbits;
	uint8_t data[];
};

struct cpu_bitmask *cpu_bitmask_new(struct cpuset *);
void cpu_bitmask_free(struct cpu_bitmask *);
int cpu_bitmask_set(struct cpu_bitmask *, unsigned) __WARN_UNUSED_RESULT;
int cpu_bitmask_clear(struct cpu_bitmask *, unsigned) __WARN_UNUSED_RESULT;
bool cpu_bitmask_is_set(const struct cpu_bitmask *, unsigned);
int cpu_bitmask_ffs(const struct cpu_bitmask *);
uint64_t cpu_bitmask_mask64(const struct cpu_bitmask *);

static inline bool cpu_bitmask_is_empty(const struct cpu_bitmask *bmask)
{
	return bmask->nbits == 0;
}

static inline int cpu_bitmask_ncpus(const struct cpu_bitmask *bmask)
{
	return bmask->nbits;
}

struct device;

struct cpuset {
	unsigned cs_from;
	unsigned cs_len;
#define CS_F_AUTO_ASSIGN		0x0001
	unsigned cs_flags;
	char *cs_name;

	struct strategy cs_strategy;

	/* CPU info sorted by number of queues/IRQs assigned */
	GSList *cs_cpu_lru_list;

	GSList *cs_dev_list;
};

extern struct cpuset *g_cpuset_auto_assign;

struct cpuset *cpuset_new(const char *, unsigned first, unsigned len);
void cpuset_free(struct cpuset *);
GSList *cpuset_get_by_name(const char *);
int cpuset_add_device(struct cpuset *, struct device *);
int cpuset_list_add(struct cpuset *);
bool cpuset_in(const struct cpuset *, unsigned);
int cpuset_set_auto_assign(struct cpuset *);
int cpuset_set_strategy(struct cpuset *, const char *);
int cpuset_interface_down(struct cpuset *, struct interface *);
int cpuset_cpu_busy(struct cpuset *, struct cpu_info *);
int cpuset_balance_queue(struct cpuset *, struct interface *, int);
void cpuset_dump(void);

static inline unsigned
cpuset_len(const struct cpuset *set)
{
	return set->cs_len;
}

static inline unsigned
cpuset_last_cpu(const struct cpuset *set)
{
	return set->cs_from + cpuset_len(set) - 1;
}

#endif /* CPU_H */
