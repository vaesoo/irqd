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
#define DEBUG
#include "irqd.h"
#include "cpu.h"
#include "interface.h"

#define CPUSET_BITS			8
#define CPUSET_SIZE(bits)	(((bits) + CPUSET_BITS - 1) & ~(CPUSET_BITS - 1))

#define CPU_MAP_FILE	"irqd.cpumap"


static struct cpu_info *cpus;
GSList *cpu_lru_list;	/* CPUs sorted by number of users */
GSList *cpu_si_load_lru_list;
static unsigned num_cpus;
struct proc_stat proc_stat, proc_stat_old;

static void dump_cpus(const char *, const GSList *list) __UNUSED;

static gint
cpu_cmp(gconstpointer __a, gconstpointer __b)
{
	const struct cpu_info *a = __a, *b = __b;

	if (a->ci_num_queues != b->ci_num_queues)
		return a->ci_num_queues - b->ci_num_queues;
	return a->ci_num - b->ci_num;
}

int
cpu_init(void)
{
	int cpu;

	/* TODO read sysfs instead */
	num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if ((cpus = calloc(num_cpus, sizeof(struct cpu_info))) == NULL) {
		OOM();
		return -1;
	}

	for (cpu = 0; cpu < num_cpus; cpu++) {
		cpus[cpu].ci_num = cpu;
		cpu_lru_list = g_slist_append(cpu_lru_list, &cpus[cpu]);
	}

	return 0;
}

void
cpu_fini(void)
{
	free(cpus);
}

unsigned
cpu_count(void)
{
	return num_cpus;
}

struct cpu_info *
cpu_nth(int cpu)
{
	BUG_ON(cpu < 0);
	if (cpu >= num_cpus)
		return NULL;
	return &cpus[cpu];
}

static void
dump_cpus(const char *prefix, const GSList *list)
{
	char buf[1024], *pch = buf, *end = buf + 1024;

	snprintf(pch, end - pch, "%s: ", prefix);
	for (; list; list = list->next) {
		const struct cpu_info *ci = list->data;

		pch += snprintf(pch, end - pch, "cpu%d/%dq ", ci->ci_num,
					   ci->ci_num_queues);
	}

	log("%s", buf);
}

static struct cpu_info *
add_queue(struct cpu_info *ci, struct if_queue_info *qi)
{
	ci->ci_queues = g_slist_append(ci->ci_queues, qi);
	ci->ci_num_queues++;
	cpu_lru_list = g_slist_remove_link(cpu_lru_list, cpu_lru_list);
	cpu_lru_list = g_slist_insert_sorted(cpu_lru_list, ci, cpu_cmp);

	return ci;
}

struct cpu_info *
cpu_add_queue(int cpu, struct interface *iface, int queue)
{
	struct cpu_info *ci = cpu_nth(cpu);
	struct if_queue_info *qi = if_queue(iface, queue);

	BUG_ON(!ci);
	return add_queue(ci, qi);
}

struct cpu_info *
cpu_add_queue_lru(struct interface *iface, int queue)
{
	struct cpu_info *ci = cpu_lru_list->data;
	struct if_queue_info *qi = if_queue(iface, queue);

	BUG_ON(!ci);
	return add_queue(ci, qi);
}

int
cpu_del_queue(int cpu, struct if_queue_info *qi)
{
	struct cpu_info *ci = cpu_nth(cpu);

	BUG_ON(!ci || ci->ci_num_queues == 0);
	ci->ci_queues = g_slist_remove(ci->ci_queues, qi);
	ci->ci_num_queues--;

	cpu_lru_list = g_slist_remove(cpu_lru_list, ci);
	cpu_lru_list = g_slist_insert_sorted(cpu_lru_list, ci, cpu_cmp);

	return -1;
}

#ifdef DEBUG
#define __SS_WRAP_CHECK(ci, var) ({										\
			typeof((ci)->ci_ss[OLD].var) old = (ci)->ci_ss[OLD].var;	\
			typeof((ci)->ci_ss[NEW].var) new = (ci)->ci_ss[NEW].var;	\
			if (new < old && old - new > (1 << 31)) BUG();				\
		})
#else
#define __SS_WRAP_CHECK(ci, var)
#endif /* DEBUG */

#define SS_WRAP(ci, var) ({											 \
			if ((ci)->ci_ss[NEW].var < (ci)->ci_ss[OLD].var)		 \
				ci->ci_ss[OLD].var = 0U;							 \
			__SS_WRAP_CHECK(ci, var);								 \
		})
	
static int
read_softnet_stat(void)
{
	char *line = NULL;
	FILE *fp;
	size_t line_len;
	int cpu, ret;

	if ((fp = id_fopen("/proc/net/softnet_stat", "r")) == NULL)
		BUG();

	for (cpu = 0; cpu < num_cpus; cpu++) {
		struct cpu_info *ci = &cpus[cpu];
		struct softnet_stat *ss = &ci->ci_ss[NEW];

		if (getline(&line, &line_len, fp) == EOF)
			BUG();

		memcpy(&ci->ci_ss[OLD], &ci->ci_ss[NEW], sizeof(struct softnet_stat));

		/* there is another field 'received_rps' in newer kernels, which
		   is currently ignored */
		ret = sscanf(line, "%08x %08x %08x 00000000 00000000 00000000 "
					 "00000000 00000000 %08x", &ss->total, &ss->dropped,
					 &ss->time_squeeze, &ss->cpu_collision);
		BUG_ON(ret != 4);

		SS_WRAP(ci, total);
		SS_WRAP(ci, dropped);
		SS_WRAP(ci, time_squeeze);
		SS_WRAP(ci, cpu_collision);
	}

	g_free(line);
	fclose(fp);

	return 0;
}

static int
read_proc_stat_softirq(struct proc_stat *ps, char *line)
{
	char *tok = strtok(line, " \t");
	int cpu = 0;

	BUG_ON(strcmp(tok, "softirq"));
	while ((tok = strtok(NULL, " \t")) != NULL) {
		struct cpu_info *ci = cpu_nth(cpu);
		
		ci->ci_psc.psc_softirq_ctr = strtoull(tok, NULL, 10);
	}

	return 0;
}

static int
read_proc_stat(struct proc_stat *ps)
{
	size_t line_len = 4096;
	char *line = malloc(line_len);
	FILE *fp;
	int ret;

	if ((fp = id_fopen("/proc/stat", "r")) == NULL)
		return -1;

	do {
		struct proc_stat_cpu *psc;
		int cpu;

		psc = &ps->ps_cpu_total;
		if ((getline(&line, &line_len, fp)) == EOF)
			break;
		ret = sscanf(line, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
					 &psc->psc_user, &psc->psc_nice, &psc->psc_system,
					 &psc->psc_idle, &psc->psc_iowait, &psc->psc_irq,
					 &psc->psc_softirq, &psc->psc_steal, &psc->psc_guest);
		BUG_ON(ret != 9);
		for (cpu = 0; cpu < num_cpus; cpu++) {
			struct cpu_info *ci = cpu_nth(cpu);
			int cpu_tmp;

			BUG_ON(!ci);
			if ((getline(&line, &line_len, fp)) == EOF)
				break;
			psc = &ci->ci_psc;
			ret = sscanf(line, "cpu%d %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
						 &cpu_tmp,
						 &psc->psc_user, &psc->psc_nice, &psc->psc_system,
						 &psc->psc_idle, &psc->psc_iowait, &psc->psc_irq,
						 &psc->psc_softirq, &psc->psc_steal, &psc->psc_guest);
			BUG_ON(cpu_tmp != cpu);
			BUG_ON(ret != 10);
		}

		if (getline(&line, &line_len, fp) == EOF)
			break;
		/* ignore IRQ line for now */

		if ((ret = fscanf(fp, "ctxt %Lu\n", &ps->ps_ctxt)) != 1)
			BUG();
		if ((ret = fscanf(fp, "btime %lu\n", &ps->ps_btime)) != 1)
			BUG();
		if ((ret = fscanf(fp, "processes %lu\n", &ps->ps_procs)) != 1)
			BUG();
		if ((ret = fscanf(fp, "procs_running %lu\n",
						  &ps->ps_procs_running)) != 1)
			BUG();
		if ((ret = fscanf(fp, "procs_blocked %lu\n",
						  &ps->ps_procs_blocked)) != 1)
			BUG();

		if (getline(&line, &line_len, fp) == EOF)
			break;
		if (read_proc_stat_softirq(ps, line) < 0)
			break;
	} while (0);

	free(line);
	fclose(fp);

	return 0;
}

int
cpu_read_stat(void)
{
	int cpu;

	if (read_softnet_stat() < 0)
		return -1;

	memcpy(&proc_stat_old, &proc_stat, sizeof(proc_stat));
	for (cpu = 0; cpu < num_cpus; cpu++) {
		struct cpu_info *ci = cpu_nth(cpu);

		if (!ci)
			continue;
		memcpy(&ci->ci_psc_old, &ci->ci_psc, sizeof(ci->ci_psc_old));
	}
	if (read_proc_stat(&proc_stat) < 0)
		return -1;

	return 0;
}

static gint
cpu_si_load_cmp(gconstpointer __a, gconstpointer __b)
{
	const struct cpu_info *a = __a, *b = __b;

	if (a->ci_si_load != b->ci_si_load)
		return a->ci_si_load - b->ci_si_load;
	return a->ci_num - b->ci_num;
}

static int
do_stat_cpu(struct cpu_info *ci)
{
	const struct proc_stat_cpu *psc = &ci->ci_psc;
	const struct proc_stat_cpu *psco = &ci->ci_psc_old;
	unsigned long long frm_tot, frm_tot_old, frm_si;

	frm_si = psc->psc_softirq - psco->psc_softirq;
	frm_tot = psc->psc_user + psc->psc_nice + psc->psc_system
		+ psc->psc_idle + psc->psc_iowait + psc->psc_irq
		+ psc->psc_softirq + psc->psc_steal + psc->psc_guest;
	frm_tot_old = psco->psc_user + psco->psc_nice + psco->psc_system
		+ psco->psc_idle + psco->psc_iowait + psco->psc_irq
		+ psco->psc_softirq + psco->psc_steal + psco->psc_guest;
	if (frm_tot > frm_tot_old)
		ci->ci_si_load = (frm_si * 100 / (frm_tot - frm_tot_old));
	else
		ci->ci_si_load = 0U;

	cpu_si_load_lru_list = g_slist_remove(cpu_si_load_lru_list, ci);
	cpu_si_load_lru_list = g_slist_insert_sorted(cpu_si_load_lru_list,
												 ci, cpu_si_load_cmp);

	return 0;
}

int
cpu_do_stat(void)
{
	int cpu;

	for (cpu = 0; cpu < num_cpus; cpu++) {
		struct cpu_info *ci = cpu_nth(cpu);

		if (ci)
			do_stat_cpu(ci);
	}

#if 0
	{
		char buf[128], *pch = buf, *end = buf + 128;
		GSList *node;

		for (node = cpu_si_load_lru_list; node; node = node->next) {
			const struct cpu_info *ci = node->data;

			pch += snprintf(pch, end - pch, " cpu%d", ci->ci_num);
		}

		log("%s", buf);
	}
#endif /* 0 */

	return 0;
}

void
cpu_dump_map(void)
{
	char path[PATH_MAX], *line = g_malloc(4096);
	FILE *fp;
	int cpu;

	/* do not use _PATH_VARDB, as on sles11 it points to /var/db,
	   which doesn't exist, */
	snprintf(path, sizeof(path), "/var/lib/misc/%s", CPU_MAP_FILE);
	if ((fp = fopen(path, "w")) == NULL) {
		g_free(line);
		return;
	}

	for (cpu = 0; cpu < num_cpus; cpu++) {
		char *pch = line, *end = line + 4096;
		GSList *node;

		if (!cpus[cpu].ci_queues)
			continue;
		pch += snprintf(pch, end - pch, "cpu%d:", cpu);
		for (node = cpus[cpu].ci_queues; node; node = node->next) {
			struct if_queue_info *qi = node->data;

			pch += snprintf(pch, end - pch, " %s:%d", qi->qi_iface->if_name,
				qi->qi_num);
		}

		fprintf(fp, "%s\n", line);
	}

	g_free(line);
	fclose(fp);
}

struct cpuset *
cpuset_new(void)
{
	struct cpuset *set;

	BUG_ON(!num_cpus);
	set = g_malloc0(sizeof(struct cpuset) + CPUSET_SIZE(num_cpus) / 8);
	if (set)
		set->len = CPUSET_SIZE(num_cpus) / 8;
	else
		OOM();

	return set;
}

void
cpuset_free(struct cpuset *set)
{
	g_free(set);
}

/**
 * @return 1: set, 0: already set
 */
int
cpuset_set(struct cpuset *set, unsigned cpu)
{
	int off = cpu / CPUSET_BITS, bit = cpu % CPUSET_BITS;

	BUG_ON(off >= set->len);
	if ((set->data[off] & (1 << bit)) == 0) {
		set->data[off] |= (1 << bit);
		set->ncpus++;

		return 1;
	}

	return 0;
}

/**
 * @return 1: cleared, 0: already cleared
 */
int
cpuset_clear(struct cpuset *set, unsigned cpu)
{
	int off = cpu / CPUSET_BITS, bit = cpu % CPUSET_BITS;

	BUG_ON(off >= set->len);
	if (set->data[off] & (1 << bit)) {
		set->data[off] &= ~(1 << bit);
		BUG_ON(set->ncpus == 0);
		set->ncpus--;

		return 1;
	}

	return 0;
}

bool
cpuset_is_set(const struct cpuset *set, unsigned cpu)
{
	int off = cpu / CPUSET_BITS, bit = cpu % CPUSET_BITS;

	BUG_ON(off >= set->len);
	return (set->data[off] & (1 << bit)) != 0;
}

int
cpuset_ffs(const struct cpuset *set)
{
	int off;

	for (off = 0; off < set->len; off++) {
		if (set->data[off]) {
			int bit;

			for (bit = 0; bit < 8; bit++)
				if (set->data[off] & (1 << bit))
					return off * 8 + bit;
		}
	}

	return -1;
}

uint64_t
cpuset_mask64(const struct cpuset *set)
{
	uint64_t mask = 0ULL;
	size_t len;

#if 0
	{
		int cpu;

		for (cpu = 0; cpu < set->len * 8; cpu++)
			if (cpuset_is_set(set, cpu))
				mask |= (1LLU << cpu);
	}
#endif /* 0 */

	len = set->len > sizeof(uint64_t) ? sizeof(uint64_t) : set->len;
	memcpy(&mask, set->data, len);

	return mask;
}
