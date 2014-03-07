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
#include "cpu.h"
#include "interface.h"

#define CPUSET_BITS			8
#define CPUSET_SIZE(bits)	(((bits) + CPUSET_BITS - 1) & ~(CPUSET_BITS - 1))

#define CPU_MAP_FILE	"irqd.cpumap"


static struct cpu_info *cpus;
GSList *cpu_load_lru_list;
static unsigned num_cpus;
struct proc_stat proc_stat, proc_stat_old;

/* each CPU belongs to a single cpuset only */
GSList *cpuset_list;

struct cpuset *g_cpuset_auto_assign;

static void dump_cpus(const char *, const GSList *list) __UNUSED;

static gint
cpu_cmp(gconstpointer __a, gconstpointer __b)
{
	const struct cpu_info *a = __a, *b = __b;

	if (b->ci_num_queues != a->ci_num_queues)
		return a->ci_num_queues - b->ci_num_queues;
	return a->ci_num - b->ci_num;
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

static int
add_queue(struct cpu_info *ci, struct if_queue_info *qi)
{
	struct cpuset *set = ci->ci_cpuset;

	ci->ci_num_queues++;

	set->cs_cpu_lru_list = g_slist_remove_link(set->cs_cpu_lru_list,
		set->cs_cpu_lru_list);
	set->cs_cpu_lru_list = g_slist_insert_sorted(set->cs_cpu_lru_list, ci,
												 cpu_cmp);

	ci->ci_queues = g_slist_append(ci->ci_queues, qi);

	return 0;
}

struct cpu_info *
cpu_add_queue(int cpu, struct interface *iface, int queue)
{
	struct cpu_info *ci = cpu_nth(cpu);
	struct if_queue_info *qi = if_queue(iface, queue);

	if (add_queue(ci, qi) < 0)
		return NULL;
	return ci;
}

/* assign queue to CPU, select most idle CPU from a cpuset */
struct cpu_info *
cpu_add_queue_lru(struct interface *iface, int queue)
{
	const struct cpuset *set = iface->if_cpuset;
	struct cpu_info *ci = set->cs_cpu_lru_list->data;
	struct if_queue_info *qi = if_queue(iface, queue);

	if (add_queue(ci, qi) < 0)
		return NULL;
	return ci;
}

int
cpu_del_queue(int cpu, struct if_queue_info *qi)
{
	struct cpu_info *ci = cpu_nth(cpu);
	struct cpuset *set = ci->ci_cpuset;

	BUG_ON(!ci || ci->ci_num_queues == 0);
	ci->ci_queues = g_slist_remove(ci->ci_queues, qi);
	ci->ci_num_queues--;
	set->cs_cpu_lru_list = g_slist_sort(set->cs_cpu_lru_list, cpu_cmp);

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

		/* There could be missing cpu%d entries, e. g. in case of hotplug
		   or just broken CPUs */
		do {
			struct proc_stat_cpu psc_cpu;
			struct cpu_info *ci;

			if (getline(&line, &line_len, fp) == EOF)
				goto out;
			if (!strncmp(line, "intr ", sizeof("intr ") - 1))
				break;

			ret = sscanf(line, "cpu%d %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
						 &cpu,
						 &psc_cpu.psc_user, &psc_cpu.psc_nice,
						 &psc_cpu.psc_system, &psc_cpu.psc_idle,
						 &psc_cpu.psc_iowait, &psc_cpu.psc_irq,
						 &psc_cpu.psc_softirq, &psc_cpu.psc_steal,
						 &psc_cpu.psc_guest);
			BUG_ON(ret != 10);
			ci = cpu_nth(cpu);
			BUG_ON(!ci);
			memcpy(&ci->ci_psc, &psc_cpu, sizeof(psc_cpu));
		} while (1);

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

out:
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
cpu_load_cmp(gconstpointer __a, gconstpointer __b)
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
	unsigned long long frm_busy, frm_busy_old, frm_tot, frm_tot_old;

	frm_busy = psc->psc_user + psc->psc_nice + psc->psc_system
		+ psc->psc_iowait + psc->psc_irq + psc->psc_softirq
		+ psc->psc_steal + psc->psc_guest;
	frm_tot = frm_busy + psc->psc_idle;
	frm_busy_old = psco->psc_user + psco->psc_nice + psco->psc_system
		+ psco->psc_iowait + psco->psc_irq + psco->psc_softirq
		+ psco->psc_steal + psco->psc_guest;
	frm_tot_old = frm_busy_old + psco->psc_idle;
	if (frm_tot > frm_tot_old) {
		unsigned d = frm_tot - frm_tot_old;

		if (frm_busy > frm_busy_old)
			ci->ci_load = (frm_busy - frm_busy_old) * 100 / d;
		if (psc->psc_softirq > psco->psc_softirq)
			ci->ci_si_load = (psc->psc_softirq - psco->psc_softirq) * 100 / d;
	}

	cpu_load_lru_list = g_slist_remove(cpu_load_lru_list, ci);
	cpu_load_lru_list = g_slist_insert_sorted(cpu_load_lru_list,
											  ci, cpu_load_cmp);

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
	if (verbose > 1) {
		char buf[4096], *pch = buf, *end = buf + sizeof(buf);
		GSList *node;

		for (node = cpu_load_lru_list; node; node = g_slist_next(node)) {
			struct cpu_info *ci = node->data;

			pch += snprintf(pch, end - pch, "cpu%d=%u/%u",
							ci->ci_num, ci->ci_load, ci->ci_si_load);
			if (node->next)
				*pch++ = ' ';
		}
		log("LRU: %s", buf);
	}
#endif /* 0 */

	return 0;
}

void
cpu_dump_map(void)
{
	char path[PATH_MAX];
	FILE *fp;
	int cpu;

	/* do not use _PATH_VARDB, as on sles11 it points to /var/db,
	   which doesn't exist, */
	snprintf(path, sizeof(path), "/var/lib/misc/%s", CPU_MAP_FILE);
	if ((fp = fopen(path, "w")) == NULL) {
		err("%s: %m", CPU_MAP_FILE);
		return;
	}
	id_set_fd_flags(fileno(fp), O_CLOEXEC);

	for (cpu = 0; cpu < num_cpus; cpu++) {
		GSList *node;

		if (fprintf(fp, "cpu%d:", cpu) == EOF)
			goto out;

		for (node = cpus[cpu].ci_queues; node; node = node->next) {
			const struct if_queue_info *qi = node->data;

			if (fprintf(fp, " %s:%d", qi->qi_iface->if_name, qi->qi_num) == EOF)
				goto out;
		}

		if (fputc('\n', fp) == EOF)
			goto out;
	}

out:
	if (fclose(fp) == EOF)
		err("%s: %m", CPU_MAP_FILE);
}

struct cpu_bitmask *
cpu_bitmask_new(struct cpuset *set)
{
	struct cpu_bitmask *bmask;

	BUG_ON(!num_cpus);
	BUG_ON(!set);
	bmask = g_malloc0(sizeof(struct cpu_bitmask) + CPUSET_SIZE(num_cpus) / 8);
	if (bmask) {
		bmask->cpuset = set;
		bmask->len = CPUSET_SIZE(num_cpus) / 8;
	} else
		OOM();

	return bmask;
}

void
cpu_bitmask_free(struct cpu_bitmask *bmask)
{
	g_free(bmask);
}

/**
 * @return 1: set, 0: already set
 */
int
cpu_bitmask_set(struct cpu_bitmask *bmask, unsigned cpu)
{
	const struct cpuset *set = bmask->cpuset;
	const struct range *rg = &set->cs_range;
	int off = cpu / CPUSET_BITS, bit = cpu % CPUSET_BITS;

	BUG_ON(cpu < rg->rg_from || cpu > cpuset_last_cpu(set));
	BUG_ON(off >= bmask->len);
	if ((bmask->data[off] & (1 << bit)) == 0) {
		bmask->data[off] |= (1 << bit);
		bmask->nbits++;

		return 1;
	}

	return 0;
}

/**
 * @return 1: cleared, 0: already cleared
 */
int
cpu_bitmask_clear(struct cpu_bitmask *bmask, unsigned cpu)
{
	const struct cpuset *set = bmask->cpuset;
	const struct range *rg = &set->cs_range;
	int off = cpu / CPUSET_BITS, bit = cpu % CPUSET_BITS;

	BUG_ON(cpu < rg->rg_from || cpu > cpuset_last_cpu(set));
	BUG_ON(off >= bmask->len);
	if (bmask->data[off] & (1 << bit)) {
		bmask->data[off] &= ~(1 << bit);
		BUG_ON(bmask->nbits == 0);
		bmask->nbits--;

		return 1;
	}

	return 0;
}

bool
cpu_bitmask_is_set(const struct cpu_bitmask *bmask, unsigned cpu)
{
	const struct cpuset *set = bmask->cpuset;
	const struct range *rg = &set->cs_range;
	int off = cpu / CPUSET_BITS, bit = cpu % CPUSET_BITS;

	BUG_ON(cpu < rg->rg_from || cpu > cpuset_last_cpu(set));
	BUG_ON(off >= bmask->len);
	return (bmask->data[off] & (1 << bit)) != 0;
}

int
cpu_bitmask_ffs(const struct cpu_bitmask *bmask)
{
	int off;

	for (off = 0; off < bmask->len; off++) {
		if (bmask->data[off]) {
			int bit;

			for (bit = 0; bit < 8; bit++)
				if (bmask->data[off] & (1 << bit))
					return off * 8 + bit;
		}
	}

	return -1;
}

uint64_t
cpu_bitmask_mask64(const struct cpu_bitmask *bmask)
{
	uint64_t mask = 0ULL;
	size_t len;

#if 0
	{
		int cpu;

		for (cpu = 0; cpu < bmask->len * 8; cpu++)
			if (cpu_bitmask_is_set(bmask, cpu))
				mask |= (1LLU << cpu);
	}
#endif /* 0 */

	len = bmask->len > sizeof(uint64_t) ? sizeof(uint64_t) : bmask->len;
	memcpy(&mask, bmask->data, len);

	return mask;
}

struct range *
range_new(unsigned from, unsigned to)
{
	struct range *range;

	if ((range = g_malloc(sizeof(struct range))) == NULL)
		return NULL;
	range->rg_from = from;
	range->rg_to = to;

	return range;
}

void
range_free(struct range *range)
{
	free(range);
}

bool
range_valid(const struct range *range)
{
	return range->rg_from <= range->rg_to;
}

bool
cpu_in_range(const struct range *rg, unsigned cpu)
{
	return cpu >= rg->rg_from && cpu <= rg->rg_to;
}

bool
range_in_range(const struct range *rg, const struct range *subrg)
{
	return range_valid(subrg)
		&& subrg->rg_from >= rg->rg_from
		&& subrg->rg_to <= rg->rg_to;
}

struct cpuset *
cpuset_new(const char *name, const struct range *range)
{
	struct cpuset *set;
	int cpu;

	BUG_ON(!range);
	BUG_ON(!num_cpus);
	if (range->rg_from > range->rg_to
		|| range->rg_to > num_cpus) {
		dbg("cpuset: out of range (from %u, to %u)", range->rg_from,
			range->rg_to);
		return NULL;
	}

	if ((set = g_malloc0(sizeof(struct cpuset))) == NULL)
		return NULL;
	if ((set->cs_name = strdup(name)) == NULL) {
		cpuset_free(set);
		return NULL;
	}

	memcpy(&set->cs_range, range, sizeof(struct range));

	for (cpu = range->rg_from; cpu <= range->rg_to; cpu++) {
		set->cs_cpu_lru_list = g_slist_append(set->cs_cpu_lru_list, &cpus[cpu]);
		BUG_ON(cpus[cpu].ci_cpuset);
		cpus[cpu].ci_cpuset = set;
	}

	return set;
}

void
cpuset_free(struct cpuset *set)
{
	/* TODO cleanup dev_list */
	if (set)
		free(set);
}

void
cpuset_dump(void)
{
	GSList *node;

	for (node = cpuset_list; node; node = node->next) {
		const struct cpuset *set = node->data;
		const GSList *dev_node;

		printf("cpuset['%s']: cpus=%d-%d strategy='%s'\n",
			   set->cs_name, set->cs_range.rg_from, set->cs_range.rg_to,
			   set->cs_strategy.s_type->name);
		for (dev_node = set->cs_dev_list; dev_node; dev_node = dev_node->next) {
			struct interface *iface = dev_to_if(dev_node->data);

			printf("  %s\n", iface->if_name); 
		}
	}
}

int
cpuset_set_auto_assign(struct cpuset *set)
{
	if (g_cpuset_auto_assign)
		return -EEXIST;
	g_cpuset_auto_assign = set;
	
	return 0;
}

int
cpuset_set_strategy(struct cpuset *set, const char *name)
{
	const struct strategy_type *type = strategy_find_type(name);

	if (!type)
		return -EINVAL;
	set->cs_strategy.s_type = type;
	if (set->cs_strategy.s_type->init != NULL)
		set->cs_strategy.s_type->init(&set->cs_strategy);
	
	return 0;
}

static bool
cpuset_has_device(const struct cpuset *set, const struct device *dev)
{
	const GSList *node;

	for (node = set->cs_dev_list; node; node = node->next)
		if (node->data == dev)
			return true;

	return false;
}

int
cpuset_add_device(struct cpuset *set, struct device *dev)
{
	BUG_ON(dev->type == DEV_INVAL);
	if (cpuset_has_device(set, dev))
		return -EBUSY;
	set->cs_dev_list = g_slist_append(set->cs_dev_list, dev);
	dbg("%s: added device %p (type %d)", __func__, dev, dev->type);

	return 0;
}

GSList *
cpuset_get_by_name(const char *name)
{
	GSList *node;

	for (node = cpuset_list; node; node = g_slist_next(node)) {
		struct cpuset *set = node->data;

		if (!strcmp(set->cs_name, name))
			return node;
	}

	return NULL;
}

bool
cpuset_in(const struct cpuset *set, unsigned n)
{
	return cpu_in_range(&set->cs_range, n);
}

int
cpuset_list_add(struct cpuset *new)
{
	GSList *node;

	if ((node = cpuset_get_by_name("default")) != NULL) {
		struct cpuset *set = node->data;

		cpuset_list = g_slist_delete_link(cpuset_list, node);
		cpuset_free(set);
	}

	for (node = cpuset_list; node; node = g_slist_next(node)) {
		const struct cpuset *set = node->data;

		if (!strcmp(set->cs_name, new->cs_name))
			return -EBUSY;
		if (cpuset_in(set, new->cs_range.rg_from)
			|| cpuset_in(set, cpuset_last_cpu(new)))
			return -EINVAL;
	}

	cpuset_list = g_slist_append(cpuset_list, new);

	return 0;
}

int
cpuset_interface_down(struct cpuset *set, struct interface *iface)
{
	if (set->cs_strategy.s_type->interface_down)
		return set->cs_strategy.s_type->interface_down(iface);

	return 0;
}

int
cpuset_cpu_busy(struct cpuset *set, struct cpu_info *ci)
{
	if (set->cs_strategy.s_type->cpu_busy)
		return set->cs_strategy.s_type->cpu_busy(ci);

	return 0;
}

/**
 * cpuset_balance_queue() - actually assign queue to CPUs
 *
 * A fixed CPU range of CPUs takes precedence over other the strategy.
 * If no fixed CPU range is specified the strategy handler is
 * consulted.
 */
int
cpuset_balance_queue(struct cpuset *set, struct interface *iface, int queue)
{
	struct if_queue_info *qi = if_queue(iface, queue);
	uint64_t cpumask;

	/* a fixed range takes precedence over the balance strategy being
	   used */
	if (iface->if_fixed_range != NULL) {
		const struct range *range = iface->if_fixed_range;
		int cpu;

		for (cpu = range->rg_from; cpu <= range->rg_to; cpu++) {
			if (!cpu_bitmask_set(qi->qi_cpu_bitmask, cpu))
				BUG();
			if (cpu_add_queue(cpu, iface, queue) < 0)
				return -1;
		}
	} else {
		if (set->cs_strategy.s_type->balance_queue(iface, queue) < 0)
			return -1;
	}

	BUG_ON(cpu_bitmask_ncpus(qi->qi_cpu_bitmask) == 0);

	cpumask = cpu_bitmask_mask64(qi->qi_cpu_bitmask);
	if (g_rps_status == RPS_S_ENABLED || g_xps_status == XPS_S_ENABLED)
		if_set_steering_cpus(iface, queue, cpumask, cpumask);

	queue_set_affinity(qi, cpumask);

	log("%s:%d: affinity irq=%#" PRIx64 " rps/xps=%#" PRIx64,
		iface->if_name, queue, cpumask, cpumask);

	return 0;
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

	for (cpu = 0; cpu < num_cpus; cpu++)
		cpus[cpu].ci_num = cpu;

	return 0;
}
