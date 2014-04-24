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

/* up to 4 CPUs mapped per queue */
#define RPS_CPU_MAX_ORDER	2
#define RPS_CPU_MAX			(1 << RPS_CPU_MAX_ORDER)

/* Softirq load threshold (percent) up to which new queues are mapped
   to a Softirq */
#define CPU_SI_MAP_THRESH		50

static void cpu_dump_queues(const struct cpu_info *) __UNUSED;
static void cpuset_dump_lru(const char *, const struct cpuset *) __UNUSED;

static bool
cpu_is_idle(const struct cpu_info *ci)
{
	return ci->ci_si_load < CPU_SI_MAP_THRESH;
}

/* maps up to four CPUs for a queue, making sure that the selected
   CPU is in the cpuset */
static struct cpu_info *
rps_select_nearby_cpu(const struct if_queue_info *qi, int cpu)
{
	const struct cpuset *set = qi->qi_iface->if_cpuset;
	int order;

	for (order = 1; order < RPS_CPU_MAX_ORDER; order++) {
		unsigned order_ncpus = 1 << order;
		int order_base, probe;

		order_base = (cpu - set->cs_range.rg_from) / order_ncpus * order_ncpus;
		for (probe = 0; probe < order_ncpus; probe++) {
			unsigned c = set->cs_range.rg_from + order_base + probe;

			if (cpuset_in(set, c)
				&& !cpu_bitmask_is_set(qi->qi_cpu_bitmask, c)) {
				struct cpu_info *new = cpu_nth(c);

				if (!new)
					continue;
				if (cpu_is_idle(new))
					return new;
			}
		}
	}

	return NULL;
}

/*
 * For multiqueue we assign the queues consecutively, with the first
 * being assigned by LRU.
 */
static struct cpu_info *
assign_mq_queue(struct interface *iface, int queue)
{
	const struct cpuset *cset = iface->if_cpuset;
	const struct if_queue_info *qi_first = if_queue(iface, 0);
	int cpu, first_used = cpu_bitmask_ffs(qi_first->qi_cpu_bitmask);

	BUG_ON(first_used < 0);
	cpu = cpuset_first_cpu(cset) + (first_used + queue) % cpuset_len(cset);

	return cpu_add_queue(cpu, iface, queue);
}

static void
check_cpuset_lru(const struct cpuset *set)
{
	GSList *node;
	int min = INT_MAX, max = 0;

	for (node = set->cs_cpu_lru_list; node; node = node->next) {
		const struct cpu_info *ci = node->data;

		if (min > ci->ci_num_queues)
			min = ci->ci_num_queues;
		if (max < ci->ci_num_queues)
			max = ci->ci_num_queues;
	}

	if (max - min > 1)
		err("uneven distribution detected for '%s'", set->cs_name);
}

static int
evenly_balance_queue(struct interface *iface, int queue)
{
	struct if_queue_info *qi;
	struct cpu_info *ci;

	BUG_ON(queue < 0);

	if (queue == 0)
		ci = cpu_add_queue_lru(iface, queue);
	else
		ci = assign_mq_queue(iface, queue);
	if (ci == NULL)
		return -1;

	qi = if_queue(iface, queue);
	if (!cpu_bitmask_set(qi->qi_cpu_bitmask, ci->ci_num))
		BUG();

	if (!if_is_multiqueue(iface) && g_rps_status == RPS_S_ENABLED) {
		int ncpus = iface->if_cpuset->cs_strategy.u.evenly.init_steer_cpus;
		int cpu;

		for (cpu = 1; cpu < ncpus; cpu++) {
			struct cpu_info *ci2 = rps_select_nearby_cpu(qi, ci->ci_num);

			if (ci2) {
				if (cpu_bitmask_set(qi->qi_cpu_bitmask, ci2->ci_num))
					cpu_add_queue(ci2->ci_num, iface, queue);
			}
		}
	}

	check_cpuset_lru(ci->ci_cpuset);

	return 0;
}

static gint
queue_irq_cmp(gconstpointer __a, gconstpointer __b, gpointer data)
{
	const struct cpu_info *ci = data;
	const struct if_queue_info *qia = __a, *qib = __b;

	return qia->qi_irq_stats[NEW][ci->ci_num]
		- qib->qi_irq_stats[NEW][ci->ci_num];
}

/**
 * queue_map_cpu - try to map queue to another CPU
 *
 * Nearby CPUs preferred, in the hope of caching effects.
 *
 * @return 1: mapped, 0: not mapped, <0: error
 */
static int
queue_map_cpu(struct if_queue_info *qi)
{
	struct interface *iface = qi->qi_iface;
	struct cpu_info *ci_new;
	int cpu = cpu_bitmask_ffs(qi->qi_cpu_bitmask);
	uint64_t cpumask;

	BUG_ON(iface->if_num_queues > 1);
	if ((ci_new = rps_select_nearby_cpu(qi, cpu)) == NULL)
		return 0;

	if (cpu_bitmask_set(qi->qi_cpu_bitmask, ci_new->ci_num))
		cpu_add_queue(ci_new->ci_num, iface, qi->qi_num);

	cpumask = cpu_bitmask_mask64(qi->qi_cpu_bitmask);
	if_set_steering_cpus(iface, qi->qi_num, cpumask, cpumask);

	queue_set_affinity(qi, cpumask);

	log("%s:%d: rps_cpus=%#" PRIx64 " smp_affinity=%#" PRIx64,
		iface->if_name, qi->qi_num, cpumask, cpumask);

	return 1;
}

static void
evenly_init(struct strategy *strategy)
{
	strategy->u.evenly.init_steer_cpus = 2;
}

static int
evenly_cpu_busy(struct cpu_info *ci)
{
	struct if_queue_info *qi;
	GList *queue_irqs_list = NULL;
	GList *node;
	GSList *snode;

	if (!ci->ci_num_queues) {
		/* TODO softirq busy, but no NICs assigned, search for other
		   devices */
		return 0;
	}

	/* One or many queues mapped, search for the busiest queue
	   (in terms of IRQs handled).  NAPI may reduce accuracy though,
	   as well as shared IRQs. */
	for (snode = ci->ci_queues; snode; snode = snode->next) {
		qi = snode->data;
		queue_irqs_list = g_list_insert_sorted_with_data(queue_irqs_list, qi,
														 queue_irq_cmp, ci);
	}

	/* for multiqueue NICs simply assume enough queues */
	node = g_list_last(queue_irqs_list);
	for (; node; node = g_list_previous(node)) {
		qi = node->data;
		if (qi->qi_iface->if_num_queues == 1)
			break;
	}

	if (!node) {
		err("cpu%d: no singlequeue NIC found to map", ci->ci_num);
		goto done;
	}
		
	if (queue_map_cpu(qi) != 1) {
		/* TODO move queue completely */
	}

done:
	g_list_free(queue_irqs_list);

	return 0;
}

static void
cpu_dump_queues(const struct cpu_info *ci)
{
	GSList *node;

	printf("cpu[%d]: q#=%u ", ci->ci_num, ci->ci_num_queues);

	for (node = ci->ci_queues; node != NULL; node = node->next) {
		const struct if_queue_info *qi = node->data;
		const struct interface *iface = qi->qi_iface;

		printf("%s:%d ", iface->if_name, qi->qi_num);
	}
	putchar('\n');
}

static void
cpuset_dump_lru(const char *prefix, const struct cpuset *set)
{
	GSList *node;

	puts(prefix);
	for (node = set->cs_cpu_lru_list; node != NULL; node = node->next) {
		const struct cpu_info *ci = node->data;

		cpu_dump_queues(ci);
	}
}

/*
 * Which IRQ to remove from most busy CPU?  Can be a difficult decision.
 *
 * For now we just choose last IRQ in list.  We determine the interface
 * it is part of, then remove it completely from the configuration.
 * Afterwards we add it to the configuration again.
 *
 * By reconfiguring all interface queues we make sure that configuration
 * is same compared to device having appeared for the first time, and
 * also avoid any issues with multiqueue NICs (e. g. two MQ queues
 * assigned to same CPU).
 *
 * We repeat this process until imbalance is solved.
 */
static int
evenly_interface_down(struct cpuset *set, struct interface *iface_down)
{
	if (set->cs_cpu_lru_list == NULL)
		return 0;

	do {
		struct cpu_info *ci_first, *ci_last;
		const struct if_queue_info *qi;
		struct interface *iface;
		int minq, maxq;

		ci_first = set->cs_cpu_lru_list->data;
		minq = ci_first->ci_num_queues;
		ci_last = g_slist_last(set->cs_cpu_lru_list)->data;
		maxq = ci_last->ci_num_queues;
		if (maxq - minq < 2)
			break;

		qi = g_slist_last(ci_last->ci_queues)->data;
		iface = qi->qi_iface;
		if_remove_cpus(iface);

		log("%s: rebalancing interface (%d queue(s))", iface->if_name,
			iface->if_num_queues);
		if (if_assign_cpus(iface) < 0)
			break;
	} while (1);

	return 0;
}

struct strategy_type evenly_strategy_type = {
	.name = "evenly",
	.init = evenly_init,
	.balance_queue = evenly_balance_queue,
	.cpu_busy = evenly_cpu_busy,
	.interface_down = evenly_interface_down,
};
