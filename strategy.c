/*
 * strategy.c
 *
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
 * Holger Eitzenberger <heitzenberger@astaro.com>, 2011.
 */
#define DEBUG
#include "irqd.h"
#include "cpu.h"
#include "interface.h"

/* up to 4 CPUs mapped per queue */
#define CPU_MAX_ORDER	2

/* Softirq load threshold (percent) up to which new queues are mapped
   to a Softirq */
#define CPU_SI_MAP_THRESH		50

static bool
cpu_is_idle(const struct cpu_info *ci)
{
	return ci->ci_si_load < CPU_SI_MAP_THRESH;
}

static struct cpu_info *
select_nearby_cpu(const struct if_queue_info *qi, int cpu)
{
	int order;

	if (cpuset_ncpus(qi->qi_cpuset) >= (1 << CPU_MAX_ORDER))
		return NULL;

	for (order = 1; order < CPU_MAX_ORDER; order++) {
		unsigned cpus = 1 << order;
		int probe, base = cpu / cpus * cpus;

		for (probe = 0; probe < cpus; probe++) {
			if (!cpuset_is_set(qi->qi_cpuset, base + probe)) {
				struct cpu_info *new = cpu_nth(base + probe);

				if (!new)
					return NULL;
				if (cpu_is_idle(new))
					return new;
			}
		}
	}

	return NULL;
}

static int
evenly_balance_queue(struct interface *iface, int queue)
{
	return 0;
}

static int
evenly_balance_queue_rps(struct interface *iface, int queue)
{
	struct if_queue_info *qi;
	struct cpu_info *ci;
	uint64_t cpumask;

	if ((ci = cpu_add_queue_lru(iface, queue)) == NULL)
		return -1;

	qi = if_queue(iface, queue);
	if (!cpuset_set(qi->qi_cpuset, ci->ci_num))
		BUG();

	if (iface->if_num_queues == 1) {
		struct cpu_info *ci2 = select_nearby_cpu(qi, ci->ci_num);

		if (ci2) {
			if (cpuset_set(qi->qi_cpuset, ci2->ci_num))
				cpu_add_queue(ci2->ci_num, iface, queue);
		}
	}

	cpumask = cpuset_mask64(qi->qi_cpuset);
	if_set_rps_cpus(iface, queue, cpumask);
	irq_set_affinity(qi->qi_irq, cpumask);

	log("%s:%d: rps_cpus=%#" PRIx64 " smp_affinity=%#" PRIx64,
		iface->if_name, queue, cpumask, cpumask);

	return 0;
}

static gint
queue_irq_cmp(gconstpointer __a, gconstpointer __b, gpointer data)
{
	const struct cpu_info *ci = data;
	const struct if_queue_info *qia = __a, *qib = __b;

	return qia->qi_irqs[NEW][ci->ci_num] - qib->qi_irqs[NEW][ci->ci_num];
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
	int cpu = cpuset_ffs(qi->qi_cpuset);
	uint64_t cpumask;

	BUG_ON(iface->if_num_queues > 1);
	if (cpuset_ncpus(qi->qi_cpuset) >= (1 << CPU_MAX_ORDER))
		return 0;
	
	if ((ci_new = select_nearby_cpu(qi, cpu)) == NULL) {
		if (!cpu_lru_list || (ci_new = cpu_lru_list->data) == NULL)
			return 0;
		if (!cpu_is_idle(ci_new))
			return 0;
	}

	if (cpuset_set(qi->qi_cpuset, ci_new->ci_num))
		cpu_add_queue(ci_new->ci_num, iface, qi->qi_num);

	cpumask = cpuset_mask64(qi->qi_cpuset);
	if_set_rps_cpus(iface, qi->qi_num, cpumask);
	irq_set_affinity(qi->qi_irq, cpumask);

	log("%s:%d: rps_cpus=%#" PRIx64 " smp_affinity=%#" PRIx64,
		iface->if_name, qi->qi_num, cpumask, cpumask);

	return 1;
}

static int
evenly_softirq_busy(struct cpu_info *ci)
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

static int
evenly_interface_down(struct interface *iface)
{
	return 0;
}

const struct balance_strategy bs_evenly = {
	.name = "evenly",
	.balance_queue = evenly_balance_queue,
	.balance_queue_rps = evenly_balance_queue_rps,
	.softirq_busy = evenly_softirq_busy,
	.interface_down = evenly_interface_down,
};
