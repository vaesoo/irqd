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
#ifndef INTERFACE_H
#define INTERFACE_H

#include <sys/socket.h>
#include <linux/if.h>

#include "device.h"

struct interface;
struct cpu_bitmask;
struct cpuset;

typedef unsigned irq_ctr_t;

/*
 * There are different scenarios possible.  The easiest one is 1) a single
 * IRQ used for Link Status Control, RX and TX:
 *
 *  46:     208685     202268     220905     215620   PCI-MSI-edge      eth0
 *
 * There are some NICs with a dedicated LSC IRQ:
 *
 *  60:          0          1   PCI-MSI-edge      eth3
 *  61:          0          0   PCI-MSI-edge      eth3-rxtx-0
 *
 * And of course different IRQs used for LSC, RX and TX:
 *
 *  51:   12187473   14354377   PCI-MSI-edge      eth0-rx-0
 *  52:      96883     106078   PCI-MSI-edge      eth0-tx-0
 *  53:        292        131   PCI-MSI-edge      eth0
 *
 * 
 */
struct if_queue_info {
	unsigned qi_num;
	int qi_rx_irq;
	int qi_tx_irq;
	struct interface *qi_iface;
	struct cpu_bitmask *qi_cpu_bitmask;	/* both IRQ and RPS affinity */
	irq_ctr_t qi_irq_stats[2][CPU_MAX];
};

struct interface {
	/* must come first */
	struct device if_dev;

#define IF_F_SHARED_IRQ			0x0001
	unsigned if_flags;

	int if_irq;					/* possibly just LSC */

	struct if_queue_info *if_queues;
	unsigned if_num_queues;

	/* the CPUs we are allowed to run on */
	struct cpuset *if_cpuset;

	/* range specifying a subset of CPUs to be used */
	struct range *if_fixed_range;

	/* Linux net_device_stats */
	struct if_net_device_stats {
		uint64_t rx_bytes;		/* total bytes received */
		uint64_t rx_packets;	/* total packets received */
		uint64_t rx_errors;		/* bad packets received */
		uint64_t rx_dropped;	/* no space in linux buffers */
		uint64_t rx_fifo_errors;
		uint64_t rx_frame_errors;
		uint64_t rx_compressed;
		uint64_t rx_mcast;

		uint64_t tx_bytes;
		uint64_t tx_packets;
		uint64_t tx_errors;
		uint64_t tx_dropped;
		uint64_t tx_fifo_errors;
		uint64_t tx_collisions;
		uint64_t tx_carrier_errors;
		uint64_t tx_compressed;
	} if_stats[2];

	char if_name[IFNAMSIZ];
};

struct interface *if_new(const char *, struct cpuset *);
void if_free(struct interface *);
int if_register(struct interface *);

static inline struct device *
if_to_dev(struct interface *iface)
{
	return &iface->if_dev;
}

static inline struct interface *
dev_to_if(struct device *dev)
{
	BUG_ON(dev->type != DEV_INTERFACE);
	return (struct interface *)dev;
}

struct if_queue_info *if_queue(const struct interface *, int);
struct if_queue_info *if_queue_by_name(const char *, int);
int if_queue_assign_range(struct if_queue_info *, const struct range *);

int if_assign_fixed_range(struct interface *, const struct range *);

static inline bool
if_is_multiqueue(struct interface *iface)
{
	BUG_ON(!iface->if_num_queues);

	return iface->if_num_queues > 1;
}

int if_init(void);
int if_rtnl_init(void);
void if_fini(void);
bool if_can_rps(const struct interface *);
bool if_can_xps(const struct interface *);
int if_set_steering_cpus(const struct interface *, int, uint64_t, uint64_t);
int if_get_queue_stat(struct if_queue_info *);

int queue_set_affinity(const struct if_queue_info *, uint64_t);

#endif /* INTERFACE_H */
