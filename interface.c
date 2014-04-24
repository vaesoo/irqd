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
#include "cpu.h"
#include "interface.h"

#include <sys/timerfd.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>

#define IRQ_INFO_CHIP_NAME_LEN	32
#define IRQ_INFO_ACTION_LEN		64

enum ProcIrqAction {
	PIA_NoMatch = 0,
	PIA_LSC,					/* Link Control Status */
	PIA_Rx,
	PIA_Tx,
	PIA_RxTx,
};

struct irq_info {
	unsigned ii_irq;
	char ii_chip_name[IRQ_INFO_CHIP_NAME_LEN];
	irq_ctr_t ii_handled[CPU_MAX];
	char ii_action[IRQ_INFO_ACTION_LEN];
};

#define REBALANCE_IVAL			5

/* threshold (in percent) of the softirq load, from which on
   a rebalance of some queues to a different CPU is scheduled */
#define REBALANCE_SI_THRESH		70

static struct nl_sock *nlh;
static struct nl_cache *nlcache;
static struct nl_cache_mngr *mngr;
static struct ev nl_ev;
static struct ev rebalance_ev;
static GHashTable *if_hash;

static struct cpuset *if_assign_cpuset_by_name(struct interface *,
											   const char *) __UNUSED;

struct interface *
if_new(const char *dev, struct cpuset *set)
{
	struct interface *iface;

	if ((iface = g_new0(struct interface, 1)) == NULL) {
		OOM();
		return NULL;
	}

	device_init(&iface->if_dev, DEV_INTERFACE);

	iface->if_cpuset = set;
	strncpy(iface->if_name, dev, IFNAMSIZ);
	iface->if_queues = g_new0(struct if_queue_info, QUEUE_MAX);
	if (!iface->if_queues) {
		g_free(iface);
		iface = NULL;
	}

	dbg("new interface '%s' (%p)", dev, iface);

	return iface;
}

void
if_free(struct interface *iface)
{
	if (iface) {
		int queue;

		dbg("free interface %p", iface);
		for (queue = 0; queue < iface->if_num_queues; queue++)
			BUG_ON(!cpu_bitmask_is_empty(if_queue(iface, queue)->qi_cpu_bitmask));
		g_free(iface->if_queues);
		g_free(iface);
	}
}

int
if_register(struct interface *iface)
{
	BUG_ON(g_hash_table_lookup(if_hash, iface->if_name));
	g_hash_table_insert(if_hash, strdup(iface->if_name), iface);
	dbg("registered interface '%s'", iface->if_name);

	return 0;
}

static void
if_assign_cpuset(struct interface *iface, struct cpuset *set)
{
	BUG_ON(iface->if_cpuset);
	iface->if_cpuset = set;
}

static struct cpuset *
if_assign_cpuset_by_name(struct interface *iface, const char *name)
{
	GSList *node;

	for (node = cpuset_list; node; node = node->next) {
		struct cpuset *set = node->data;

		if (!strcmp(set->cs_name, name)) {
			if_assign_cpuset(iface, set);
			return set;
		}
	}

	return NULL;
}

struct if_queue_info *
if_queue(const struct interface *iface, int queue)
{
	BUG_ON(queue < 0 || queue >= QUEUE_MAX);
	return &iface->if_queues[queue];
}

struct if_queue_info *
if_queue_by_name(const char *dev, int queue)
{
	const struct interface *iface;

	if ((iface = g_hash_table_lookup(if_hash, dev)) == NULL)
		return NULL;

	return if_queue(iface, queue);
}

/**
 * if_queue_assign_range() - assign CPUs in range to queue
 *
 * Low-level function to assign CPUs to an interface queue.
 */
int
if_queue_assign_range(struct if_queue_info *qi, const struct range *range)
{
	int cpu;

	for (cpu = range->rg_from; cpu <= range->rg_to; cpu++) {
		if (!cpu_bitmask_set(qi->qi_cpu_bitmask, cpu))
			BUG();
		if (cpu_add_queue(cpu, qi->qi_iface, qi->qi_num) < 0)
			return -1;
	}

	return 0;
}

/*
 * if_assign_fixed_range() - assign an unchangeable subrange
 *
 * Intended use-case is for single-queue NICs, but all queues
 * are pinned if there are multiple queues.
 *
 * The actual pinning happens at the time the interface comes
 * up.
 */
int
if_assign_fixed_range(struct interface *iface, const struct range *range)
{
	struct cpuset *set = iface->if_cpuset;

	BUG_ON(set == NULL);
	if (!range_in_range(&set->cs_range, range)) {
		dbg("range [%u,%u] within '%s' cpuset is invalid",
			range->rg_from, range->rg_to, set->cs_name);
		return -EINVAL;
	}

	BUG_ON(iface->if_fixed_range);
	iface->if_fixed_range = range_new(range->rg_from, range->rg_to);
	if (!iface->if_fixed_range)
		return -ENOMEM;

	return 0;
}

bool
if_can_rps(const struct interface *iface)
{
	char path[PATH_MAX], *fmt;
	struct stat st;

	fmt = id_path("/sys/class/net/%s/queues/rx-0/rps_cpus");
	snprintf(path, sizeof(path), fmt, iface->if_name);
	g_free(fmt);
	if (stat(path, &st) < 0)
		return false;

	return true;
}

bool
if_can_xps(const struct interface *iface)
{
	char path[PATH_MAX], *fmt;
	struct stat st;

	fmt = id_path("/sys/class/net/%s/queues/tx-0/xps_cpus");
	snprintf(path, sizeof(path), fmt, iface->if_name);
	g_free(fmt);
	if (stat(path, &st) < 0)
		return false;

	return true;
}

static enum EvReturn
rtnl_io_cb(struct ev *ev, unsigned short what)
{
	switch (what) {
	case EV_READ:
		nl_cache_mngr_data_ready(mngr);
		break;
		
	default:
		BUG();
	}

	return 0;
}

static int
write_u64_mask(const char *file, uint64_t mask)
{
	char buf[32];
	int fd, len, nwritten;

	if ((fd = open(file, O_WRONLY | O_CLOEXEC)) < 0) {
		err("%s: %m", file);
		return -1;
	}

	len = snprintf(buf, sizeof(buf), "%" PRIx64, mask);
	nwritten = write(fd, buf, len);
	BUG_ON(nwritten != len);

	close(fd);

	return 0;
}

int
if_set_steering_cpus(const struct interface *iface, int queue,
					 uint64_t rps_mask, uint64_t xps_mask)
{
	char path[PATH_MAX];

	if (g_rps_status == RPS_S_ENABLED) {
		snprintf(path, sizeof(path), "/sys/class/net/%s/queues/rx-%d/rps_cpus",
				 iface->if_name, queue);
		write_u64_mask(path, rps_mask);
	}

	if (g_xps_status == XPS_S_ENABLED) {
		snprintf(path, sizeof(path), "/sys/class/net/%s/queues/tx-%d/xps_cpus",
				 iface->if_name, queue);
		write_u64_mask(path, xps_mask);
	}

	return 0;
}

static enum ProcIrqAction
parse_iface_irq_action_tail(const char *tail, int *queue)
{
	if (*tail == '\0')
		return PIA_LSC;

	if (sscanf(tail, "-TxRx-%u", queue) == 1)
		return PIA_RxTx;
	/* some Intel e1000e */
	if (sscanf(tail, "-rxtx-%u", queue) == 1)
		return PIA_RxTx;

	/* Broadcom NICs (netxen, bnx2) */
	if (sscanf(tail, "[%u]", queue) == 1)
		return PIA_RxTx;
	/* Broadcom bnx2 */
	if (sscanf(tail, "-%u", queue) == 1)
		return PIA_RxTx;

	/* Intel igb driver */
	if (sscanf(tail, "-rx-%u", queue) == 1)
		return PIA_Rx;
	if (sscanf(tail, "-tx-%u", queue) == 1)
		return PIA_Tx;

	/* Qualcomm Atheros (alx) */
	if (sscanf(tail, "-TR-%u", queue) == 1)
		return PIA_RxTx;

	return PIA_NoMatch;
}

static enum ProcIrqAction
parse_iface_irq_action(struct interface *iface, const char *action,
					   int *queue)
{
	const int len = strlen(iface->if_name);

	if (strncmp(iface->if_name, action, len))
		return PIA_NoMatch;

	*queue = 0;

	return parse_iface_irq_action_tail(action + len, queue);
}

static struct if_queue_info *
if_add_queue(struct interface *iface, int queue, int rx_irq, int tx_irq)
{
	struct if_queue_info *qi = if_queue(iface, queue);

	if (!qi->qi_cpu_bitmask) {
		struct cpuset *set = iface->if_cpuset;

		if ((qi->qi_cpu_bitmask = cpu_bitmask_new(set)) == NULL)
			return NULL;
	}
	qi->qi_num = queue;
	qi->qi_iface = iface;
	if (rx_irq > 0)
		qi->qi_rx_irq = rx_irq;
	if (tx_irq > 0)
		qi->qi_tx_irq = tx_irq;

	iface->if_num_queues = max(iface->if_num_queues, queue + 1);

	return qi;
}

/**
 * queues_from_interrupts() - parse /proc/interrupts for for NIC
 *
 * See documentation for if_queue_info for the different cases
 * to consider.
 *
 * @return 0: ok, -1 on error
 */
static int
queues_from_interrupts(struct interface *iface, size_t qi_len)
{
	FILE *fp;
	char *line = NULL;
	size_t line_len;
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int lineno = 0;

	BUG_ON(g_rps_status == RPS_S_NEED_CHECK);
	iface->if_num_queues = 0;

	if ((fp = id_fopen("/proc/interrupts", "r")) == NULL)
		goto err_free;

	getline(&line, &line_len, fp);
	lineno++;
next_line:
	while (!feof(fp)) {
		struct if_queue_info *qi = NULL;
		char *pch, *tok, *end, *saveptr;
		int i, irq, devs = 0;
		enum ProcIrqAction pia;

		if (getline(&line, &line_len, fp) == EOF)
			break;
		lineno++;
		pch = g_strstrip(line);

		tok = strtok_r(pch, " \t", &saveptr);
		irq = strtoul(tok, &end, 0);
		if (*end != ':')
			continue;			/* not an IRQ line */
		if ((pch = strstr(saveptr, iface->if_name)) == NULL)
			continue;			/* not a NIC IRQ line */
			
		for (i = 0; i < num_cpus; i++)
			if ((tok = strtok_r(NULL, " \t", &saveptr)) == NULL)
				goto next_line;

		/* chip */
		if ((tok = strtok_r(NULL, " \t", &saveptr)) == NULL)
			continue;
		
		/* action */
		do {
			int queue = 0;

			if ((tok = strtok_r(NULL, " \t,", &saveptr)) == NULL)
				break;

			pia = parse_iface_irq_action(iface, tok, &queue);
			switch (pia) {
			case PIA_LSC:
				/* this may not be just LSC if both rx_irq and tx_irq
				   are zero */
				iface->if_irq = irq;
				qi = if_add_queue(iface, queue, -1, -1);
				break;

			case PIA_Rx:
				qi = if_add_queue(iface, queue, irq, -1);
				break;

			case PIA_Tx:
				qi = if_add_queue(iface, queue, -1, irq);
				break;

			case PIA_RxTx:
				qi = if_add_queue(iface, queue, irq, irq);
				break;

			case PIA_NoMatch:
				log("interrupts: failed to parse '%s'.  Please report.", tok);
				qi = NULL;
				break;
			}

			devs++;
		} while (1);

		if (pia == PIA_LSC && devs > 1)
			iface->if_flags |= IF_F_SHARED_IRQ;

		if (qi && verbose > 1)
			log("%s: irqs: LSC=%d RX=%d TX=%d\n", iface->if_name,
				iface->if_irq, qi->qi_rx_irq, qi->qi_tx_irq);
	}

	free(line);
	/* if (ferror(fp)) ... */
	fclose(fp);

	return 0;

err_free:
	g_free(line);
	if (fp)
		fclose(fp);

	return -1;
}

int
queue_set_affinity(const struct if_queue_info *qi, uint64_t cpumask)
{
	const struct interface *iface = qi->qi_iface;

	if (qi->qi_rx_irq > 0) {
		irq_set_affinity(qi->qi_rx_irq, cpumask);

		if (qi->qi_tx_irq > 0 && qi->qi_tx_irq != qi->qi_rx_irq)
			irq_set_affinity(qi->qi_tx_irq, cpumask);
	}

	/* virtual interfaces (lo, tun, ...) don't have an IRQ */
	if (iface->if_irq > 0)
		irq_set_affinity(iface->if_irq, cpumask);

	return 0;
}

static int
if_on_up(struct interface *iface, const char *dev)
{
	int i;

	if (g_rps_status == RPS_S_NEED_CHECK) {
		g_rps_status = if_can_rps(iface) ? RPS_S_ENABLED : RPS_S_DISABLED;
		g_xps_status = if_can_xps(iface) ? XPS_S_ENABLED : XPS_S_DISABLED;

		log("RPS %s, XPS %s",
			g_rps_status == RPS_S_ENABLED ? "enabled" : "disabled",
			g_xps_status == XPS_S_ENABLED ? "enabled" : "disabled");
	}

	if (queues_from_interrupts(iface, QUEUE_MAX) < 0) 
		return -1;
	if (iface->if_num_queues == 0)
		if_add_queue(iface, 0, -1, -1); /* lo, tun, etc. */
	log("%s: detected %d queue(s), '%s' cpuset", iface->if_name,
		iface->if_num_queues, iface->if_cpuset->cs_name);

	for (i = 0; i < iface->if_num_queues; i++)
		cpuset_balance_queue(iface->if_cpuset, iface, i);

	log("%s: up", iface->if_name);

	return 0;
}

static int
if_on_down(struct interface *iface, const char *dev)
{
	struct cpuset *set = iface->if_cpuset;
	int queue;

	cpuset_interface_down(set, iface);

	for (queue = 0; queue < iface->if_num_queues; queue++) {
		struct if_queue_info *qi = if_queue(iface, queue);
		int cpu;

		for (cpu = set->cs_range.rg_from; cpu <= cpuset_last_cpu(set); cpu++)
			if (cpu_bitmask_clear(qi->qi_cpu_bitmask, cpu))
				cpu_del_queue(cpu, qi);
	}

	log("%s: down", iface->if_name);

	return 0;
}

static int
rtnl_balance_link(struct rtnl_link *lnk)
{
	struct interface *iface;
	const char *dev;
	int flags;
	bool change = false;

	if ((dev = rtnl_link_get_name(lnk)) == NULL)
		return 0;

	if ((iface = g_hash_table_lookup(if_hash, dev)) == NULL) {
		if (g_cpuset_auto_assign) {
			if ((iface = if_new(dev, g_cpuset_auto_assign)) == NULL)
				return -1;
			cpuset_add_device(g_cpuset_auto_assign, if_to_dev(iface));
			if_register(iface);
		} else {
			log("%s: ignored by configuration", dev);
			return 0;
		}
	}

	flags = rtnl_link_get_flags(lnk);
	if ((iface->if_flags & IFF_UP) == 0 && (flags & IFF_UP)) {
		if (if_on_up(iface, dev) < 0)
			goto err;
		change = true;
	} else if ((iface->if_flags & IFF_UP) && (flags & IFF_UP) == 0) {
		if (if_on_down(iface, dev) < 0)
			goto err;
		change = true;
	}

	iface->if_flags = flags;

	if (change)
		cpu_dump_map();

	return 0;

err:
	return -1;
}

/**
 * @return 1: IRQ line, 0: no IRQ line, <1 on error
 */
static int
read_irq_info(char *line, struct irq_info *ii)
{
	char *pch, *tok, *end, *saveptr;
	int cpu;

	pch = g_strstrip(line);

	/*
	 * EXAMPLES
	 *
	 *   11:  24  XT-PIC-XT  eth2, eth7
	 *   46:  2  0  2  0  0 0  2 2  PCI-MSI-edge  eth11-TxRx-1
	 */
	tok = strtok_r(pch, " \t", &saveptr);
	ii->ii_irq = strtoul(tok, &end, 0);
	if (*end != ':')
		return 0;				/* not an IRQ line */

	for (cpu = 0; cpu < cpu_count(); cpu++) {
		if ((tok = strtok_r(NULL, " \t", &saveptr)) == NULL)
			return -EINVAL;

		ii->ii_handled[cpu] = strtoul(tok, NULL, 10);
	}

	tok = strtok_r(NULL, " \t", &saveptr);
	BUG_ON(!tok);
	xstrncpy(ii->ii_chip_name, tok, IRQ_INFO_CHIP_NAME_LEN);

	tok = g_strchug(saveptr);
	xstrncpy(ii->ii_action, tok ? tok : "", IRQ_INFO_ACTION_LEN); 

	return 1;
}

static int
read_net_device_stats(void)
{
	char *line = NULL;
	size_t line_len;
	FILE *fp;
	int ret;

	if ((fp = id_fopen("/proc/net/dev", "r")) == NULL)
		BUG();

	getline(&line, &line_len, fp);
	getline(&line, &line_len, fp);
	while (!feof(fp)) {
		struct if_net_device_stats nds;
		struct interface *iface;
		char *name, *saveptr;

		if (getline(&line, &line_len, fp) == EOF)
			break;

		if ((name = strtok_r(line, ": ", &saveptr)) == NULL)
			continue;
		BUG_ON(strlen(name) > IFNAMSIZ);

#define __S        "%" PRIx64
		ret = sscanf(saveptr, __S " " __S " " __S " " __S " "__S " "__S " "
					 __S " " __S " " __S " " __S " " __S " " __S " " __S " "
					 __S " " __S " " __S,
#undef __S
					 /* RX */
					 &nds.rx_bytes, &nds.rx_packets,
					 &nds.rx_errors, &nds.rx_dropped,
					 &nds.rx_fifo_errors, &nds.rx_frame_errors,
					 &nds.rx_compressed, &nds.rx_mcast,
					 /* TX */
					 &nds.tx_bytes, &nds.tx_packets,
					 &nds.tx_errors, &nds.tx_dropped,
					 &nds.tx_fifo_errors, &nds.tx_collisions,
					 &nds.tx_carrier_errors, &nds.tx_compressed);
		if (ret != 16)
			continue;
		if ((iface = g_hash_table_lookup(if_hash, name)) == NULL)
			continue;			/* not UP or not interested */

		memcpy(&iface->if_stats[OLD], &iface->if_stats[NEW],
			   sizeof(iface->if_stats[OLD]));
		memcpy(&iface->if_stats[NEW], &nds, sizeof(iface->if_stats[NEW]));
	}

	g_free(line);
	fclose(fp);

	return 0;
}

static void
queue_update_irqs(struct if_queue_info *qi, const struct irq_info *ii)
{
	int cpu;

	memcpy(qi->qi_irq_stats[OLD], qi->qi_irq_stats[NEW],
		   cpu_count() * sizeof(unsigned));
	memcpy(qi->qi_irq_stats[NEW], ii->ii_handled,
		   cpu_count() * sizeof(unsigned));
	for (cpu = 0; cpu < cpu_count(); cpu++)
		if (qi->qi_irq_stats[OLD][cpu] > qi->qi_irq_stats[NEW][cpu])
			qi->qi_irq_stats[OLD][cpu] = 0U;

#ifdef DEBUG
	{
		char buf[128], *pch = buf, *end = buf + 128;

		for (cpu = 0; cpu < cpu_count(); cpu++)
			pch += snprintf(pch, end - pch, "%d:%d ",
							cpu, qi->qi_irq_stats[NEW][cpu]);
		buf[127] = '\0';
		dbg("irqs: %s:%d: %s", qi->qi_iface->if_name, qi->qi_num, buf);
	}
#endif
}

static void
irq_update_stats(const char *action, const struct irq_info *ii)
{
	struct if_queue_info *qi = NULL;
	enum ProcIrqAction pia;
	const char *tail;
	int queue;

	if ((tail = strpbrk(action, "-[")) != NULL) {
		pia = parse_iface_irq_action_tail(tail, &queue);
		switch (pia) {
			break;

		case PIA_Rx:
		case PIA_Tx:
		case PIA_RxTx:
			qi = if_queue_by_name(action, queue);
			break;

		case PIA_LSC:
			/* can't happen */
		case PIA_NoMatch:
			break;
		}
	} else
		qi = if_queue_by_name(action, queue);

	if (qi)
		queue_update_irqs(qi, ii);
}

static int
read_irq_stats(void)
{
	char *line = NULL;
	size_t line_len;
	FILE *fp;

	if ((fp = id_fopen("/proc/interrupts", "r")) == NULL)
		goto err;

	getline(&line, &line_len, fp);
	while (!feof(fp)) {
		struct irq_info ii;
		char *tok, *saveptr;
		int ret;

		if (getline(&line, &line_len, fp) == EOF)
			break;
		if ((ret = read_irq_info(line, &ii)) < 0)
			goto err;
		else if (ret == 0)
			continue;

		tok = strtok_r(ii.ii_action, " ,\t", &saveptr);
		while (tok) {
			irq_update_stats(tok, &ii);
	
			tok = strtok_r(NULL, " ,\t", &saveptr);
		}
	}

	fclose(fp);
	g_free(line);

	return 0;

err:
	if (fp)
		fclose(fp);
	g_free(line);
	return -1;
}

static enum EvReturn
rebalance_cb(struct ev *ev, unsigned short what)
{
	static int turn;
	uint64_t exp;
	int nread, cpu;

	BUG_ON(what != EV_READ);
	if ((nread = read(ev->fd, &exp, sizeof(exp))) < 0) {
		if (errno == -EAGAIN)
			return EvOk;
		err("read: %m");
		return EvStop;
	}
	BUG_ON(nread != sizeof(exp));

	cpu_read_stat();
	read_net_device_stats();
	read_irq_stats();

	if (turn++ == 0)
		return EvOk;

	cpu_do_stat();

	for (cpu = 0; cpu < cpu_count(); cpu++) {
		struct cpu_info *ci = cpu_nth(cpu);
		struct cpuset *set = ci->ci_cpuset;

#if 0
		log("cpu%d: dropped:%u,%u time_squeeze:%u,%u", cpu,
			ci->ci_ss[OLD].dropped, ci->ci_ss[NEW].dropped,
			ci->ci_ss[OLD].time_squeeze, ci->ci_ss[NEW].time_squeeze);
#endif /* 0 */

		/* Not all CPUs are part of a cpuset */
		if ((ci->ci_si_load > REBALANCE_SI_THRESH
			 || CPU_SS_DIFF(ci, dropped) > 0) && set != NULL)
			cpuset_cpu_busy(set, ci);
	}

	return EvOk;
}

static int
rebalance_init(void)
{
	struct itimerspec its = {
		.it_interval = { .tv_sec = REBALANCE_IVAL, },
		.it_value = { .tv_sec = REBALANCE_IVAL, },
	};
	struct timespec now;
	int fd;

	if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
		err("clock_gettime: %m");
		return -1;
	}

	fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		err("timerfd_create: %m");
		return -1;
	}

	its.it_value.tv_sec += now.tv_sec;
	if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
		err("timerfd_settime: %m");
		return -1;
	}

	ev_set(&rebalance_ev, fd, NULL, NULL);
	rebalance_ev.cb_read = rebalance_cb;
	ev_add(&rebalance_ev, EV_READ);

	log("rebalance started (every %d sec)", REBALANCE_IVAL);

	return 0;
}

static void
rtnl_interface_cb(struct nl_object *obj, void *arg)
{
	char buf[128];
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_LINE,
		.dp_buf = buf,
		.dp_buflen = sizeof(buf),
	};

	buf[0] = '\0';
	nl_object_dump(obj, &dp);
	log("%s", buf);

	rtnl_balance_link((struct rtnl_link *)obj);
}

static void
rtnl_change_cb(struct nl_cache *cache, struct nl_object *obj, int action,
	void *arg)
{
	char buf[128];
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_LINE,
		.dp_buf = buf,
		.dp_buflen = sizeof(buf),
	};

	buf[0] = '\0';
	nl_object_dump(obj, &dp);
	log("%s", buf);

	rtnl_balance_link((struct rtnl_link *)obj);
}

int
if_init(void)
{
	if_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	if (!if_hash) {
		OOM();
		return -1;
	}

	return 0;
}

int
if_rtnl_init(void)
{
	int ret;

	BUG_ON(!cpu_count() || !config_is_read);
	if ((nlh = nl_socket_alloc()) == NULL) {
		err("unable to allocate netlink handle");
		return -1;
	}

	nl_socket_disable_seq_check(nlh);

	ret = nl_cache_mngr_alloc(nlh, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (ret < 0) {
		err("%s\n", nl_geterror(ret));
		return -1;
	}

	ret = nl_cache_mngr_add(mngr, "route/link", rtnl_change_cb, NULL,
							&nlcache);
	if (ret < 0) {
		err("%s\n", nl_geterror(ret));
		return -1;
	}

	ev_set(&nl_ev, nl_cache_mngr_get_fd(mngr), NULL, mngr);
	nl_ev.cb_read = rtnl_io_cb;
	ev_add(&nl_ev, EV_READ);
	log("getting interface notifications");

	nl_cache_foreach(nlcache, rtnl_interface_cb, NULL);

	return rebalance_init();
}

void
if_fini(void)
{
	nl_cache_mngr_free(mngr);
}
