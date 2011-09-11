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

static enum RpsStatus {
	RPS_S_NEED_CHECK = 0,
	RPS_S_DISABLED,
	RPS_S_ENABLED,
} rps_status;
static struct nl_handle *nlh;
static struct nl_cache *nlcache;
static struct nl_cache_mngr *mngr;
static struct ev nl_ev;
static struct ev rebalance_ev;
static GHashTable *if_hash;
static const struct balance_strategy *strategy = &bs_evenly;

static void if_free(struct interface *iface) __UNUSED;

static struct interface *
if_new(const char *dev)
{
	struct interface *iface;

	iface = g_new0(struct interface, 1);
	if (iface) {
		strncpy(iface->if_name, dev, IFNAMSIZ);
		iface->if_queues = g_new0(struct if_queue_info, QUEUE_MAX);
		if (!iface->if_queues) {
			g_free(iface);
			iface = NULL;
		}
	}

	if (!iface)
		OOM();
	return iface;
}

static void
if_free(struct interface *iface)
{
	if (iface) {
		int queue;

		for (queue = 0; queue < iface->if_num_queues; queue++)
			BUG_ON(!cpuset_is_empty(if_queue(iface, queue)->qi_cpuset));
		g_free(iface->if_queues);
		g_free(iface);
	}
}

struct if_queue_info *
if_queue_by_name(const char *dev, int queue)
{
	const struct interface *iface;

	if ((iface = g_hash_table_lookup(if_hash, dev)) == NULL)
		return NULL;

	return if_queue(iface, queue);
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

int
if_set_rps_cpus(const struct interface *iface, int queue, uint64_t mask)
{
	char path[PATH_MAX], buf[32];
	int fd, len, nwritten;

	snprintf(path, sizeof(path), "/sys/class/net/%s/queues/rx-%d/rps_cpus",
			 iface->if_name, queue);
	if ((fd = open(path, O_WRONLY | O_CLOEXEC)) < 0) {
		err("%s/%d/rps_cpus: %m", iface->if_name, queue);
		return -1;
	}

	len = snprintf(buf, sizeof(buf), "%" PRIx64, mask);
	nwritten = write(fd, buf, len);
	BUG_ON(nwritten != len);

	close(fd);

	return 0;
}

/**
 * @return 1: found, 0: not found, <0 error
 */
static int
parse_irq_action(const char *tok, const char *dev, int *queue)
{
	char pattern[32];

	/* this may be just a LSC IRQ */
	if (!strcmp(tok, dev)) {
		*queue = 0;
		return 1;
	}
		
	snprintf(pattern, sizeof(pattern), "%s-TxRx-%%u", dev);
	if (sscanf(tok, pattern, queue) == 1) 
		return 1;

	/* Broadcom NICs (netxen, bnx2) */
	snprintf(pattern, sizeof(pattern), "%s[%%u]", dev);
	if (sscanf(tok, pattern, queue) == 1)
		return 1;

	return 0;
}

static struct if_queue_info *
if_add_queue(struct interface *iface, int queue, int irq)
{
	struct if_queue_info *qi = if_queue(iface, queue);

	if (!qi->qi_cpuset && (qi->qi_cpuset = cpuset_new()) == NULL)
		return NULL;
	qi->qi_num = queue;
	qi->qi_iface = iface;
	qi->qi_irq = irq;

	iface->if_num_queues = max(iface->if_num_queues, queue + 1);

	return qi;
}

/*
 * @return number of queues read, or -1 on error
 */
static int
add_queues(struct interface *iface, size_t qi_len)
{
	FILE *fp;
	char *path = NULL, *line = NULL;
	size_t line_len;
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int lineno = 0;

	BUG_ON(rps_status == RPS_S_NEED_CHECK);
	iface->if_num_queues = 0;

	path = id_path("/proc/interrupts");
	if ((fp = fopen(path, "r")) == NULL) {
		err("interrupts: %m");
		goto err_free;
	}

	g_free(path);

	getline(&line, &line_len, fp);
	lineno++;
next_line:
	while (!feof(fp)) {
		struct if_queue_info *qi = NULL;
		char *pch, *tok, *end, *saveptr;
		int i, irq, devs = 0;

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

			if (parse_irq_action(tok, iface->if_name, &queue) == 1)
				qi = if_add_queue(iface, queue, irq);
			devs++;
		} while (1);

		if (qi && devs > 1)
			qi->qi_flags |= QI_F_SHARED_IRQ;
	}

	free(line);
	/* if (ferror(fp)) ... */
	fclose(fp);

	return 0;

err_free:
	g_free(path);
	g_free(line);
	if (fp)
		fclose(fp);

	return -1;
}

static int
rtnl_link_up(struct rtnl_link *link, const char *dev)
{
	struct interface *iface;
	int i;

	if ((iface = g_hash_table_lookup(if_hash, dev)) == NULL)
		return 0;

	if (rps_status == RPS_S_NEED_CHECK) {
		rps_status = if_can_rps(iface) ? RPS_S_ENABLED : RPS_S_DISABLED;
		log("RPS is %s", rps_status == RPS_S_ENABLED ? "enabled" : "disabled");
	}

	if (add_queues(iface, QUEUE_MAX) < 0)
		return -1;
	
	for (i = 0; i < iface->if_num_queues; i++) {
		if (rps_status == RPS_S_ENABLED)
			strategy->balance_queue_rps(iface, i);
		else
			strategy->balance_queue(iface, i);
	}

	return 0;
}

static int
rtnl_link_down(struct rtnl_link *link, const char *dev)
{
	struct interface *iface;
	int queue;

	if ((iface = g_hash_table_lookup(if_hash, dev)) == NULL)
		return 0;

	if (strategy->interface_down)
		strategy->interface_down(iface);

	for (queue = 0; queue < iface->if_num_queues; queue++) {
		struct if_queue_info *qi = if_queue(iface, queue);
		int cpu;

		for (cpu = 0; cpu < cpu_count(); cpu++) {
			if (cpuset_clear(qi->qi_cpuset, cpu))
				cpu_del_queue(cpu, qi);
		}
	}

	cpu_dump_map();

	return 0;
}

static int
rtnl_balance_link(struct rtnl_link *link)
{
	struct interface *iface;
	const char *dev;
	int flags;
	bool change = false;

	if ((dev = rtnl_link_get_name(link)) == NULL)
		return 0;
	if (strncmp(dev, "eth", 3))
		return 0;

	if ((iface = g_hash_table_lookup(if_hash, dev)) == NULL) {
		if ((iface = if_new(dev)) == NULL)
			return -1;

		g_hash_table_insert(if_hash, strdup(dev), iface);
	}

	flags = rtnl_link_get_flags(link);
	if ((iface->if_flags & IFF_UP) == 0 && (flags & IFF_UP)) {
		if (rtnl_link_up(link, dev) < 0)
			goto err;
		change = true;
	} else if ((iface->if_flags & IFF_UP) && (flags & IFF_UP) == 0) {
		if (rtnl_link_down(link, dev) < 0)
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

	if ((fp = fopen("/proc/net/dev", "r")) == NULL)
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

static int
parse_eth_action(const char *str, char *dev, size_t dev_len, int *queue)
{
	int n;

	BUG_ON(dev_len < IFNAMSIZ);
	*queue = 0;
	if (sscanf(str, "eth%d-TxRx-%d", &n, queue) == 2
		|| sscanf(str, "eth%d", &n) == 1) {
		snprintf(dev, IFNAMSIZ, "eth%d", n);
		return 0;
	}

	return -1;
}

static void
queue_update_irqs(struct if_queue_info *qi, const struct irq_info *ii)
{
	int cpu;

	memcpy(qi->qi_irqs[OLD], qi->qi_irqs[NEW], cpu_count() * sizeof(unsigned));
	memcpy(qi->qi_irqs[NEW], ii->ii_handled, cpu_count() * sizeof(unsigned));
	for (cpu = 0; cpu < cpu_count(); cpu++)
		if (qi->qi_irqs[OLD][cpu] > qi->qi_irqs[NEW][cpu])
			qi->qi_irqs[OLD][cpu] = 0U;

#ifdef DEBUG
	{
		char buf[128], *pch = buf, *end = buf + 128;

		for (cpu = 0; cpu < cpu_count(); cpu++)
			pch += snprintf(pch, end - pch, "%d:%d ",
							cpu, qi->qi_irqs[NEW][cpu]);
		buf[127] = '\0';
		dbg("irqs: %s:%d: %s", qi->qi_iface->if_name, qi->qi_num, buf);
	}
#endif
}

static int
read_irq_stats(void)
{
	char *path = NULL, *line = NULL;
	size_t line_len;
	FILE *fp = NULL;

	path = id_path("/proc/interrupts");
	if ((fp = fopen(path, "r")) == NULL) {
		err("interrupts: %m");
		goto err;
	}
	g_free(path);

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
			struct if_queue_info *qi;
			char dev[IFNAMSIZ];
			int queue;

			if (parse_eth_action(tok, dev, sizeof(dev), &queue) == 0) {
				if ((qi = if_queue_by_name(dev, queue)) != NULL)
					queue_update_irqs(qi, &ii);
			}

			tok = strtok_r(NULL, " ,\t", &saveptr);
		}
	}

	fclose(fp);
	g_free(line);

	return 0;

err:
	if (fp)
		fclose(fp);
	g_free(path);
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
	nread = read(ev->fd, &exp, sizeof(exp));

	cpu_read_stat();
	read_net_device_stats();
	read_irq_stats();

	if (turn++ == 0)
		return EvOk;

	cpu_do_stat();

	for (cpu = 0; cpu < cpu_count(); cpu++) {
		struct cpu_info *ci = cpu_nth(cpu);

#if 0
		log("cpu%d: dropped:%u,%u time_squeeze:%u,%u", cpu,
			ci->ci_ss[OLD].dropped, ci->ci_ss[NEW].dropped,
			ci->ci_ss[OLD].time_squeeze, ci->ci_ss[NEW].time_squeeze);
#endif /* 0 */
		if (ci->ci_si_load > REBALANCE_SI_THRESH
			|| CPU_SS_DIFF(ci, dropped) > 0) {
			if (strategy->softirq_busy)
				strategy->softirq_busy(ci);
		}
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
		.dp_type = NL_DUMP_BRIEF,
		.dp_buf = buf,
		.dp_buflen = sizeof(buf),
	};

	buf[0] = '\0';
	nl_object_dump(obj, &dp);
	log("%s", buf);

	rtnl_balance_link((struct rtnl_link *)obj);
}

static void
rtnl_change_cb(struct nl_cache *cache, struct nl_object *obj, int action)
{
	char buf[128];
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_BRIEF,
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
	BUG_ON(!cpu_count());
	if_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	if (!if_hash) {
		OOM();
		return -1;
	}

	if ((nlh = nl_handle_alloc()) == NULL) {
		err("unable to allocate netlink handle");
		return -1;
	}

	nl_disable_sequence_check(nlh);

	mngr = nl_cache_mngr_alloc(nlh, NETLINK_ROUTE, NL_AUTO_PROVIDE);
	if (!mngr) {
		err("%s\n", nl_geterror());
		return -1;
	}

	nlcache = nl_cache_mngr_add(mngr, "route/link", rtnl_change_cb);
	if (!nlcache) {
		err("%s\n", nl_geterror());
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
