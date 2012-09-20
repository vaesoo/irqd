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
#include <getopt.h>

#include "irqd.h"
#include "event.h"
#include "cpu.h"
#include "interface.h"
#include "cfg_grammar.h"

#define PID_FILE		"irqd.pid"


/* if set allows to access files below /sys and /proc below a subdirectory */
/* FIXME make automake aware */
char *cfg_file = "/etc/irqdrc";
bool config_is_read;

char *irqd_prefix;
bool no_daemon;
int verbose;
enum RpsStatus g_rps_status;
enum XpsStatus g_xps_status;

extern int yyparse();
extern void yyset_in(FILE *);

static int
check_opts(int argc, char *argv[])
{
	static struct option lopts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "verbose", 0, NULL, 'v' },
		{ "version", 0, NULL, 0 },
		{ 0 }
	};
	int c, idx = 0;

	while ((c = getopt_long(argc, argv, "c:dv", lopts, &idx)) != -1) {
		if (!c) {				/* long-only option */
			switch (idx) {
			case 1:				/* version */
				break;

			default:
				return -1;
			}
			continue;
		}

		switch (c) {
		case 'c':
			cfg_file = strdup(optarg);
			break;

		case 'd':
			no_daemon = true;
			break;

		case 'v':				/* verbose */
			verbose++;
			break;

		case '?':
			return -1;
		}
	}

	return 0;
}

static int
config_read(void)
{
	struct cpuset *set;
	FILE *fp;

	if ((fp = fopen(cfg_file, "r")) == NULL) {
		if (errno == ENOENT) {
			log("no config file found");
			goto out_read;
		}

		err("%s: %m", cfg_file);
		return -1;
	}

	yyset_in(fp);
	if (yyparse() == 1)
		goto err;
	else if (yyparse() == 2) {
		OOM();
		goto err;
	}

out_read:
	if (!cpuset_list) {
		if ((set = cpuset_new("default", 0, cpu_count())) == NULL)
			return -1;
		cpuset_set_auto_assign(set);
		cpuset_set_strategy(set, "evenly");
		cpuset_list_add(set);
	}

	if (fp)
		fclose(fp);
	config_is_read = true;

	return 0;

err:
	fclose(fp);
	return -1;
}

static void
config_dump(void)
{
	cpuset_dump();
}

/* returned string needs to be freed by caller */
char *
id_path(const char *path)
{
	char *buf = malloc(PATH_MAX);

	BUG_ON(*path != '/');

	if ((buf = malloc(PATH_MAX)) == NULL) {
		OOM();
		return NULL;
	}

	snprintf(buf, PATH_MAX, "%s%s", irqd_prefix, path);
	buf[PATH_MAX - 1] = '\0';

	return buf;
}

int
id_set_fd_flags(int fd, int new_flags)
{
	int flags = fcntl(fd, F_GETFD, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFD, flags  | new_flags);
}

/**
 * id_fopen() - wrapper arund fopen() with debug possibilities
 *
 * Only works for absolute paths.
 */
FILE *
id_fopen(const char *file, const char *mode)
{
	FILE *fp;

	BUG_ON(file[0] != '/');
	if (irqd_prefix) {
		char path[2 * PATH_MAX];

		snprintf(path, sizeof(path), "%s%s", irqd_prefix, file);
		path[sizeof(path) - 1] = '\0';
		if ((fp = fopen(path, mode)) == NULL) {
			if (errno != ENOENT)
				goto err;
		}
	}

	if (!fp && (fp = fopen(file, mode)) == NULL)
		goto err;
	/* FIXME remove race */
	id_set_fd_flags(fileno(fp), O_CLOEXEC);

	return fp;

err:
	err("%s: %m", file);
	return NULL;
}

int
irq_set_affinity(int irq, uint64_t mask)
{
	char path[PATH_MAX], buf[16];
	int fd, len, nwritten;

	snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity", irq);
	if ((fd = open(path, O_WRONLY | O_CLOEXEC)) < 0) {
		err("%s: %m", path);
		return -1;
	}

	len = snprintf(buf, sizeof(buf), "%" PRIx64 "\n", mask);
	nwritten = write(fd, buf, len);
	BUG_ON(nwritten != len);

	close(fd);

	return 0;
}

char *
xstrncpy(char *dst, const char *src, size_t n)
{
	strncpy(dst, src, n);
	if (dst[n - 1])
		dst[n - 1] = '\0';
	return dst;
}


static void
irqd_at_exit(void)
{
	char pidfile[PATH_MAX];

	snprintf(pidfile, sizeof(pidfile), "%s%s", _PATH_VARRUN, PID_FILE);
	unlink(pidfile);
}

/* write PID file unless already running */
static int
write_pid(void)
{
	char path[PATH_MAX];
	FILE *fp = NULL;
	int fd;

	snprintf(path, sizeof(path), "%s%s", _PATH_VARRUN, PID_FILE);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644)) < 0) {
		err("already running");
		return -1;
	}

	if ((fp = fdopen(fd, "r+")) == NULL) {
		err("%s: %m", PID_FILE);
		close(fd);

		return -1;
	}

	fprintf(fp, "%u\n", getpid());

	fclose(fp);

	atexit(irqd_at_exit);

	return 0;
}

int
main(int argc, char *argv[])
{
	log_init();

	if (check_opts(argc, argv) < 0)
		exit(EXIT_FAILURE);

	if (!no_daemon)
		openlog("irqd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	if ((irqd_prefix = getenv("IRQD_PREFIX")) == NULL)
		irqd_prefix = "";

	setlocale(LC_ALL, "");

	if (geteuid()) {
		err("root required");
		exit(1);
	}

	ev_init();
	strategy_init();

	cpu_init();
	if(cpu_count() == 1) {
		log("single CPU, nothing to balance");
		exit(0);
	}

	if (optind < argc) {
		err("extra arguments on command line");
		exit(1);
	}

	if_init();

	if (config_read() < 0)
		exit(1);
	if (no_daemon && verbose)
		config_dump();

	if (!no_daemon && daemon(0, 0) < 0) {
		err("can't start daemon\n");
		exit(1);
	}

	if (write_pid() < 0)
		exit(1);

	if_rtnl_init();

	ev_dispatch();

	if_fini();
	cpu_fini();
	ev_fini();

	return 0;
}
