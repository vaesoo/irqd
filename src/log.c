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

static int log_buf_len = 1024;
static char *log_buf_stdout;
static char *log_buf_stderr;


static void
log_va(FILE *fp, char *buf, const char *file, int line, const char *prefix,
	   int prio, const char *fmt, va_list ap)
{
	char *pch = buf, *end = buf + log_buf_len;

	if (with_debug)
		flockfile(fp);

	if (file && line)
		pch += snprintf(pch, end - pch, "%s:%d: ", file, line);
	if (prefix)
		pch += snprintf(pch, end - pch, "%s: ", prefix);
	pch += vsnprintf(pch, end - pch, fmt, ap);

	if (with_debug) {
		if (pch > buf && pch[-1] != '\n')
			strcat(pch, "\n");
		fputs_unlocked(buf, fp);
		funlockfile(fp);
	} else
		syslog(prio, "%s", buf);
}

void
id_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_va(stdout, log_buf_stdout, NULL, 0, NULL, LOG_INFO, fmt, ap);
	va_end(ap);
}

void
id_err(const char *file, int line, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_va(stderr, log_buf_stderr, file, line, "ERROR", LOG_ERR, fmt, ap);
	va_end(ap);
}

static void
id_fail_va(const char *file, int line, const char *fmt, va_list ap)
{
	log_va(stderr, log_buf_stderr, file, line, NULL, LOG_CRIT, fmt, ap);
}

void
id_bug(const char *file, int line)
{
// As a NULL is not allowed for ARM va_list
	va_list ap;
	id_fail_va(file, line, "BUG", ap);
	abort();
}

void
id_oom(const char *file, int line)
{
// As a NULL is not allowed for ARM va_list
	va_list ap;
	id_fail_va(file, line, "OOM", ap);
	errno = ENOMEM;
}

int
log_init(void)
{
	log_buf_stdout = g_malloc(log_buf_len);
	log_buf_stderr = g_malloc(log_buf_len);
	if (!log_buf_stdout || !log_buf_stderr) {
		fprintf(stderr, "log: %m\n");
		return -1;
	}

	return 0;
}

