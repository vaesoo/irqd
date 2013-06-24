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

GSList *strategy_type_list;

extern struct strategy_type evenly_strategy_type;

struct strategy_type *
strategy_find_type(const char *name)
{
	GSList *node;

	for (node = strategy_type_list; node; node = g_slist_next(node)) {
		struct strategy_type *type = node->data;

		if (!strcmp(type->name, name))
			return type;
	}

	return NULL;
}

int
strategy_init(void)
{
	strategy_type_list = g_slist_append(strategy_type_list,
										&evenly_strategy_type);

	return 0;
}
