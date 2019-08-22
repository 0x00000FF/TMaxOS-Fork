/*
 *  log.c - ACPI daemon logging
 *
 *  Portions Copyright (C) 2000 Andrew Henroid
 *  Portions Copyright (C) 2001 Sun Microsystems
 *  Portions Copyright (C) 2004 Tim Hockin (thockin@hockin.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

#include "log.h"

int log_to_stderr = 0;
int debug_level = 0;

int
#ifdef __GNUC__
__attribute__((format(printf, 2, 3)))
#endif
acpid_log(int level, const char *fmt, ...)
{
	if (level == LOG_DEBUG && !debug_level) return 0;
	va_list args;
	va_start(args, fmt);

	if (log_to_stderr) {
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
	} else {
		vsyslog(level, fmt, args);
	}

	va_end(args);
	return 0;
}
