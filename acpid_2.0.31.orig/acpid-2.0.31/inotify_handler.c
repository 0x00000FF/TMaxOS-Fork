/*
 *  inotify_handler.c - inotify Handler for New Devices
 *
 *  Watches /dev/input for new input layer device files.
 *
 *  Copyright (C) 2009, Ted Felix (www.tedfelix.com)
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
 *
 *  (tabs at 4)
 */

/* system */
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

/* local */
#include "acpid.h"
#include "log.h"
#include "connection_list.h"
#include "input_layer.h"

#include "inotify_handler.h"

/*-----------------------------------------------------------------*/
/* called when an inotify event is received */
static void process_inotify(int fd)
{
	int bytes;
	int processed_bytes = 0;

	char eventbuf[sizeof(struct inotify_event) + NAME_MAX + 1];

	bytes = read(fd, &eventbuf, sizeof(eventbuf));

	acpid_log(LOG_DEBUG, "inotify read bytes: %d", bytes);

	/* eof is not expected */	
	if (bytes == 0) {
		acpid_log(LOG_WARNING, "inotify fd eof encountered");
		return;
	}
	else if (bytes < 0) {
		/* EINVAL means buffer wasn't big enough.  See inotify(7). */
		acpid_log(LOG_ERR, "inotify read error: %s (%d)",
			strerror(errno), errno);
		acpid_log(LOG_ERR, "disconnecting from inotify");
		delete_connection(fd);
		return;
	}

	const int dnsize = NAME_MAX + 1;
	char devname[dnsize];

	/* while there are still messages in eventbuf */
	while (processed_bytes < bytes) {
		struct inotify_event* curevent = (struct inotify_event *)
			&eventbuf[processed_bytes];

		acpid_log(LOG_DEBUG, "inotify name len: %d", curevent->len);

		/* if a name is included */
		if (curevent->len > 0) {
			/* devname = ACPID_INPUTLAYERDIR + "/" + pevent -> name */
			strcpy(devname, ACPID_INPUTLAYERDIR);
			strcat(devname, "/");
			strncat(devname, curevent->name, dnsize - strlen(devname) - 1);
		}

		/* if this is a create */
		if (curevent->mask & IN_CREATE) {
			acpid_log(LOG_DEBUG, "inotify about to open: %s", devname);

			open_inputfile(devname);
		}

		/* if this is a delete */
		if (curevent->mask & IN_DELETE) {
			/* struct connection *c; */

			acpid_log(LOG_DEBUG, "inotify received a delete for: %s", devname);

#if 0
/* Switching back to the original ENODEV detection scheme.  See
   process_input() in input_layer.c. */
/* keeping this for future reference */
			/* search for the event file in the connection list */
			/* ??? Or should we just have a delete_connection_name()? */
			c = find_connection_name(devname);

			/* close that connection if found */
			if (c)
				delete_connection(c->fd);
#endif
		}

		processed_bytes += sizeof(struct inotify_event) + curevent->len;
	}
}

/*-----------------------------------------------------------------*/
/* Set up an inotify watch on /dev/input. */
void open_inotify(void)
{
	int fd = -1;
	int wd = -1;
	struct connection c;

	/* set up inotify */
	fd = inotify_init1(IN_CLOEXEC);
	
	if (fd < 0) {
		acpid_log(LOG_ERR, "inotify_init() failed: %s (%d)",
			strerror(errno), errno);
		return;
	}
	
	acpid_log(LOG_DEBUG, "inotify fd: %d", fd);

	/* watch for files being created or deleted in /dev/input */
	wd = inotify_add_watch(fd, ACPID_INPUTLAYERDIR, IN_CREATE | IN_DELETE);

	if (wd < 0) {
		if (errno == ENOENT) {
			/* Common with headless devices. */
			acpid_log(LOG_WARNING, "inotify_add_watch(): input layer not found");
		} else {
			acpid_log(LOG_ERR, "inotify_add_watch() failed: %s (%d)",
				strerror(errno), errno);
		}

		close(fd);			
		return;
	}

	acpid_log(LOG_DEBUG, "inotify wd: %d", wd);

	/* add a connection to the list */
	c.fd = fd;
	c.process = process_inotify;
	c.pathname = NULL;
	c.kybd = 0;

	if (add_connection(&c) < 0) {
		close(fd);
		acpid_log(LOG_ERR, "can't add connection for inotify");
		return;
	}
}

