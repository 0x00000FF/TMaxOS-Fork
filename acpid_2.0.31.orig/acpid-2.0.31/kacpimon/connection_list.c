/*
 *  connection_list.c - ACPI daemon connection list
 *
 *  Copyright (C) 2008, Ted Felix (www.tedfelix.com)
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
 *  Tabs at 4
 */

#include <unistd.h>
#include <stdio.h>

#include "connection_list.h"

#define max(a, b)  (((a)>(b))?(a):(b))

/*---------------------------------------------------------------*/
/* private objects */

#define MAX_CONNECTIONS 100

static struct connection connection_list[MAX_CONNECTIONS];

static int nconnections = 0;

/* fd_set containing all the fd's that come in */
static fd_set allfds;

/* highest fd that is opened */
/* (-2 + 1) causes select() to return immediately */
static int highestfd = -2;

/*---------------------------------------------------------------*/
/* public functions */

void
add_connection(struct connection *p)
{
	if (nconnections < 0)
		return;
	if (nconnections >= MAX_CONNECTIONS) {
		printf("add_connection(): Too many connections.\n");
		return;
	}

	if (nconnections == 0)
		FD_ZERO(&allfds);
	
	/* add the connection to the connection list */
	connection_list[nconnections] = *p;
	++nconnections;
	
	/* add to the fd set */
	FD_SET(p->fd, &allfds);
	highestfd = max(highestfd, p->fd);
}

/*---------------------------------------------------------------*/

struct connection *
find_connection(int fd)
{
	int i;

	/* for each connection */
	for (i = 0; i < nconnections; ++i) {
		/* if the file descriptors match, return the connection */
		if (connection_list[i].fd == fd)
			return &connection_list[i];
	}

	return NULL;
}

/*---------------------------------------------------------------*/

int 
get_number_of_connections(void)
{
	return nconnections;
}

/*---------------------------------------------------------------*/

struct connection *
get_connection(int i)
{
	if (i < 0  ||  i >= nconnections)
		return NULL;

	return &connection_list[i];
}

/*---------------------------------------------------------------*/

const fd_set *
get_fdset(void)
{
	return &allfds;
}

/*---------------------------------------------------------------*/

int
get_highestfd(void)
{
	return highestfd;
}
