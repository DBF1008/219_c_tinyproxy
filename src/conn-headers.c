/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2000 Chris Lightfoot <chris@ex-parrot.com>
 * Copyright (C) 2002 Petr Lampa <lampa@fit.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Cleanup of hop-by-hop connection headers.  Split out of reqs.c so it can
 * be exercised by a focused unit test; it relies only on the pseudomap API.
 */

#include "conn-headers.h"

#include <string.h>
#include <strings.h>
#include <sys/types.h>

/*
 * Extract the headers to remove.  These headers were listed in the Connection
 * and Proxy-Connection headers.
 */
int remove_connection_headers (pseudomap *hashofheaders)
{
        static const char *headers[] = {
                "connection",
                "proxy-connection"
        };

        char *data;
        char *ptr;
        ssize_t len;
        int i,j,df;

        for (i = 0; i != (sizeof (headers) / sizeof (char *)); ++i) {
                /*
                 * Look for this connection header.  If it's not present, move
                 * on to the next one instead of bailing out: a message may
                 * carry only "Proxy-Connection" (along with the hop-by-hop
                 * headers it enumerates), and those still need to be removed.
                 */
                data = pseudomap_find(hashofheaders, headers[i]);

                if (!data)
                        continue;

                len = strlen(data);

                /*
                 * Go through the data line and replace any special characters
                 * with a NULL.
                 */
                ptr = data;
                while ((ptr = strpbrk (ptr, "()<>@,;:\\\"/[]?={} \t")))
                        *ptr++ = '\0';

                /*
                 * All the tokens are separated by NULLs.  Now go through the
                 * token and remove them from the hashofheaders.
                 */
                ptr = data;
                while (ptr < data + len) {
                        df = 0;
                        /* check that ptr isn't one of headers to prevent
                           double-free (CVE-2023-49606) */
                        for (j = 0; j != (sizeof (headers) / sizeof (char *)); ++j)
                                if(!strcasecmp(ptr, headers[j])) df = 1;
                        if (!df) pseudomap_remove (hashofheaders, ptr);

                        /* Advance ptr to the next token */
                        ptr += strlen (ptr) + 1;
                        while (ptr < data + len && *ptr == '\0')
                                ptr++;
                }

                /* Now remove the connection header it self. */
                pseudomap_remove (hashofheaders, headers[i]);
        }

        return 0;
}
