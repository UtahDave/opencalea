/*
 * Copyright (c) 2007, Merit Network, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Merit Network, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY MERIT NETWORK, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL MERIT NETWORK, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"


/* Helper Routines */

void *Calloc(size_t size) {
  char *ptr;
  ptr = calloc(1, size);
  if(!ptr) {
    pdie("calloc");
  }
  return ptr;
}


void *Strdup(const char *str) {
  char *ptr;
  ptr = strdup(str);
  if(!ptr) {
    pdie("strdup");
  }
  return ptr;
}


/*-------------------------------------------------------------------------------------*/
/* Print hex data                                                                      */
/*                                                                                     */
/*   Offset                                                                            */
/* Dec   Hex     Hex Data                                            ASCII Data        */
/* 00000 (00000) 4E 4F 54 49 46 59 20 73  69 70 3A 6F 70 65 6E 73    NOTIFY s ip:opens */
/*                                                                                     */
/*-------------------------------------------------------------------------------------*/
void print_hex(const u_char *payload, size_t payload_size) {

  size_t i, j, k, index = 0;
  char line[80];

  sprintf(line, "Starting Address: %p (%05Zud) (%05lXx)  ", payload, (long unsigned)payload_size, (long unsigned)payload_size);
  debug_5(line);

  for (index=0; index < payload_size; index+=16) {
    bzero(line, 80);

    /* Print the base address. */
    sprintf(line, "%05Zu (%05lX)  ", index, (long unsigned)index);

    /* Print full row */
    if ( (k=payload_size-index) > 15 )  {
      /* Print full row */
      for ( i = 0; i < 16; i++ ) {
        if (i == 8) sprintf(line, "%s ", line);
        sprintf(line, "%s%02X ", line, payload[index+i]);
      }
      sprintf(line, "%s  ", line);
      for ( j = 0; j < 16; j++ ) {
        if (j == 8) sprintf(line, "%s ", line);
        sprintf(line, "%s%c", line, isprint(payload[index+j]) ? payload[index+j] : '.');
      }
      debug_5(line);
    } else {
    /* Print partial row */
      for ( i = 0; i < 16; i++ ) {
        if (i == 8) sprintf(line, "%s ", line);
        if (i < k) {
          sprintf(line, "%s%02X ", line, payload[index+i]);
        } else {
          sprintf(line, "%s   ", line);
        }
      }
      sprintf(line, "%s  ", line);
      for ( j = 0; j < 16; j++ ) {
        if (j == 8) sprintf(line, "%s ", line);
        if (j < k) {
          sprintf(line, "%s%c", line, isprint(payload[index+j]) ? payload[index+j] : '.');
        } else {
          sprintf(line, "%s ", line);
        }
      }
      debug_5(line);
    }
  }

}

/* tcp_read */
ssize_t tcp_read(int fd, void *buf, size_t tot_len) {
	size_t len;		/* length of the current read */
	ssize_t num_read;	/* number of bytes returned by last read operation */
	char *buf_index;	/* index into the buffer where the next data read will be placed */

	buf_index = buf;	/* initialize the index into the buffer */
	len = tot_len;		/* initialize the number of bytes to read */

	/* loop while the length of data to read is > 0 */
	/* or an error condition is raised		*/
	/* or an EOF condition is raised		*/
	while (len > 0) {
		if ( (num_read = read(fd, buf_index, len)) < 0) {
			if (errno == EINTR) {
				num_read = 0;
			} else {
				return -1;
			}
		} else if (num_read == 0)		/* zero bytes read indicate an EOF condition */
			break;

		len = len - num_read;			/* reduce total length by number of bytes read */
		buf_index = buf_index + num_read;	/* prepare index into buffer for next read */
	}
	return (tot_len - len);				/* return actual number of bytes read */
}

/* tcp_write */
ssize_t tcp_write(int fd, const void *buf, size_t tot_len) {
	size_t num_left;	/* number of bytes left to write */
	ssize_t num_written;	/* number of bytes written by last write operation */
	const char *buf_index;  /* index into the buffer where the next data to be written will be found */

	buf_index = buf;	/* iniitialize the index into the buffer */
	num_left = tot_len;	/* initialuze the number of bytes to write */
	while (num_left > 0) {
		if ( (num_written = write(fd, buf_index, num_left)) <= 0) {
			if (num_written < 0 && errno == EINTR)
				num_written = 0;
			else
				return -1;
		}

		num_left = num_left - num_written;	/* reduce the number of bytes left to write */
		buf_index = buf_index + num_written;	/* move the index into the buffer for the next write */
	}
	return(tot_len);				/* return the number of bytes written */
}

/* */
