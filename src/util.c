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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR OR CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "log_debug.h"


/* Helper Routines */

void *Calloc(size_t size) {
  char *ptr;
  ptr = calloc(1, size);
  if(!ptr) {
    pdie("calloc");
  }
  return ptr;
}


/* Note: you need to free() the pointer returned yourself */
void *Strdup ( const char *format, ... ) {
    va_list ap;
    char *ptr;

    va_start( ap, format );
    if (vasprintf(&ptr, format, ap) == -1)
        pdie("Strdup: vasprintf");
    va_end( ap );

    if(!ptr) {
        pdie("Strdup: vasprintf");
    }

    return ptr;
}



/* Config management routines */

/* Allocate space for a Config structure */
Config *configalloc(void) {
    return (Config *) Calloc( sizeof(Config) );
}

/* Add a config item to the tree */
Config *add_config_item(Config *p, char *key, char *val) {
    int cond, i;
    char **oldvalue;

    if (p == NULL) {
        debug_5 ("add_config_item: adding %s = %s", key, val);
        p = configalloc();
        p->key = Strdup( key );
        p->num = 0;
        p->value = Calloc( sizeof(char *) * 2 );
        p->value[p->num++] = Strdup( val );
        p->value[p->num] = NULL;      /* NULL terminate */
        p->nextval = p->value;
        p->left = p->right = NULL;
    } else if ((cond = strcmp(key, p->key)) == 0) {
        debug_5 ("add_config_item: adding %s = %s", key, val);
        oldvalue = p->value;
        p->value = Calloc( sizeof(char *) * (p->num + 2) );
        for (i=0; i < p->num; i++)
            p->value[i] = oldvalue[i];
        p->value[p->num++] = Strdup( val );
        p->value[p->num] = NULL;      /* NULL terminate */
        if (oldvalue)
            free(oldvalue);
    } else if (cond < 0)
        p->left = add_config_item(p->left, key, val);
    else
        p->right = add_config_item(p->right, key, val);

    return p;
}

/* Update a config item in the tree */
Config *set_config_item(Config *p, char *key, char *val) {
    int cond, i;

    if (p == NULL) {
        debug_5 ("set_config_item: setting %s via add_config_item", key);
        return add_config_item(p, key, val);
    } else if ((cond = strcmp(key, p->key)) == 0) {
        debug_5 ("set_config_item: setting %s = %s", key, val);
        if (p->value) {
            for (i=0; i <= p->num; i++)
                free(p->value[i]);
            free(p->value);
        }
        p->num=0;
        p->value = Calloc( sizeof(char *) );
        p->value[p->num++] = Strdup( val );
        p->value[p->num] = NULL;      /* NULL terminate */
        p->nextval = p->value;
        return p;
    } else if (cond < 0)
        return set_config_item(p->left, key, val);
    else
        return set_config_item(p->right, key, val);
}

/* Delete a config item from the tree */
void del_config_item(Config *p, char *key) {
    int cond, i;

    if (p == NULL)
        return;
    else if ((cond = strcmp(key, p->key)) == 0) {
        debug_5 ("del_config_item: deleting %s", key);
        if (p->value) {
            for (i=0; i <= p->num; i++)
                free(p->value[i]);
            free(p->value);
        }
        p->num=0;
        p->value=NULL;
        p->nextval=NULL;
        return;
    } else if (cond < 0)
        return del_config_item(p->left, key);
    else
        return del_config_item(p->right, key);
}

/* Search for a config item in the tree */
Config *get_config(Config *p, char *key) {
    int cond;

    if (p == NULL)
        return (Config *)NULL;
    else if ((cond = strcmp(key, p->key)) == 0) {
        debug_5 ("get_config: found %s with %i values", key, p->num);
        if (p->value) {
            p->nextval=p->value;
            return p;
        } else
            return (Config *)NULL;
    } else if (cond < 0)
        return get_config(p->left, key);
    else
        return get_config(p->right, key);
}


/* parse_config: parse a config file into a Config tree */
/* returns < 0 for fatal error, > 0 for non-fatal */
int parse_config(Config *cfg, char *section, char *file) {
    GKeyFile* gkeyfile;
    GError *gerror = NULL;
    char **key = NULL;
    char **keys = NULL;
    char **keyptr = NULL;
    char **keysptr = NULL;

    gkeyfile = g_key_file_new ( );
    debug_4("parsing config file: %s", file);
    if ( !g_key_file_load_from_file ( gkeyfile, file, 
           G_KEY_FILE_KEEP_COMMENTS, &gerror) ) {
        log_2 ( "g_key_file_load_from_file(%s): %s", file, gerror->message );
        debug_2 ( "g_key_file_load_from_file(%s): %s", file, gerror->message );
        g_error_free ( gerror );
        g_key_file_free ( gkeyfile );
        return 1;
    } else {
        g_key_file_set_list_separator(gkeyfile, (gchar)',');
        debug_5("parse_config: reading keys from %s section [%s]", file, section);
        keys = g_key_file_get_keys ( gkeyfile, section, NULL, &gerror );
        if (keys == NULL) {
            error ("g_get_file_get_keys(%s): %s", file, gerror->message);
            g_error_free ( gerror );
            g_key_file_free ( gkeyfile );
            return 2;
        }
        for (keysptr=keys; *keysptr; keysptr++) {
            debug_5 ("parse_config: reading key %s", *keysptr);
            if ( (key = g_key_file_get_string_list(gkeyfile,
                section, *keysptr, NULL, &gerror)) == NULL ) {
                error ("g_key_file_get_string_list(%s): %s", *keysptr, gerror->message);
                g_error_free ( gerror );
                g_strfreev(keys);
                g_key_file_free ( gkeyfile );
                return 3;
            }
            for (keyptr = key; *keyptr; keyptr++) {
                debug_5 ("parse_config: got %s value %s", *keysptr, *keyptr);
                if (keyptr == key)
                    set_config_item(cfg,*keysptr,*keyptr);  /* first item we set */
                else
                    add_config_item(cfg,*keysptr,*keyptr);  /* the rest we add */
            }
            g_strfreev(key);
        }
        g_strfreev ( keys );
        g_key_file_free ( gkeyfile );
    }

    return 0;
}



/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 * (copied/adapted from tcpdump)
 */
char *copy_argv(register char **argv) {
	register char **p;
	register u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)Calloc(len);

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
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

/**
 * Socket - create an endpoint for communication
 */
 
int Socket(int domain, int type, int protocol) {

	int fd;	/* socket file descriptor */

	fd = socket(domain, type, protocol);
	if (fd == -1) {
		debug_5("Socket error: %s", strerror(errno));
	}
	return fd;
}

/**
 * Connect - connect to a socket
 */

int Connect(int socket, const struct sockaddr *address, socklen_t address_len) {
  int rc;

  rc = connect(socket, address, address_len);
  if (!rc) {
		debug_5("Connect error: %s", strerror(errno));
  }
  return rc;
}

int Listen(int socket, int backlog) {

	int rc;
	rc = listen(socket, backlog);
	if (rc == -1) {
		debug_5("Listen error: %s", strerror(errno));
	}
	return rc;
}

/* */
