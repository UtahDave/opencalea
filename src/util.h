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

#ifndef _UTIL_H
#define _UTIL_H

/* binary tree for config settings */
typedef struct config_t {
    char *key;                         /* config item key (name) */
    int num;                           /* number of values currently set */
    char **value;
    char **nextval;                    /* pointer used to retrieve all values */
    struct config_t *left;
    struct config_t *right;
} Config;

Config *add_config_item(Config *, char *, char *);
Config *set_config_item(Config *, char *, char *);
void del_config_item(Config *, char *);
Config *get_config(Config *, char *);
int parse_config(Config *, char *, char *);

char *copy_argv(register char **);

#define CALLOC(parm) (parm *)Calloc(sizeof(parm))

void *Calloc(size_t);
void *Strdup ( const char *format, ... );
void print_hex(const u_char *, size_t);

int Socket(int domain, int type, int protocol);
int Connect(int socket, const struct sockaddr *address, socklen_t address_len);
int Bind(int socket, const struct sockaddr *address, socklen_t address_len);
int Listen(int socket, int backlog);
int Setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len);
struct addrinfo *Getaddrinfo1st(const char *hostname, int port, int family, int socktype);

#endif
