/*
 * Copyright (c) 2007 Norman Brandinger <norm@goes.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_UTF8String_H_
#define	_UTF8String_H_

#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t UTF8String_t;	/* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t asn_DEF_UTF8String;

asn_struct_print_f UTF8String_print;
asn_constr_check_f UTF8String_constraint;

/*
 * Returns length of the given UTF-8 string in characters,
 * or a negative error code:
 * -1:	UTF-8 sequence truncated 
 * -2:	Illegal UTF-8 sequence start
 * -3:	Continuation expectation failed
 * -4:	Not minimal length encoding
 * -5:	Invalid arguments
 */
ssize_t UTF8String_length(const UTF8String_t *st);

/*
 * Convert the UTF-8 string into a sequence of wide characters.
 * Returns the number of characters necessary.
 * Returned value might be greater than dstlen.
 * In case of conversion error, 0 is returned.
 * 
 * If st points to a valid UTF-8 string, calling
 * 	UTF8String_to_wcs(st, 0, 0);
 * is equivalent to
 * 	UTF8String_length(const UTF8String_t *st);
 */
size_t UTF8String_to_wcs(const UTF8String_t *st, uint32_t *dst, size_t dstlen);

#ifdef __cplusplus
}
#endif

#endif	/* _UTF8String_H_ */
