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
 * Copyright (c) 2003, 2005 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_INTEGER_H_
#define	_INTEGER_H_

#include <asn_application.h>
#include <asn_codecs_prim.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef ASN__PRIMITIVE_TYPE_t INTEGER_t;

extern asn_TYPE_descriptor_t asn_DEF_INTEGER;

/* Map with <tag> to integer value association */
typedef struct asn_INTEGER_enum_map_s {
	long		 nat_value;	/* associated native integer value */
	size_t		 enum_len;	/* strlen("tag") */
	const char	*enum_name;	/* "tag" */
} asn_INTEGER_enum_map_t;

/* This type describes an enumeration for INTEGER and ENUMERATED types */
typedef struct asn_INTEGER_specifics_s {
	asn_INTEGER_enum_map_t *value2enum;	/* N -> "tag"; sorted by N */
	unsigned int *enum2value;		/* "tag" => N; sorted by tag */
	int map_count;				/* Elements in either map */
	int extension;				/* This map is extensible */
	int strict_enumeration;			/* Enumeration set is fixed */
} asn_INTEGER_specifics_t;

asn_struct_print_f INTEGER_print;
ber_type_decoder_f INTEGER_decode_ber;
der_type_encoder_f INTEGER_encode_der;
xer_type_decoder_f INTEGER_decode_xer;
xer_type_encoder_f INTEGER_encode_xer;
per_type_decoder_f INTEGER_decode_uper;
per_type_encoder_f INTEGER_encode_uper;

/***********************************
 * Some handy conversion routines. *
 ***********************************/

/*
 * Returns 0 if it was possible to convert, -1 otherwise.
 * -1/EINVAL: Mandatory argument missing
 * -1/ERANGE: Value encoded is out of range for long representation
 * -1/ENOMEM: Memory allocation failed (in asn_long2INTEGER()).
 */
int asn_INTEGER2long(const INTEGER_t *i, long *l);
int asn_long2INTEGER(INTEGER_t *i, long l);

/*
 * Convert the integer value into the corresponding enumeration map entry.
 */
const asn_INTEGER_enum_map_t *INTEGER_map_value2enum(asn_INTEGER_specifics_t *specs, long value);

#ifdef __cplusplus
}
#endif

#endif	/* _INTEGER_H_ */
