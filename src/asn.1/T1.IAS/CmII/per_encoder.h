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
 * Copyright (c) 2006 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_PER_ENCODER_H_
#define	_PER_ENCODER_H_

#include <asn_application.h>
#include <per_support.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/*
 * Unaligned PER encoder of any ASN.1 type. May be invoked by the application.
 */
asn_enc_rval_t uper_encode(struct asn_TYPE_descriptor_s *type_descriptor,
	void *struct_ptr,	/* Structure to be encoded */
	asn_app_consume_bytes_f *consume_bytes_cb,	/* Data collector */
	void *app_key		/* Arbitrary callback argument */
);

/* A variant of uper_encode() which encodes data into the existing buffer */
asn_enc_rval_t uper_encode_to_buffer(
	struct asn_TYPE_descriptor_s *type_descriptor,
	void *struct_ptr,	/* Structure to be encoded */
	void *buffer,		/* Pre-allocated buffer */
	size_t buffer_size	/* Initial buffer size (max) */
);


/*
 * Type of the generic PER encoder function.
 */
typedef asn_enc_rval_t (per_type_encoder_f)(
	struct asn_TYPE_descriptor_s *type_descriptor,
	asn_per_constraints_t *constraints,
	void *struct_ptr,
	asn_per_outp_t *per_output
);

#ifdef __cplusplus
}
#endif

#endif	/* _PER_ENCODER_H_ */
