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

#include <asn_application.h>
#include <asn_internal.h>
#include <per_decoder.h>

asn_dec_rval_t
uper_decode(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td, void **sptr, const void *buffer, size_t size, int skip_bits, int unused_bits) {
	asn_codec_ctx_t s_codec_ctx;
	asn_dec_rval_t rval;
	asn_per_data_t pd;

	if(skip_bits < 0 || skip_bits > 7
	|| unused_bits < 0 || unused_bits > 7
	|| (unused_bits > 0 && !size))
		_ASN_DECODE_FAILED;

	/*
	 * Stack checker requires that the codec context
	 * must be allocated on the stack.
	 */
	if(opt_codec_ctx) {
		if(opt_codec_ctx->max_stack_size) {
			s_codec_ctx = *opt_codec_ctx;
			opt_codec_ctx = &s_codec_ctx;
		}
	} else {
		/* If context is not given, be security-conscious anyway */
		memset(&s_codec_ctx, 0, sizeof(s_codec_ctx));
		s_codec_ctx.max_stack_size = _ASN_DEFAULT_STACK_MAX;
		opt_codec_ctx = &s_codec_ctx;
	}

	/* Fill in the position indicator */
	pd.buffer = (const uint8_t *)buffer;
	pd.nboff = skip_bits;
	pd.nbits = 8 * size - unused_bits; /* 8 is CHAR_BIT from <limits.h> */
	if(pd.nboff > pd.nbits)
		_ASN_DECODE_FAILED;

	/*
	 * Invoke type-specific decoder.
	 */
	if(!td->uper_decoder)
		_ASN_DECODE_FAILED;	/* PER is not compiled in */
	rval = td->uper_decoder(opt_codec_ctx, td, 0, sptr, &pd);
	if(rval.code == RC_OK) {
		/* Return the number of consumed bits */
		rval.consumed = ((pd.buffer - (const uint8_t *)buffer) << 3)
					+ pd.nboff - skip_bits;
	} else {
		/* PER codec is not a restartable */
		rval.consumed = 0;
	}
	return rval;
}

