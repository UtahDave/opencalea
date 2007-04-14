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

#include "asn_internal.h"
#include "constraints.h"

int
asn_generic_no_constraint(asn_TYPE_descriptor_t *type_descriptor,
	const void *struct_ptr, asn_app_constraint_failed_f *cb, void *key) {

	(void)type_descriptor;	/* Unused argument */
	(void)struct_ptr;	/* Unused argument */
	(void)cb;	/* Unused argument */
	(void)key;	/* Unused argument */

	/* Nothing to check */
	return 0;
}

int
asn_generic_unknown_constraint(asn_TYPE_descriptor_t *type_descriptor,
	const void *struct_ptr, asn_app_constraint_failed_f *cb, void *key) {

	(void)type_descriptor;	/* Unused argument */
	(void)struct_ptr;	/* Unused argument */
	(void)cb;	/* Unused argument */
	(void)key;	/* Unused argument */

	/* Unknown how to check */
	return 0;
}

struct errbufDesc {
	asn_TYPE_descriptor_t *failed_type;
	const void *failed_struct_ptr;
	char *errbuf;
	size_t errlen;
};

static void
_asn_i_ctfailcb(void *key, asn_TYPE_descriptor_t *td, const void *sptr, const char *fmt, ...) {
	struct errbufDesc *arg = key;
	va_list ap;
	ssize_t vlen;
	ssize_t maxlen;

	arg->failed_type = td;
	arg->failed_struct_ptr = sptr;

	maxlen = arg->errlen;
	if(maxlen <= 0)
		return;

	va_start(ap, fmt);
	vlen = vsnprintf(arg->errbuf, maxlen, fmt, ap);
	va_end(ap);
	if(vlen >= maxlen) {
		arg->errbuf[maxlen-1] = '\0';	/* Ensuring libc correctness */
		arg->errlen = maxlen - 1;	/* Not counting termination */
		return;
	} else if(vlen >= 0) {
		arg->errbuf[vlen] = '\0';	/* Ensuring libc correctness */
		arg->errlen = vlen;		/* Not counting termination */
	} else {
		/*
		 * The libc on this system is broken.
		 */
		vlen = sizeof("<broken vsnprintf>") - 1;
		maxlen--;
		arg->errlen = vlen < maxlen ? vlen : maxlen;
		memcpy(arg->errbuf, "<broken vsnprintf>", arg->errlen);
		arg->errbuf[arg->errlen] = 0;
	}

	return;
}

int
asn_check_constraints(asn_TYPE_descriptor_t *type_descriptor,
		const void *struct_ptr, char *errbuf, size_t *errlen) {
	struct errbufDesc arg;
	int ret;

	arg.failed_type = 0;
	arg.failed_struct_ptr = 0;
	arg.errbuf = errbuf;
	arg.errlen = errlen ? *errlen : 0;

	ret = type_descriptor->check_constraints(type_descriptor,
		struct_ptr, _asn_i_ctfailcb, &arg);
	if(ret == -1 && errlen)
		*errlen = arg.errlen;

	return ret;
}

