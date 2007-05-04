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

/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "IAS-LAES-CmII-Abstract-Syntax-Module"
 * 	found in "IAS-LAES-CmII-Abstract-Syntax-Module.asn"
 * 	`asn1c -funnamed-unions -findirect-choice -fbless-SIZE -fcompound-names -fnative-types`
 */

#ifndef	_IPAddress_H_
#define	_IPAddress_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IpAddress.h"
#include <UTF8String.h>
#include <NativeInteger.h>
#include <NULL.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IPAddress__allocationMethod_PR {
	IPAddress__allocationMethod_PR_NOTHING,	/* No components present */
	IPAddress__allocationMethod_PR_static,
	IPAddress__allocationMethod_PR_dynamic,
	IPAddress__allocationMethod_PR_unknown,
	IPAddress__allocationMethod_PR_notApplicable
} IPAddress__allocationMethod_PR;

/* IPAddress */
typedef struct IPAddress {
	IpAddress_t	 address;
	struct IPAddress__allocationMethod {
		IPAddress__allocationMethod_PR present;
		union {
			NULL_t	 Static;
			NULL_t	 dynamic;
			NULL_t	 unknown;
			NULL_t	 notApplicable;
		};
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} allocationMethod;
	UTF8String_t	*iPv6FlowLabel	/* OPTIONAL */;
	long	*prefixLen	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IPAddress_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IPAddress;

#ifdef __cplusplus
}
#endif

#endif	/* _IPAddress_H_ */