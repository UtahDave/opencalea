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
 * From ASN.1 module "T1S1-LAES-VoP-Abstract-Syntax-Module"
 * 	found in "T1S1-LAES-VoP-Abstract-Syntax-Module.asn"
 * 	`asn1c -funnamed-unions -findirect-choice -fbless-SIZE -fcompound-names -fnative-types`
 */

#ifndef	_DeliveryIdentifier_H_
#define	_DeliveryIdentifier_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DeliveryIdentifier_PR {
	DeliveryIdentifier_PR_NOTHING,	/* No components present */
	DeliveryIdentifier_PR_cccId,
	DeliveryIdentifier_PR_ccAddress
} DeliveryIdentifier_PR;

/* Forward declarations */
struct CCCIdentity;
struct CCAddress;

/* DeliveryIdentifier */
typedef struct DeliveryIdentifier {
	DeliveryIdentifier_PR present;
	union {
		struct CCCIdentity	*cccId;
		struct CCAddress	*ccAddress;
	};
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DeliveryIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DeliveryIdentifier;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CCCIdentity.h"
#include "CCAddress.h"

#endif	/* _DeliveryIdentifier_H_ */
