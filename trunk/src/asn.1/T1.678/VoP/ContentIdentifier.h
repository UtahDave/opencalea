/*
 * This file is autogenerated by the ASN.1 compiler.
 * Copyright (c) 2003-2007 Lev Walkin <vlm@lionet.info>
 * See http://lionet.info/asn1c
 *
 * Source ASN.1 file is Copyright (c) by US CALEA, included
 * with permission (if included). <<< this depends on whether
 * or not you include the original ASN.1 file into OpenCALEA >>>
 *
 * This file is part of OpenCALEA suite (http://opencalea.org)
 * and is subject to OpenCALEA license (see COPYING file in the
 * root of the opencalea distribution).
 *
 * Copyright (c) 2007 Norman Brandinger <norm@goes.com>
 *
 */

/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "T1S1-LAES-VoP-Abstract-Syntax-Module"
 * 	found in "T1S1-LAES-VoP-Abstract-Syntax-Module.asn"
 * 	`asn1c -fnative-types`
 */

#ifndef	_ContentIdentifier_H_
#define	_ContentIdentifier_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CorrelationIdentifier.h"
#include "CallIdentity.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ContentIdentifier_PR {
	ContentIdentifier_PR_NOTHING,	/* No components present */
	ContentIdentifier_PR_correlationID,
	ContentIdentifier_PR_callID
} ContentIdentifier_PR;

/* ContentIdentifier */
typedef struct ContentIdentifier {
	ContentIdentifier_PR present;
	union ContentIdentifier_u {
		CorrelationIdentifier_t	 correlationID;
		CallIdentity_t	 callID;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ContentIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ContentIdentifier;

#ifdef __cplusplus
}
#endif

#endif	/* _ContentIdentifier_H_ */
