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

#include <asn_internal.h>

#include "DirectSignalReporting.h"

static asn_TYPE_member_t asn_MBR_signalingMsg_7[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_EncapsulatedSignalingMessage,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_signalingMsg_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_signalingMsg_specs_7 = {
	sizeof(struct DirectSignalReporting__signalingMsg),
	offsetof(struct DirectSignalReporting__signalingMsg, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_signalingMsg_7 = {
	"signalingMsg",
	"signalingMsg",
	SET_OF_free,
	SET_OF_print,
	SET_OF_constraint,
	SET_OF_decode_ber,
	SET_OF_encode_der,
	SET_OF_decode_xer,
	SET_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_signalingMsg_tags_7,
	sizeof(asn_DEF_signalingMsg_tags_7)
		/sizeof(asn_DEF_signalingMsg_tags_7[0]) - 1, /* 1 */
	asn_DEF_signalingMsg_tags_7,	/* Same as above */
	sizeof(asn_DEF_signalingMsg_tags_7)
		/sizeof(asn_DEF_signalingMsg_tags_7[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_signalingMsg_7,
	1,	/* Single element */
	&asn_SPC_signalingMsg_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_DirectSignalReporting_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DirectSignalReporting, caseId),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CaseIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"caseId"
		},
	{ ATF_POINTER, 1, offsetof(struct DirectSignalReporting, iAPSystemId),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IAPSystemIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"iAPSystemId"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DirectSignalReporting, timestamp),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeStamp,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"timestamp"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DirectSignalReporting, correlationID),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CorrelationIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"correlationID"
		},
	{ ATF_POINTER, 1, offsetof(struct DirectSignalReporting, protocolSpecificParameters),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ProtocolSpecificParameters,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"protocolSpecificParameters"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DirectSignalReporting, signalingMsg),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		0,
		&asn_DEF_signalingMsg_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"signalingMsg"
		},
};
static ber_tlv_tag_t asn_DEF_DirectSignalReporting_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DirectSignalReporting_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* caseId at 181 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* iAPSystemId at 182 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timestamp at 183 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* correlationID at 184 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* protocolSpecificParameters at 185 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* signalingMsg at 187 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DirectSignalReporting_specs_1 = {
	sizeof(struct DirectSignalReporting),
	offsetof(struct DirectSignalReporting, _asn_ctx),
	asn_MAP_DirectSignalReporting_tag2el_1,
	6,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DirectSignalReporting = {
	"DirectSignalReporting",
	"DirectSignalReporting",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_DirectSignalReporting_tags_1,
	sizeof(asn_DEF_DirectSignalReporting_tags_1)
		/sizeof(asn_DEF_DirectSignalReporting_tags_1[0]), /* 1 */
	asn_DEF_DirectSignalReporting_tags_1,	/* Same as above */
	sizeof(asn_DEF_DirectSignalReporting_tags_1)
		/sizeof(asn_DEF_DirectSignalReporting_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DirectSignalReporting_1,
	6,	/* Elements count */
	&asn_SPC_DirectSignalReporting_specs_1	/* Additional specs */
};

