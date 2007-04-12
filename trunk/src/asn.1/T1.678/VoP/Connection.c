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

#include "Connection.h"

static asn_TYPE_member_t asn_MBR_callId_5[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_CallIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_callId_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_callId_specs_5 = {
	sizeof(struct Connection__callId),
	offsetof(struct Connection__callId, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_callId_5 = {
	"callId",
	"callId",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_callId_tags_5,
	sizeof(asn_DEF_callId_tags_5)
		/sizeof(asn_DEF_callId_tags_5[0]) - 1, /* 1 */
	asn_DEF_callId_tags_5,	/* Same as above */
	sizeof(asn_DEF_callId_tags_5)
		/sizeof(asn_DEF_callId_tags_5[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_callId_5,
	1,	/* Single element */
	&asn_SPC_callId_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_connectedParties_7[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_PartyIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_connectedParties_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_connectedParties_specs_7 = {
	sizeof(struct Connection__connectedParties),
	offsetof(struct Connection__connectedParties, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_connectedParties_7 = {
	"connectedParties",
	"connectedParties",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_connectedParties_tags_7,
	sizeof(asn_DEF_connectedParties_tags_7)
		/sizeof(asn_DEF_connectedParties_tags_7[0]) - 1, /* 1 */
	asn_DEF_connectedParties_tags_7,	/* Same as above */
	sizeof(asn_DEF_connectedParties_tags_7)
		/sizeof(asn_DEF_connectedParties_tags_7[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_connectedParties_7,
	1,	/* Single element */
	&asn_SPC_connectedParties_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_newParties_9[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_PartyIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_newParties_tags_9[] = {
	(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_newParties_specs_9 = {
	sizeof(struct Connection__newParties),
	offsetof(struct Connection__newParties, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_newParties_9 = {
	"newParties",
	"newParties",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_newParties_tags_9,
	sizeof(asn_DEF_newParties_tags_9)
		/sizeof(asn_DEF_newParties_tags_9[0]) - 1, /* 1 */
	asn_DEF_newParties_tags_9,	/* Same as above */
	sizeof(asn_DEF_newParties_tags_9)
		/sizeof(asn_DEF_newParties_tags_9[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_newParties_9,
	1,	/* Single element */
	&asn_SPC_newParties_specs_9	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_signalingMsg_13[] = {
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
static ber_tlv_tag_t asn_DEF_signalingMsg_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_signalingMsg_specs_13 = {
	sizeof(struct Connection__signalingMsg),
	offsetof(struct Connection__signalingMsg, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_signalingMsg_13 = {
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
	asn_DEF_signalingMsg_tags_13,
	sizeof(asn_DEF_signalingMsg_tags_13)
		/sizeof(asn_DEF_signalingMsg_tags_13[0]) - 1, /* 1 */
	asn_DEF_signalingMsg_tags_13,	/* Same as above */
	sizeof(asn_DEF_signalingMsg_tags_13)
		/sizeof(asn_DEF_signalingMsg_tags_13[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_signalingMsg_13,
	1,	/* Single element */
	&asn_SPC_signalingMsg_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_Connection_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Connection, caseId),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CaseIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"caseId"
		},
	{ ATF_POINTER, 1, offsetof(struct Connection, iAPSystemId),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IAPSystemIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"iAPSystemId"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Connection, timestamp),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeStamp,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"timestamp"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Connection, callId),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_callId_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"callId"
		},
	{ ATF_POINTER, 5, offsetof(struct Connection, connectedParties),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		0,
		&asn_DEF_connectedParties_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"connectedParties"
		},
	{ ATF_POINTER, 4, offsetof(struct Connection, newParties),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		0,
		&asn_DEF_newParties_9,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"newParties"
		},
	{ ATF_POINTER, 3, offsetof(struct Connection, connectedMedia),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MediaInformation,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"connectedMedia"
		},
	{ ATF_POINTER, 2, offsetof(struct Connection, protocolSpecificParameters),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ProtocolSpecificParameters,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"protocolSpecificParameters"
		},
	{ ATF_POINTER, 1, offsetof(struct Connection, signalingMsg),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		0,
		&asn_DEF_signalingMsg_13,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"signalingMsg"
		},
};
static ber_tlv_tag_t asn_DEF_Connection_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_Connection_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* caseId at 129 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* iAPSystemId at 130 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timestamp at 131 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* callId at 132 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* connectedParties at 135 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* newParties at 136 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* connectedMedia at 137 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* protocolSpecificParameters at 138 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 } /* signalingMsg at 139 */
};
static asn_SEQUENCE_specifics_t asn_SPC_Connection_specs_1 = {
	sizeof(struct Connection),
	offsetof(struct Connection, _asn_ctx),
	asn_MAP_Connection_tag2el_1,
	9,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Connection = {
	"Connection",
	"Connection",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_Connection_tags_1,
	sizeof(asn_DEF_Connection_tags_1)
		/sizeof(asn_DEF_Connection_tags_1[0]), /* 1 */
	asn_DEF_Connection_tags_1,	/* Same as above */
	sizeof(asn_DEF_Connection_tags_1)
		/sizeof(asn_DEF_Connection_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Connection_1,
	9,	/* Elements count */
	&asn_SPC_Connection_specs_1	/* Additional specs */
};
