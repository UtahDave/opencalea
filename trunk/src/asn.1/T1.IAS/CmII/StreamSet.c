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
 * From ASN.1 module "IAS-LAES-CmII-Abstract-Syntax-Module"
 * 	found in "IAS-LAES-CmII-Abstract-Syntax-Module.asn"
 * 	`asn1c -fnative-types`
 */

#include <asn_internal.h>

#include "StreamSet.h"

static asn_TYPE_member_t asn_MBR_StreamSet_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct StreamSet, streamID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Value,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"streamID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct StreamSet, sourceIPaddress),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IPAddress,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"sourceIPaddress"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct StreamSet, destinationIPaddress),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IPAddress,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"destinationIPaddress"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct StreamSet, packetCount),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"packetCount"
		},
	{ ATF_POINTER, 2, offsetof(struct StreamSet, sourcePortNumber),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PortNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"sourcePortNumber"
		},
	{ ATF_POINTER, 1, offsetof(struct StreamSet, destinationPortNumber),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PortNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"destinationPortNumber"
		},
};
static ber_tlv_tag_t asn_DEF_StreamSet_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_StreamSet_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* streamID at 243 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sourceIPaddress at 244 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* destinationIPaddress at 245 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* packetCount at 246 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* sourcePortNumber at 247 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* destinationPortNumber at 248 */
};
static asn_SEQUENCE_specifics_t asn_SPC_StreamSet_specs_1 = {
	sizeof(struct StreamSet),
	offsetof(struct StreamSet, _asn_ctx),
	asn_MAP_StreamSet_tag2el_1,
	6,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_StreamSet = {
	"StreamSet",
	"StreamSet",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_StreamSet_tags_1,
	sizeof(asn_DEF_StreamSet_tags_1)
		/sizeof(asn_DEF_StreamSet_tags_1[0]), /* 1 */
	asn_DEF_StreamSet_tags_1,	/* Same as above */
	sizeof(asn_DEF_StreamSet_tags_1)
		/sizeof(asn_DEF_StreamSet_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_StreamSet_1,
	6,	/* Elements count */
	&asn_SPC_StreamSet_specs_1	/* Additional specs */
};

