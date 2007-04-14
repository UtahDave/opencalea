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

#include <asn_internal.h>

#include "H324Caps.h"

static asn_TYPE_member_t asn_MBR_dataRatesSupported_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_DataRate,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_dataRatesSupported_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_dataRatesSupported_specs_4 = {
	sizeof(struct H324Caps__dataRatesSupported),
	offsetof(struct H324Caps__dataRatesSupported, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dataRatesSupported_4 = {
	"dataRatesSupported",
	"dataRatesSupported",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_dataRatesSupported_tags_4,
	sizeof(asn_DEF_dataRatesSupported_tags_4)
		/sizeof(asn_DEF_dataRatesSupported_tags_4[0]) - 1, /* 1 */
	asn_DEF_dataRatesSupported_tags_4,	/* Same as above */
	sizeof(asn_DEF_dataRatesSupported_tags_4)
		/sizeof(asn_DEF_dataRatesSupported_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_dataRatesSupported_4,
	1,	/* Single element */
	&asn_SPC_dataRatesSupported_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_supportedPrefixes_6[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_SupportedPrefix,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_supportedPrefixes_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_supportedPrefixes_specs_6 = {
	sizeof(struct H324Caps__supportedPrefixes),
	offsetof(struct H324Caps__supportedPrefixes, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supportedPrefixes_6 = {
	"supportedPrefixes",
	"supportedPrefixes",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_supportedPrefixes_tags_6,
	sizeof(asn_DEF_supportedPrefixes_tags_6)
		/sizeof(asn_DEF_supportedPrefixes_tags_6[0]) - 1, /* 1 */
	asn_DEF_supportedPrefixes_tags_6,	/* Same as above */
	sizeof(asn_DEF_supportedPrefixes_tags_6)
		/sizeof(asn_DEF_supportedPrefixes_tags_6[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_supportedPrefixes_6,
	1,	/* Single element */
	&asn_SPC_supportedPrefixes_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_H324Caps_1[] = {
	{ ATF_POINTER, 3, offsetof(struct H324Caps, nonStandardData),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NonStandardParameter,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"nonStandardData"
		},
	{ ATF_POINTER, 2, offsetof(struct H324Caps, dataRatesSupported),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_dataRatesSupported_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"dataRatesSupported"
		},
	{ ATF_POINTER, 1, offsetof(struct H324Caps, supportedPrefixes),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_supportedPrefixes_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"supportedPrefixes"
		},
};
static ber_tlv_tag_t asn_DEF_H324Caps_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_H324Caps_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nonStandardData at 1064 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dataRatesSupported at 1066 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* supportedPrefixes at 1068 */
};
static asn_SEQUENCE_specifics_t asn_SPC_H324Caps_specs_1 = {
	sizeof(struct H324Caps),
	offsetof(struct H324Caps, _asn_ctx),
	asn_MAP_H324Caps_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	0,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_H324Caps = {
	"H324Caps",
	"H324Caps",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_H324Caps_tags_1,
	sizeof(asn_DEF_H324Caps_tags_1)
		/sizeof(asn_DEF_H324Caps_tags_1[0]), /* 1 */
	asn_DEF_H324Caps_tags_1,	/* Same as above */
	sizeof(asn_DEF_H324Caps_tags_1)
		/sizeof(asn_DEF_H324Caps_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_H324Caps_1,
	3,	/* Elements count */
	&asn_SPC_H324Caps_specs_1	/* Additional specs */
};

