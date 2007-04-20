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

#include <asn_internal.h>

#include "IasProtocol.h"

static asn_TYPE_member_t asn_MBR_IasProtocol_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IasProtocol, protocolIdentifier),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		0,
		&asn_DEF_IAS_LAES_CmII_Abstract_Syntax_Module_OID,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"protocolIdentifier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IasProtocol, iasMessage),
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_IasMessage,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"iasMessage"
		},
};
static ber_tlv_tag_t asn_DEF_IasProtocol_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_IasProtocol_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 }, /* protocolIdentifier at 11 */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* access-Attempt at 16 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* access-Accepted at 17 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 1, 0, 0 }, /* access-Failed at 18 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 1, 0, 0 }, /* access-Session-End at 19 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 1, 0, 0 }, /* access-Rejected at 20 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 1, 0, 0 }, /* access-Signaling-Message-Report at 21 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 1, 0, 0 }, /* session-Start at 22 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 1, 0, 0 }, /* session-Failed at 23 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 1, 0, 0 }, /* session-End at 24 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 1, 0, 0 }, /* session-Already-Established at 25 */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 1, 0, 0 }, /* data-Header-Report at 26 */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 1, 0, 0 } /* data-Summary-Report at 28 */
};
static asn_SEQUENCE_specifics_t asn_SPC_IasProtocol_specs_1 = {
	sizeof(struct IasProtocol),
	offsetof(struct IasProtocol, _asn_ctx),
	asn_MAP_IasProtocol_tag2el_1,
	13,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_IasProtocol = {
	"IasProtocol",
	"IasProtocol",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_IasProtocol_tags_1,
	sizeof(asn_DEF_IasProtocol_tags_1)
		/sizeof(asn_DEF_IasProtocol_tags_1[0]), /* 1 */
	asn_DEF_IasProtocol_tags_1,	/* Same as above */
	sizeof(asn_DEF_IasProtocol_tags_1)
		/sizeof(asn_DEF_IasProtocol_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_IasProtocol_1,
	2,	/* Elements count */
	&asn_SPC_IasProtocol_specs_1	/* Additional specs */
};
