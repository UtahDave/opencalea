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

#ifndef	_IAPSystemIdentity_H_
#define	_IAPSystemIdentity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <VisibleString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IAPSystemIdentity */
typedef VisibleString_t	 IAPSystemIdentity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IAPSystemIdentity;
asn_struct_free_f IAPSystemIdentity_free;
asn_struct_print_f IAPSystemIdentity_print;
asn_constr_check_f IAPSystemIdentity_constraint;
ber_type_decoder_f IAPSystemIdentity_decode_ber;
der_type_encoder_f IAPSystemIdentity_encode_der;
xer_type_decoder_f IAPSystemIdentity_decode_xer;
xer_type_encoder_f IAPSystemIdentity_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _IAPSystemIdentity_H_ */
