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
 * From ASN.1 module "IAS-LAES-CmII-Optional-Messages-Abstract-Syntax-Module"
 * 	found in "IAS-LAES-CmII-Optional-Messages-Abstract-Syntax-Module.asn"
 * 	`asn1c -fnative-types`
 */

#ifndef	_SessionIdentity_H_
#define	_SessionIdentity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <UTF8String.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SessionIdentity */
typedef UTF8String_t	 SessionIdentity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SessionIdentity;
asn_struct_free_f SessionIdentity_free;
asn_struct_print_f SessionIdentity_print;
asn_constr_check_f SessionIdentity_constraint;
ber_type_decoder_f SessionIdentity_decode_ber;
der_type_encoder_f SessionIdentity_encode_der;
xer_type_decoder_f SessionIdentity_decode_xer;
xer_type_encoder_f SessionIdentity_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _SessionIdentity_H_ */
