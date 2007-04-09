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

#ifndef	_H225CallSignaling_H_
#define	_H225CallSignaling_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* H225CallSignaling */
typedef OCTET_STRING_t	 H225CallSignaling_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_H225CallSignaling;
asn_struct_free_f H225CallSignaling_free;
asn_struct_print_f H225CallSignaling_print;
asn_constr_check_f H225CallSignaling_constraint;
ber_type_decoder_f H225CallSignaling_decode_ber;
der_type_encoder_f H225CallSignaling_encode_der;
xer_type_decoder_f H225CallSignaling_decode_xer;
xer_type_encoder_f H225CallSignaling_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _H225CallSignaling_H_ */
