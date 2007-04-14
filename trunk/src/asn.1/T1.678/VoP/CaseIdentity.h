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

#ifndef	_CaseIdentity_H_
#define	_CaseIdentity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <VisibleString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CaseIdentity */
typedef VisibleString_t	 CaseIdentity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CaseIdentity;
asn_struct_free_f CaseIdentity_free;
asn_struct_print_f CaseIdentity_print;
asn_constr_check_f CaseIdentity_constraint;
ber_type_decoder_f CaseIdentity_decode_ber;
der_type_encoder_f CaseIdentity_encode_der;
xer_type_decoder_f CaseIdentity_decode_xer;
xer_type_encoder_f CaseIdentity_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _CaseIdentity_H_ */
