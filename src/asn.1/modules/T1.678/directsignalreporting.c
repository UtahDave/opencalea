/*-
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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "LAESProtocol.h"

#define CALLOC(parm) (parm *)Calloc(sizeof(parm))

void *Calloc(size_t size);

int directsignalreporting(FILE *fp) {

  LAESProtocol_t                 *LAESProtocol;
  EnhancedProtocol_t             *enhancedProtocol;
  ProtocolSpecificParameters_t	 *protocolSpecificParameters;
  DirectSignalReporting_t        *directSignalReporting;
  CorrelationIdentifier_t        *correlationIdentifier;
  EncapsulatedSignalingMessage_t *encapsulatedSignalingMessage;

  struct ProtocolSpecificParameters__sip            *psp_sip;
  struct ProtocolSpecificParameters__sip__sipHeader *psp_sipHeader;
  struct ProtocolSpecificParameters__sip__sipBody   *psp_sipBody;

  struct DirectSignalReporting__signalingMsg *signalingMsg;

  IpAddress_t *IPAddress1, *IPAddress2;

  SipHeader_t *SipHeader, *psp_sipBodyHeader;
  SipHeader_t *SipFromHeader;
  SipHeader_t *SipToHeader;
  SipHeader_t *SipViaHeader;
  SipHeader_t *SipContactHeader;
  SipHeader_t *SipHeaderArray[10];

  A_SET_OF(SipHeader_t) *SipHeaders, *psp_sipBodyHeaders;

  struct ProtocolSpecificParameters__sip__sipBody *SipBody;

  int oid[] = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };
  char caseId[]   = "DialedDigitExtraction CaseID";
  char systemID[] = "DialedDigitExtraction SystemID";

  char *sip_data[] = {"1111","2222","3333","4444","5555","6666","7777","8888","9999","0000"};
  char sip_header[] = "SIP HEADER";
  char sip_bodyheader[] = "SIP BODY HEADER";
  char sip_bodycontents[] = "SIP BODY CONTENTS";
  char sigprot[] = "Encaps Sig Prot";
  char sigmsg[] = "Encaps Sig Msg";

  int frac_value = 1234;
  int frac_digits = 4;
  int force_gmt = 1;
  int ret;
  int i;

  time_t rawtime;
  struct tm *timestamp;

  asn_enc_rval_t ec;      /* Encoder return value  */

  time ( &rawtime );
  timestamp = gmtime ( &rawtime );

  LAESProtocol                 = CALLOC(LAESProtocol_t);
  enhancedProtocol             = CALLOC(EnhancedProtocol_t);
  protocolSpecificParameters   = CALLOC(ProtocolSpecificParameters_t);
  directSignalReporting        = CALLOC(DirectSignalReporting_t);
  correlationIdentifier        = CALLOC(CorrelationIdentifier_t);
  encapsulatedSignalingMessage = CALLOC(EncapsulatedSignalingMessage_t);
  IPAddress1 		       = CALLOC(IpAddress_t);
  IPAddress2 		       = CALLOC(IpAddress_t);

  signalingMsg = CALLOC(struct DirectSignalReporting__signalingMsg);

  psp_sip          = CALLOC(struct ProtocolSpecificParameters__sip);
  psp_sipHeader    = CALLOC(struct ProtocolSpecificParameters__sip__sipHeader);
  psp_sipBody      = CALLOC(struct ProtocolSpecificParameters__sip__sipBody);

  SipHeaders = calloc(1, sizeof(A_SET_OF(SipHeader_t)));
  if(!SipHeaders) {
    perror("SipHeaders calloc() failed");
    exit(-1);
  }

  psp_sipBodyHeaders = calloc(1, sizeof(A_SET_OF(SipHeader_t)));
  if(!psp_sipBodyHeaders) {
    perror("psp_sipBodyHeaders calloc() failed");
    exit(-1);
  }

  SipBody = calloc(1, sizeof(struct ProtocolSpecificParameters__sip__sipBody));
  if(!SipBody) {
    perror("SipBody calloc() failed");
    exit(-1);
  }

  LAESProtocol->enhancedProtocol = enhancedProtocol;
  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;

  ret = OBJECT_IDENTIFIER_set_arcs(&enhancedProtocol->protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0]));
  assert(ret == 0);

  /* LAESMessage: DirectSignalReporting */
  enhancedProtocol->laesMessage.present = LaesMessage_PR_directSignalReporting;
  enhancedProtocol->laesMessage.directSignalReporting = directSignalReporting;

  /* caseId */
  OCTET_STRING_fromString(&directSignalReporting->caseId, caseId);

  /* iAPSystemId */
  directSignalReporting->iAPSystemId  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, systemID, strlen(systemID));;

  /* timestamp */
  asn_time2GT_frac(&directSignalReporting->timestamp,timestamp,frac_value, frac_digits, force_gmt);

  /* correlationID */
  OCTET_STRING_fromString(correlationIdentifier, "CorrelationID 1234");
  memcpy(&directSignalReporting->correlationID, correlationIdentifier, sizeof(CorrelationIdentifier_t));

  /* protocolSpecificParameters */
  protocolSpecificParameters->present = ProtocolSpecificParameters_PR_sip;

  /*------------------*/
  /* encode sipHeader */
  /*------------------*/
  SipHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_header, strlen(sip_header));
  asn_set_add(SipHeaders, SipHeader);
  asn_set_add(SipHeaders, SipHeader);
  asn_set_add(SipHeaders, SipHeader);

  memcpy(&psp_sipHeader->list, SipHeaders, sizeof(A_SET_OF(SipHeader_t)));

  psp_sip->sipHeader = psp_sipHeader;

  /*----------------------*/
  /* encode sipBodyHeader */
  /*----------------------*/

  psp_sipBodyHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_bodyheader, strlen(sip_bodyheader));

  asn_set_add(psp_sipBodyHeaders, psp_sipBodyHeader);
  asn_set_add(psp_sipBodyHeaders, psp_sipBodyHeader);
  asn_set_add(psp_sipBodyHeaders, psp_sipBodyHeader);

  memcpy(&psp_sipBody->sipBodyHeader.list, psp_sipBodyHeaders, sizeof(A_SET_OF(SipHeader_t)));
  OCTET_STRING_fromString(&psp_sipBody->sipBodyContents, "SIP BODY CONTENTS");
  psp_sip->sipBody = psp_sipBody;

  protocolSpecificParameters->sip = psp_sip;
  directSignalReporting->protocolSpecificParameters = protocolSpecificParameters;

  /* signalingMsg */
  OCTET_STRING_fromString(&encapsulatedSignalingMessage->signalingProt, sigprot);
  OCTET_STRING_fromString(&encapsulatedSignalingMessage->sigMsg, sigmsg);

  asn_set_add(signalingMsg, encapsulatedSignalingMessage);
  memcpy(&directSignalReporting->signalingMsg, signalingMsg, sizeof(struct DirectSignalReporting__signalingMsg));

  encode(fp, LAESProtocol);
  return 0;
}
