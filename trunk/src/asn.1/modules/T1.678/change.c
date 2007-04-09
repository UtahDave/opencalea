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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "LAESProtocol.h"

#define LAES_CHANGE(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.change.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int change(FILE *fp) {

  LAESProtocol_t *LAESProtocol;

  char caseId[] = "Change CaseID";
  char iAPSystemId[] = "Change SystemID";
  time_t rawtime;
  struct tm *timestamp;
  DeliveryIdentifier_t          *deliveryIdentifier;
  ProtocolSpecificParameters_t	*protocolSpecificParameters;
  struct Change__signalingMsg	*signalingMsg;

  CallIdentity_t		*CallID1, *CallID2, *CallID3, *CallID4;

  IpAddress_t *IPAddress1, *IPAddress2;

  SipHeader_t *SipHeader, *SipBodyHeader;
  SipHeader_t *SipFromHeader;
  SipHeader_t *SipToHeader;
  SipHeader_t *SipViaHeader;
  SipHeader_t *SipContactHeader;
  SipHeader_t *SipHeaderArray[10];
  A_SET_OF(SipHeader_t) *SipHeaders, *SipBodyHeaders;

  A_SET_OF(CallIdentity_t) *CallIDs_previous, *CallIDs_resulting;

  struct ProtocolSpecificParameters__sip__sipBody *SipBody;
  EncapsulatedSignalingMessage_t *ESM1, *ESM2;

  CCCIdentity_t *cccId;
  CCAddress_t *ccAddress;

  int oid[] = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };

  char *sip_data[] = {"1111","2222","3333","4444","5555","6666","7777","8888","9999","0000"};

  int frac_value = 1234;
  int frac_digits = 4;
  int force_gmt = 1;
  int ret;
  int i;

  asn_enc_rval_t ec;      /* Encoder return value  */

  time ( &rawtime );
  timestamp = gmtime ( &rawtime );

  LAESProtocol = calloc(1, sizeof(LAESProtocol_t));
  if(!LAESProtocol) {
    perror("LAESProtocol calloc() failed");
    exit(-1);
  }

  ESM1 = calloc(1, sizeof(EncapsulatedSignalingMessage_t));
  ESM2 = calloc(1, sizeof(EncapsulatedSignalingMessage_t));

  cccId = calloc(1, sizeof(CCCIdentity_t));
  if(!cccId) {
    perror("cccId calloc() failed");
    exit(-1);
  }

  ccAddress = calloc(1, sizeof(CCAddress_t));
  if(!ccAddress) {
    perror("ccAddress calloc() failed");
    exit(-1);
  }

  CallIDs_previous = calloc(1, sizeof(A_SET_OF(CallIdentity_t)));
  if(!CallIDs_previous) {
    perror("CallIDs_previous calloc() failed");
    exit(-1);
  }

  CallIDs_resulting = calloc(1, sizeof(A_SET_OF(CallIdentity_t)));
  if(!CallIDs_resulting) {
    perror("CallIDs_resulting calloc() failed");
    exit(-1);
  }

  SipHeaders = calloc(1, sizeof(A_SET_OF(SipHeader_t)));
  if(!SipHeaders) {
    perror("SipHeaders calloc() failed");
    exit(-1);
  }

  SipBodyHeaders = calloc(1, sizeof(A_SET_OF(SipHeader_t)));
  if(!SipBodyHeaders) {
    perror("SipBodyHeaders calloc() failed");
    exit(-1);
  }

  SipBody = calloc(1, sizeof(struct ProtocolSpecificParameters__sip__sipBody));
  if(!SipBody) {
    perror("SipBody calloc() failed");
    exit(-1);
  }

  protocolSpecificParameters = calloc(1, sizeof(ProtocolSpecificParameters_t));
  if (!protocolSpecificParameters) {
    perror("protocolSpecificParameters calloc() failed");
    exit(-1);
  }

  CallID1 = calloc(1, sizeof(CallIdentity_t));
  if (!CallID1) {
    perror("CallID1 calloc() failed");
    exit(-1);
  }

  CallID2 = calloc(1, sizeof(CallIdentity_t));
  if (!CallID2) {
    perror("CallID2 calloc() failed");
    exit(-1);
  }

  CallID3 = calloc(1, sizeof(CallIdentity_t));
  if (!CallID3) {
    perror("CallID3 calloc() failed");
    exit(-1);
  }

  CallID4 = calloc(1, sizeof(CallIdentity_t));
  if (!CallID4) {
    perror("CallID4 calloc() failed");
    exit(-1);
  }

  deliveryIdentifier = calloc(1, sizeof(DeliveryIdentifier_t));
  if (!deliveryIdentifier) {
    perror("deliveryIdentifier calloc() failed");
    exit(-1);
  }

  IPAddress1 = calloc(1, sizeof(IpAddress_t));
  IPAddress2 = calloc(1, sizeof(IpAddress_t));

  signalingMsg = calloc(1, sizeof(struct Change__signalingMsg));
  if (!signalingMsg) {
    perror("signalingMsg calloc() failed");
    exit(-1);
  }

  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
  OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0])); 

  /* Laes_Message */
  LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_change;

  /* caseId */
  OCTET_STRING_fromString(&LAES_CHANGE(caseId), caseId);

  /* iAPSystemId */
  LAES_CHANGE(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, iAPSystemId, strlen(iAPSystemId));;

  /* timestamp */
  asn_time2GT_frac(&LAES_CHANGE(timestamp),timestamp,frac_value, frac_digits, force_gmt);

  /* call_identities */
  callidentity(CallID1, "Change CallID1 MAIN", "Change CallID1 LEG");
  callidentity(CallID2, "Change CallID2 MAIN", "Change CallID2 LEG");
  callidentity(CallID3, "Change CallID3 MAIN", "Change CallID3 LEG");
  callidentity(CallID4, "Change CallID4 MAIN", "Change CallID4 LEG");
  asn_set_add(CallIDs_previous, CallID1);
  asn_set_add(CallIDs_previous, CallID2);
  memcpy(&LAES_CHANGE(previous).call_identities, CallIDs_previous, sizeof(CallIdentity_t));
  asn_set_add(CallIDs_resulting, CallID3);
  asn_set_add(CallIDs_resulting, CallID4);
  memcpy(&LAES_CHANGE(resulting).call_identities, CallIDs_resulting, sizeof(CallIdentity_t));

  /* deliveryIdentifier */
  //deliveryIdentifier->present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_combCCC;
  //OCTET_STRING_fromString(&cccId->choice.combCCC, "User Data combCCC");
  //memcpy(&deliveryIdentifier->choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryIdentifier->present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_sepCCCpair;
  //OCTET_STRING_fromString(&cccId->choice.sepCCCpair.sepXmitCCC, "User Data sepXmitCCC");
  //OCTET_STRING_fromString(&cccId->choice.sepCCCpair.sepRecvCCC, "User Data sepRecvCCC");
  //memcpy(&deliveryIdentifier->choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryIdentifier->present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indXmitCCC;
  //OCTET_STRING_fromString(&cccId->choice.indXmitCCC, "User Data indXmitCCC");
  //memcpy(&deliveryIdentifier->choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryIdentifier->present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indRecvCCC;
  //OCTET_STRING_fromString(&cccId->choice.indRecvCCC, "User Data indRecvCCC");
  //memcpy(&deliveryIdentifier->choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryIdentifier->present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indCCC;
  //OCTET_STRING_fromString(&cccId->choice.indCCC, "User Data indCCC");
  //memcpy(&deliveryIdentifier->choice.cccId, cccId, sizeof(CCCIdentity_t));

  deliveryIdentifier->present = DeliveryIdentifier_PR_ccAddress;
  ipaddress(&ccAddress->leaIPAddress, "111.111.111.111");
  ccAddress->leaPortNumber = 5222;
  memcpy(&deliveryIdentifier->choice.ccAddress, ccAddress, sizeof(CCAddress_t));

  LAES_CHANGE(resulting).deliveryIdentifier = deliveryIdentifier;

  /* protocolSpecificParameters */
  protocolSpecificParameters->present = ProtocolSpecificParameters_PR_sip;

  SipFromHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "From", 4);
  asn_set_add(SipHeaders, SipFromHeader);
  SipToHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "To", 2);
  asn_set_add(SipHeaders, SipToHeader);
  SipViaHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Via", 3);
  asn_set_add(SipHeaders, SipViaHeader);
  SipContactHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Contact", 7);
  asn_set_add(SipHeaders, SipContactHeader);

  for (i=0; i<4; i++) {
    SipHeaderArray[i] = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_data[i], strlen(sip_data[i]));
    asn_set_add(SipHeaders, SipHeaderArray[i]);
  }

  protocolSpecificParameters->choice.sip.sipHeader = SipHeaders;

  for (i=4; i<6; i++) {
    SipHeaderArray[i] = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_data[i], strlen(sip_data[i]));
    asn_set_add(SipBodyHeaders, SipHeaderArray[i]);
  }

  memcpy(&SipBody->sipBodyHeader.list, SipBodyHeaders, sizeof(A_SET_OF(SipHeader_t)));
  OCTET_STRING_fromString(&SipBody->sipBodyContents, "SIP BODY CONTENTS");
  protocolSpecificParameters->choice.sip.sipBody = SipBody;

  LAES_CHANGE(protocolSpecificParameters) = protocolSpecificParameters;

  /* signalingMsg */
  encapsulatedsignalingmessage(ESM1,"MimeType 1", "test message 1");
  asn_set_add(signalingMsg, ESM1);

  encapsulatedsignalingmessage(ESM2,"MimeType 2", "test message 2");
  asn_set_add(signalingMsg, ESM2);

  LAES_CHANGE(signalingMsg) = signalingMsg;

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Change message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
