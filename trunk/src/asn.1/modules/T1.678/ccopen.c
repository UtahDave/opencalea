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

#define LAES_CCOPEN(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.ccOpen.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int ccopen(FILE *fp) {

  LAESProtocol_t *LAESProtocol;

  ContentIdentifier_t		*contentIdentifier;
  DeliveryIdentifier_t		*deliveryIdentifier;
  CCDeliveryFormat_t		*ccDeliveryFormat;
  MediaInformation_t		*subjectMedia;
  MediaInformation_t		*associateMedia;
  ProtocolSpecificParameters_t	*protocolSpecificParameters;
  struct CCOpen__signalingMsg	*signalingMsg;

  IpAddress_t *IPAddress1, *IPAddress2;

  SipHeader_t *SipHeader, *SipBodyHeader;
  SipHeader_t *SipFromHeader;
  SipHeader_t *SipToHeader;
  SipHeader_t *SipViaHeader;
  SipHeader_t *SipContactHeader;
  SipHeader_t *SipHeaderArray[10];
  A_SET_OF(SipHeader_t) *SipHeaders, *SipBodyHeaders;

  struct ProtocolSpecificParameters__sip__sipBody *SipBody;
  EncapsulatedSignalingMessage_t *ESM1, *ESM2;
  CorrelationIdentifier_t *correlationID;
  CallIdentity_t *callID;
  CCCIdentity_t *cccId;
  CCAddress_t *ccAddress;

  int vop_oid[]        = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };
  int ccdelivery_oid[] = { 1, 2, 840, 113737, 2, 1, 0, 1, 1 };

  char caseId[]   = "CCOpen CaseID";
  char systemID[] = "CCOpen SystemID";

  char *sip_data[] = {"1111","2222","3333","4444","5555","6666","7777","8888","9999","0000"};

  int frac_value = 1234;
  int frac_digits = 4;
  int force_gmt = 1;
  int ret;
  int i;

  time_t rawtime;
  struct tm *ptm;

  asn_enc_rval_t ec;      /* Encoder return value  */

  time ( &rawtime );
  ptm = gmtime ( &rawtime );

  LAESProtocol = calloc(1, sizeof(LAESProtocol_t));
  if(!LAESProtocol) {
    perror("LAESProtocol calloc() failed");
    exit(-1);
  }

  ESM1 = calloc(1, sizeof(EncapsulatedSignalingMessage_t));
  ESM2 = calloc(1, sizeof(EncapsulatedSignalingMessage_t));

  subjectMedia = calloc(1, sizeof(MediaInformation_t));
  if (!subjectMedia) {
    perror("subjectMedia calloc() failed");
    exit(-1);
  }

  associateMedia = calloc(1, sizeof(MediaInformation_t));
  if (!associateMedia) {
    perror("associateMedia calloc() failed");
    exit(-1);
  }

  cccId = calloc(1, sizeof(CCCIdentity_t));
  if(!cccId) {
    perror("cccId calloc() failed");
    exit(-1);
  }

  ccDeliveryFormat = calloc(1, sizeof(CCDeliveryFormat_t));
  if(!ccDeliveryFormat) {
    perror("ccDeliveryformat calloc() failed");
    exit(-1);
  }

  ccAddress = calloc(1, sizeof(CCAddress_t));
  if(!ccAddress) {
    perror("ccAddress calloc() failed");
    exit(-1);
  }

  deliveryIdentifier = calloc(1, sizeof(DeliveryIdentifier_t));
  if(!deliveryIdentifier) {
    perror("deliveryIdentifier calloc() failed");
    exit(-1);
  }

  contentIdentifier = calloc(1, sizeof(ContentIdentifier_t));
  if(!contentIdentifier) {
    perror("contentIdentifier calloc() failed");
    exit(-1);
  }

  correlationID = calloc(1, sizeof(CorrelationIdentifier_t));
  if(!correlationID) {
    perror("correlationID calloc() failed");
    exit(-1);
  }

  callID = calloc(1, sizeof(CallIdentity_t));
  if(!callID) {
    perror("callID calloc() failed");
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

  IPAddress1 = calloc(1, sizeof(IpAddress_t));
  IPAddress2 = calloc(1, sizeof(IpAddress_t));
  
  protocolSpecificParameters = calloc(1, sizeof(ProtocolSpecificParameters_t));
  if (!protocolSpecificParameters) {
    perror("protocolSpecificParameters calloc() failed");
    exit(-1);
  }

  signalingMsg = calloc(1, sizeof(struct CCOpen__signalingMsg));
  if (!signalingMsg) {
    perror("signalingMsg calloc() failed");
    exit(-1);
  }

  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
  ret = OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, vop_oid, sizeof(vop_oid[0]), sizeof(vop_oid) / sizeof(vop_oid[0])); 
  assert(ret == 0);

  /* Laes_Message */
  LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_ccOpen;

  /* caseId */
  OCTET_STRING_fromString(&LAES_CCOPEN(caseId), caseId);

  /* iAPSystemId */
  LAES_CCOPEN(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, systemID, strlen(systemID));;

  /* timestamp */
  asn_time2GT_frac(&LAES_CCOPEN(timestamp),ptm,frac_value, frac_digits, force_gmt);

  /* contentIdentifier */

  LAES_CCOPEN(contentIdentifier).present = ContentIdentifier_PR_correlationID;
  OCTET_STRING_fromString(correlationID, "CORRELATION ID 123");
  memcpy(&LAES_CCOPEN(contentIdentifier).choice.correlationID, correlationID, sizeof(CorrelationIdentifier_t));

  //LAES_CCOPEN(contentIdentifier).present = ContentIdentifier_PR_callID;
  //callidentity(callID, "CCOPEN MAIN", "CCOPEN LEG");
  //memcpy(&LAES_CCOPEN(contentIdentifier).choice.callID, callID, sizeof(CallIdentity_t));

  /* deliveryIdentifier */

  //LAES_CCOPEN(deliveryIdentifier).present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_combCCC;
  //OCTET_STRING_fromString(&cccId->choice.combCCC, "User Data combCCC");
  //memcpy(&LAES_CCOPEN(deliveryIdentifier).choice.cccId, cccId, sizeof(CCCIdentity_t));

  LAES_CCOPEN(deliveryIdentifier).present = DeliveryIdentifier_PR_cccId;
  cccId->present = CCCIdentity_PR_sepCCCpair;
  OCTET_STRING_fromString(&cccId->choice.sepCCCpair.sepXmitCCC, "User Data sepXmitCCC");
  OCTET_STRING_fromString(&cccId->choice.sepCCCpair.sepRecvCCC, "User Data sepRecvCCC");
  memcpy(&LAES_CCOPEN(deliveryIdentifier).choice.cccId, cccId, sizeof(CCCIdentity_t));

  //LAES_CCOPEN(deliveryIdentifier).present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indXmitCCC;
  //OCTET_STRING_fromString(&cccId->choice.indXmitCCC, "User Data indXmitCCC");
  //memcpy(&LAES_CCOPEN(deliveryIdentifier).choice.cccId, cccId, sizeof(CCCIdentity_t));

  //LAES_CCOPEN(deliveryIdentifier).present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indRecvCCC;
  //OCTET_STRING_fromString(&cccId->choice.indRecvCCC, "User Data indRecvCCC");
  //memcpy(&LAES_CCOPEN(deliveryIdentifier).choice.cccId, cccId, sizeof(CCCIdentity_t));

  //LAES_CCOPEN(deliveryIdentifier).present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indCCC;
  //OCTET_STRING_fromString(&cccId->choice.indCCC, "User Data indCCC");
  //memcpy(&LAES_CCOPEN(deliveryIdentifier).choice.cccId, cccId, sizeof(CCCIdentity_t));

  //LAES_CCOPEN(deliveryIdentifier).present = DeliveryIdentifier_PR_ccAddress;
  //ipaddress(&ccAddress->leaIPAddress, "111.111.111.111");
  //ccAddress->leaPortNumber = 5222;
  //memcpy(&LAES_CCOPEN(deliveryIdentifier).choice.ccAddress, ccAddress, sizeof(CCAddress_t));

  /* deliveryFormat */

  LAES_CCOPEN(ccDeliveryFormat).present = CCDeliveryFormat_PR_cc_APDU;
  OBJECT_IDENTIFIER_set_arcs(&LAES_CCOPEN(ccDeliveryFormat).choice.cc_APDU, ccdelivery_oid, sizeof(ccdelivery_oid[0]), sizeof(ccdelivery_oid) / sizeof(ccdelivery_oid[0])); 

  //LAES_CCOPEN(ccDeliveryFormat).present = CCDeliveryFormat_PR_scte;
  //OCTET_STRING_fromString(&LAES_CCOPEN(ccDeliveryFormat).choice.scte, "User Data SCTE");

  /* subjectMedia */

  subjectMedia->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
  subjectMedia->characteristics->present = MediaInformation__characteristics_PR_sdp;
  OCTET_STRING_fromString(&subjectMedia->characteristics->choice.sdp, "SUBJECT MEDIA SDP");
  LAES_CCOPEN(subjectMedia) = subjectMedia;

  /* associateMedia */

  associateMedia->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
  associateMedia->characteristics->present = MediaInformation__characteristics_PR_sdp;
  OCTET_STRING_fromString(&associateMedia->characteristics->choice.sdp, "ASSOCIATE MEDIA SDP");
  LAES_CCOPEN(associateMedia) = associateMedia;

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

  LAES_CCOPEN(protocolSpecificParameters) = protocolSpecificParameters;

  /* signalingMsg */
  encapsulatedsignalingmessage(ESM1,"MimeType 1", "test message 1");
  asn_set_add(signalingMsg, ESM1);

  encapsulatedsignalingmessage(ESM2,"MimeType 2", "test message 2");
  asn_set_add(signalingMsg, ESM2);

  LAES_CCOPEN(signalingMsg) = signalingMsg;

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote CCOpen message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
