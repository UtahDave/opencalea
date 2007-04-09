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

#define LAES_CONNECTIONBREAK(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.connectionBreak.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int connectionbreak(FILE *fp) {

  LAESProtocol_t *LAESProtocol;

  char caseId[]   = "Connection CaseID";
  char iAPSystemId[] = "Connection SystemID";
  CallIdentity_t *callID1, *callID2, *callID3;
  PartyIdentity_t *Party1, *Party2, *Party3;
  MediaInformation_t *suspendedMedia;
  ProtocolSpecificParameters_t	*protocolSpecificParameters;
  struct ConnectionBreak__signalingMsg	*signalingMsg;

  IpAddress_t *PartyIP1, *PartyIP2, *PartyIP3;

  SipHeader_t *SipHeader, *SipBodyHeader;
  SipHeader_t *SipFromHeader;
  SipHeader_t *SipToHeader;
  SipHeader_t *SipViaHeader;
  SipHeader_t *SipContactHeader;
  SipHeader_t *SipHeaderArray[10];

  A_SEQUENCE_OF(CallIdentity_t)  *callId;
  A_SEQUENCE_OF(PartyIdentity_t) *removedParties, *remainingParties, *droppedParties;

  A_SET_OF(SipHeader_t) *SipHeaders, *SipBodyHeaders;

  struct ProtocolSpecificParameters__sip__sipBody *SipBody;
  EncapsulatedSignalingMessage_t *ESM1, *ESM2;

  int oid[] = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };

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

  droppedParties = calloc(1, sizeof(A_SEQUENCE_OF(PartyIdentity_t)));
  if(!droppedParties) {
    perror("droppedParties calloc() failed");
    exit(-1);
  }

  remainingParties = calloc(1, sizeof(A_SEQUENCE_OF(PartyIdentity_t)));
  if(!remainingParties) {
    perror("remainingParties calloc() failed");
    exit(-1);
  }

  removedParties = calloc(1, sizeof(A_SEQUENCE_OF(PartyIdentity_t)));
  if(!removedParties) {
    perror("removedParties calloc() failed");
    exit(-1);
  }

  callId = calloc(1, sizeof(A_SEQUENCE_OF(CallIdentity_t)));
  if(!callId) {
    perror("callId calloc() failed");
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

  suspendedMedia = calloc(1, sizeof(MediaInformation_t));
  if (!suspendedMedia) {
    perror("suspendedMedia calloc() failed");
    exit(-1);
  }

  Party1 = calloc(1, sizeof(PartyIdentity_t));
  if (!Party1) {
    perror("Party1 calloc() failed");
    exit(-1);
  }

  Party2 = calloc(1, sizeof(PartyIdentity_t));
  if (!Party2) {
    perror("Party2 calloc() failed");
    exit(-1);
  }

  Party3 = calloc(1, sizeof(PartyIdentity_t));
  if (!Party3) {
    perror("Party3 calloc() failed");
    exit(-1);
  }

  callID1 = calloc(1, sizeof(CallIdentity_t));
  if (!callID1) {
    perror("callID1 calloc() failed");
    exit(-1);
  }

  callID2 = calloc(1, sizeof(CallIdentity_t));
  if (!callID2) {
    perror("callID2 calloc() failed");
    exit(-1);
  }

  callID3 = calloc(1, sizeof(CallIdentity_t));
  if (!callID3) {
    perror("callID3 calloc() failed");
    exit(-1);
  }

  PartyIP1 = calloc(1, sizeof(IpAddress_t));
  PartyIP2 = calloc(1, sizeof(IpAddress_t));
  PartyIP3 = calloc(1, sizeof(IpAddress_t));

  signalingMsg = calloc(1, sizeof(struct ConnectionBreak__signalingMsg));
  if (!signalingMsg) {
    perror("signalingMsg calloc() failed");
    exit(-1);
  }

  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
  ret = OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0])); 
  assert(ret == 0);

  /* Laes_Message */
  LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_connectionBreak;

  /* caseId */
  OCTET_STRING_fromString(&LAES_CONNECTIONBREAK(caseId), caseId);

  /* iAPSystemId */
  LAES_CONNECTIONBREAK(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, iAPSystemId, strlen(iAPSystemId));;

  /* timestamp */
  asn_time2GT_frac(&LAES_CONNECTIONBREAK(timestamp),ptm,frac_value, frac_digits, force_gmt);

  /* callId */
  callidentity(callID1, "CallID1 MAIN", "CallID1 LEG");
  asn_sequence_add(callId, callID1);
  memcpy(&LAES_CONNECTIONBREAK(callId), callId, sizeof(A_SEQUENCE_OF(CallIdentity_t)));

  /* remainingParties */
  ipaddress(PartyIP1, "111.111.111.111");
  Party1->ipAddress = PartyIP1;
  Party1->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Remaining Party Context", 23);
  asn_sequence_add(remainingParties, Party1);
  LAES_CONNECTIONBREAK(remainingParties) = remainingParties; 

  /* removedParties */
  ipaddress(PartyIP2, "222.222.222.222");
  Party2->ipAddress = PartyIP2;
  Party2->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Removed Party Context", 21);
  asn_sequence_add(removedParties, Party2);
  LAES_CONNECTIONBREAK(removedParties) = removedParties; 

  /* droppedParties */
  ipaddress(PartyIP3, "333.333.333.333");
  Party3->ipAddress = PartyIP3;
  Party3->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Dropped Party Context", 21);
  asn_sequence_add(droppedParties, Party3);
  LAES_CONNECTIONBREAK(droppedParties) = droppedParties; 

  /* suspendedMedia */

  suspendedMedia->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
  suspendedMedia->characteristics->present = MediaInformation__characteristics_PR_sdp;
  OCTET_STRING_fromString(&suspendedMedia->characteristics->choice.sdp, "SUSPENDED MEDIA SDP");
  LAES_CONNECTIONBREAK(suspendedMedia) = suspendedMedia;

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

  LAES_CONNECTIONBREAK(protocolSpecificParameters) = protocolSpecificParameters;


  /* signalingMsg */
  encapsulatedsignalingmessage(ESM1,"MimeType 1", "test message 1");
  asn_set_add(signalingMsg, ESM1);

  encapsulatedsignalingmessage(ESM2,"MimeType 2", "test message 2");
  asn_set_add(signalingMsg, ESM2);

  LAES_CONNECTIONBREAK(signalingMsg) = signalingMsg;
  
  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Connection message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
