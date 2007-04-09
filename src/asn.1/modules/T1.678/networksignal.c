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

#define LAES_NETWORKSIGNAL(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.networkSignal.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int networksignal(FILE *fp) {

  LAESProtocol_t *LAESProtocol;

  char caseId[]   = "NetworkSignal CaseID";
  char iAPSystemId[] = "NetworkSignal SystemID";
  CallIdentity_t *callId;
  PartyIdentity_t *signaledToPartyId, *subjectContactAddresses, *associateContactAddresses;
  MediaInformation_t *associateMedia;
  AlertingSignal_t alertingSignal;
  AudibleSignal_t  subjectAudibleSignal;
  TerminalDisplayInfo_t *terminalDisplayInfo;
  ProtocolSpecificParameters_t	*protocolSpecificParameters;
  struct NetworkSignal__signalingMsg	*signalingMsg;
  struct NetworkSignal__refer       *refer;

  IpAddress_t *PartyIP1, *PartyIP2, *PartyIP3;

  SipHeader_t *SipHeader, *SipBodyHeader;
  SipHeader_t *SipFromHeader;
  SipHeader_t *SipToHeader;
  SipHeader_t *SipViaHeader;
  SipHeader_t *SipContactHeader;
  SipHeader_t *SipHeaderArray[10];

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

  terminalDisplayInfo = calloc(1, sizeof(TerminalDisplayInfo_t));
  if(!terminalDisplayInfo) {
    perror("terminalDisplayInfo calloc() failed");
    exit(-1);
  }

  callId = calloc(1, sizeof(CallIdentity_t));
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

  associateMedia = calloc(1, sizeof(MediaInformation_t));
  if (!associateMedia) {
    perror("associateMedia calloc() failed");
    exit(-1);
  }

  signaledToPartyId = calloc(1, sizeof(PartyIdentity_t));
  if (!signaledToPartyId) {
    perror("signaledToPartyId calloc() failed");
    exit(-1);
  }

  subjectContactAddresses = calloc(1, sizeof(PartyIdentity_t));
  if (!subjectContactAddresses) {
    perror("subjectContactAddresses calloc() failed");
    exit(-1);
  }

  associateContactAddresses = calloc(1, sizeof(PartyIdentity_t));
  if (!associateContactAddresses) {
    perror("associateContactAddresses calloc() failed");
    exit(-1);
  }

  PartyIP1 = calloc(1, sizeof(IpAddress_t));
  PartyIP2 = calloc(1, sizeof(IpAddress_t));
  PartyIP3 = calloc(1, sizeof(IpAddress_t));

  signalingMsg = calloc(1, sizeof(struct NetworkSignal__signalingMsg));
  if (!signalingMsg) {
    perror("signalingMsg calloc() failed");
    exit(-1);
  }

  refer = calloc(1, sizeof(struct NetworkSignal__refer));
  if (!refer) {
    perror("refer calloc() failed");
    exit(-1);
  }

  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
  ret = OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0])); 
  assert(ret == 0);

  /* Laes_Message */
  LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_networkSignal;

  /* caseId */
  OCTET_STRING_fromString(&LAES_NETWORKSIGNAL(caseId), caseId);

  /* iAPSystemId */
  LAES_NETWORKSIGNAL(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, iAPSystemId, strlen(iAPSystemId));;

  /* timestamp */
  asn_time2GT_frac(&LAES_NETWORKSIGNAL(timestamp),ptm,frac_value, frac_digits, force_gmt);

  /* callId */
  callidentity(callId, "NetworkSignal MAIN", "NetworkSignal LEG");
  LAES_NETWORKSIGNAL(callId) = callId;

  /* signaledToPartyId */
  ipaddress(PartyIP1, "111.111.111.111");
  signaledToPartyId->ipAddress = PartyIP1;
  signaledToPartyId->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Signaled To Party Context", 25);
  LAES_NETWORKSIGNAL(signaledToPartyId) = signaledToPartyId; 

  /* subjectContactAddresses */
  ipaddress(PartyIP2, "222.222.222.222");
  subjectContactAddresses->ipAddress = PartyIP2;
  subjectContactAddresses->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Subject Contact Party Context", 29);
  LAES_NETWORKSIGNAL(subjectContactAddresses) = subjectContactAddresses; 

  /* associateContactAddresses */
  ipaddress(PartyIP3, "333.333.333.333");
  associateContactAddresses->ipAddress = PartyIP3;
  associateContactAddresses->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Associate Contact Party Context", 31);
  LAES_NETWORKSIGNAL(associateContactAddresses) = associateContactAddresses; 

  /* associateMedia */
  associateMedia->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
  associateMedia->characteristics->present = MediaInformation__characteristics_PR_sdp;
  OCTET_STRING_fromString(&associateMedia->characteristics->choice.sdp, "Associate MEDIA SDP");
  LAES_NETWORKSIGNAL(associateMedia) = associateMedia;

  /* alertingSignal */

  //alertingSignal = AlertingSignal_alertingPattern0;
  //alertingSignal = AlertingSignal_alertingPattern1;
  //alertingSignal = AlertingSignal_alertingPattern2;
  //alertingSignal = AlertingSignal_alertingPattern3;
  //alertingSignal = AlertingSignal_alertingPattern4;
  alertingSignal = AlertingSignal_callWaitingPattern1;
  //alertingSignal = AlertingSignal_callWaitingPattern2;
  //alertingSignal = AlertingSignal_callWaitingPattern3;
  //alertingSignal = AlertingSignal_callWaitingPattern4;
  //alertingSignal = AlertingSignal_bargeInTone;
  LAES_NETWORKSIGNAL(alertingSignal) = &alertingSignal;

  /* subjectAudibleSignal */

  //subjectAudibleSignal = AudibleSignal_dialTone; 
  //subjectAudibleSignal = AudibleSignal_recallDialTone; 
  //subjectAudibleSignal = AudibleSignal_ringbackTone; 
  //subjectAudibleSignal = AudibleSignal_reorderTone; 
  //subjectAudibleSignal = AudibleSignal_busyTone; 
  //subjectAudibleSignal = AudibleSignal_confirmationTone; 
  //subjectAudibleSignal = AudibleSignal_expensiveRouteTone; 
  //subjectAudibleSignal = AudibleSignal_messageWaitingTone; 
  //subjectAudibleSignal = AudibleSignal_receiverOffHookTone; 
  subjectAudibleSignal = AudibleSignal_specialInfoTone; 
  //subjectAudibleSignal = AudibleSignal_denialTone; 
  //subjectAudibleSignal = AudibleSignal_interceptTone; 
  //subjectAudibleSignal = AudibleSignal_answerTone; 
  //subjectAudibleSignal = AudibleSignal_tonesOff; 
  //subjectAudibleSignal = AudibleSignal_pipTone;
  //subjectAudibleSignal = AudibleSignal_abbreviatedIntercept; 
  //subjectAudibleSignal = AudibleSignal_abbreviatedCongestion; 
  //subjectAudibleSignal = AudibleSignal_warningTone; 
  //subjectAudibleSignal = AudibleSignal_dialToneBurst; 
  //subjectAudibleSignal = AudibleSignal_numberUnObtainableTone;
  //subjectAudibleSignal = AudibleSignal_authenticationFailTone;
  LAES_NETWORKSIGNAL(subjectAudibleSignal) = &subjectAudibleSignal;

  /* terminalDisplayInfo */
  terminalDisplayInfo->generalDisplay        = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "General Display", 15);
  terminalDisplayInfo->calledNumber          = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Called Number", 13);
  terminalDisplayInfo->callingNumber         = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Calling Number", 14);
  terminalDisplayInfo->callingName           = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Calling Name", 12);
  terminalDisplayInfo->originalCalledNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Original Called Number", 22);
  terminalDisplayInfo->lastRedirectingNumber = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Last Redirecting Number", 23);
  terminalDisplayInfo->redirectingName       = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Redirecting Name", 16);
  terminalDisplayInfo->redirectingReason     = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Redirecting Reason", 18);
  terminalDisplayInfo->messageWaitingNotif   = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Message Waiting Not If", 22);
  LAES_NETWORKSIGNAL(terminalDisplayInfo) = terminalDisplayInfo; 

  /* other */
  LAES_NETWORKSIGNAL(other)  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "OTHER TESTING", 13);

  /* refer */
  refer->present = NetworkSignal__refer_PR_sip;
  SipHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "FROM", 4);
  asn_set_add(&refer->choice.sip.list, SipHeader);
  asn_set_add(&refer->choice.sip.list, SipHeader);
  asn_set_add(&refer->choice.sip.list, SipHeader);
  LAES_NETWORKSIGNAL(refer) = refer;

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

  LAES_NETWORKSIGNAL(protocolSpecificParameters) = protocolSpecificParameters;


  /* signalingMsg */
  encapsulatedsignalingmessage(ESM1,"MimeType 1", "test message 1");
  asn_set_add(signalingMsg, ESM1);

  encapsulatedsignalingmessage(ESM2,"MimeType 2", "test message 2");
  asn_set_add(signalingMsg, ESM2);

  LAES_NETWORKSIGNAL(signalingMsg) = signalingMsg;
  
  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote NetworkSignal message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
