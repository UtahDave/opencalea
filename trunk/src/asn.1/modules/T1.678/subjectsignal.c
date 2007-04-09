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


#define LAES_SUBJECTSIGNAL(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.subjectSignal.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int subjectsignal(FILE *fp) {

LAESProtocol_t *LAESProtocol;

MediaInformation_t *MediaInformation;

ProtocolSpecificParameters_t *protocolSpecificParameters;

CallIdentity_t  *CallIdentity;

PartyIdentity_t *SignaledPartyIdentity;
PartyIdentity_t *SignalingPartyIdentity;

IpAddress_t *SignaledIPAddress;
IpAddress_t *SignalingIPAddress;

EncapsulatedSignalingMessage_t *EncapsulatedSignalingMessage;

SipHeader_t *SipHeader, *SipBodyHeader;

struct ProtocolSpecificParameters__sip__sipBody *SipBody;

struct SubjectSignal__input        *input;
struct SubjectSignal__signal       *signal;
struct SubjectSignal__signalingMsg *signalingMsg;

A_SET_OF(SipHeader_t) *SipHeaders, *SipBodyHeaders;

char dialed_digits[] = "18005551212";
char sigprot[] = "Encaps Sig Prot"; 
char sigmsg[] = "Encaps Sig Msg"; 
char sip[] = "SIP"; 
char sip_header[] = "SIP HEADER"; 
char sip_bodyheader[] = "SIP BODY HEADER"; 
char sip_bodycontents[] = "SIP BODY CONTENTS"; 
char sdp[] = "SDP"; 
char generic[] = "GENERIC"; 
char caseId[] = "TestCase";
char systemID[] = "OpenSER";
char callId_main[] = "Call Id MAIN";
char callId_leg[] = "Call Id LEG";
char signaled_partyId_context[] = "Signaled Party Id Context";
char signaling_partyId_context[] = "Signaling Party Id Context";
char signaledPartyId[] = "Signaled Party Id";
char signalingPartyId[] = "Signaling Party Id";
char signaled_ipaddress[] = "000.000.000.000";
char signaling_ipaddress[] = "999.999.999.999";

int frac_value = 1234;
int frac_digits = 4;
int force_gmt = 1;
int ret;

time_t rawtime;
struct tm *ptm;

asn_enc_rval_t ec;      /* Encoder return value  */

int oid[] = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };

time ( &rawtime );
ptm = gmtime ( &rawtime );

LAESProtocol = calloc(1, sizeof(LAESProtocol_t));
if(!LAESProtocol) {
  perror("LAESProtocol calloc() failed");
  exit(-1);
}

EncapsulatedSignalingMessage = calloc(1, sizeof(EncapsulatedSignalingMessage_t));
if(!EncapsulatedSignalingMessage) {
  perror("EncapsulatedSignalingMessage calloc() failed");
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

MediaInformation = calloc(1, sizeof(MediaInformation_t));
if (!MediaInformation) {
  perror("MediaInformation calloc() failed");
  exit(-1);
}

CallIdentity = calloc(1, sizeof(CallIdentity_t));
if (!CallIdentity) {
  perror("CallIdentity calloc() failed");
  exit(-1);
}

SignaledPartyIdentity = calloc(1, sizeof(PartyIdentity_t));
if (!SignaledPartyIdentity) {
  perror("SignaledPartyIdentity calloc() failed");
  exit(-1);
}
SignalingPartyIdentity = calloc(1, sizeof(PartyIdentity_t));
if (!SignalingPartyIdentity) {
  perror("SignalingPartyIdentity calloc() failed");
  exit(-1);
}

SignaledIPAddress = calloc(1, sizeof(IpAddress_t));
if (!SignaledIPAddress) {
  perror("SignaledIPAddress calloc() failed");
  exit(-1);
}

SignalingIPAddress = calloc(1, sizeof(IpAddress_t));
if (!SignalingIPAddress) {
  perror("SignalingIPAddress calloc() failed");
  exit(-1);
}

input = calloc(1, sizeof(struct SubjectSignal__input));
if (!input) {
  perror("input calloc() failed");
  exit(-1);
}

signal = calloc(1, sizeof(struct SubjectSignal__signal));
if (!signal) {
  perror("signal calloc() failed");
  exit(-1);
}

signalingMsg = calloc(1, sizeof(struct SubjectSignal__signalingMsg));
if (!signalingMsg) {
  perror("signalingMsg calloc() failed");
  exit(-1);
}

LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
ret = OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0])); 
assert(ret == 0);

/* Laes_Message */
LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_subjectSignal;

/* caseId */
OCTET_STRING_fromString(&LAES_SUBJECTSIGNAL(caseId), caseId);

/* iAPSystemId */
LAES_SUBJECTSIGNAL(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, systemID, strlen(systemID));;

/* timestamp */
asn_time2GT_frac(&LAES_SUBJECTSIGNAL(timestamp),ptm,frac_value, frac_digits, force_gmt);

/* callId */
OCTET_STRING_fromString(&CallIdentity->main, callId_main);
CallIdentity->leg = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, callId_leg, strlen(callId_leg));
LAES_SUBJECTSIGNAL(callId) = CallIdentity;

/* signaledPartyId  - PartyIdentity*/
SignaledIPAddress->present = IpAddress_PR_ipV4;
OCTET_STRING_fromString(&SignaledIPAddress->choice.ipV4, signaled_ipaddress);
SignaledPartyIdentity->ipAddress = SignaledIPAddress;
SignaledPartyIdentity->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, signaled_partyId_context, strlen(signaled_partyId_context));
LAES_SUBJECTSIGNAL(signaledPartyId) = SignaledPartyIdentity;

/* signalingPartyId - PartyIdentity */
SignalingIPAddress->present = IpAddress_PR_ipV4;
OCTET_STRING_fromString(&SignalingIPAddress->choice.ipV4, signaling_ipaddress);
SignalingPartyIdentity->ipAddress = SignalingIPAddress;
SignalingPartyIdentity->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, signaling_partyId_context, strlen(signaling_partyId_context));
LAES_SUBJECTSIGNAL(signalingPartyId) = SignalingPartyIdentity;

/* input */
input->present = SubjectSignal__input_PR_userInput;
input->choice.userInput.present = SubjectSignal__input__userInput_PR_generic;
OCTET_STRING_fromString(&input->choice.userInput.choice.generic, generic); 
memcpy(&LAES_SUBJECTSIGNAL(input),input,sizeof(struct SubjectSignal__input));

/* subjectMedia */
MediaInformation->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
MediaInformation->characteristics->present = MediaInformation__characteristics_PR_sdp;
OCTET_STRING_fromString(&MediaInformation->characteristics->choice.sdp, sdp); 
LAES_SUBJECTSIGNAL(subjectMedia) = MediaInformation;

/* signal */
signal->refer = calloc(1, sizeof(struct SubjectSignal__signal__refer));
signal->refer->present = SubjectSignal__signal__refer_PR_sip;
signal->dialedDigits = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, dialed_digits, strlen(dialed_digits));

SipHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_header, strlen(sip_header));
asn_set_add(&signal->refer->choice.sip.list, SipHeader);
asn_set_add(&signal->refer->choice.sip.list, SipHeader);
asn_set_add(&signal->refer->choice.sip.list, SipHeader);
memcpy(&LAES_SUBJECTSIGNAL(signal),signal,sizeof(struct SubjectSignal__signal));

/* protocolSpecificParameters */
protocolSpecificParameters->present = ProtocolSpecificParameters_PR_sip;

asn_set_add(SipHeaders, SipHeader);
asn_set_add(SipHeaders, SipHeader);
asn_set_add(SipHeaders, SipHeader);
protocolSpecificParameters->choice.sip.sipHeader = SipHeaders;

SipBodyHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_bodyheader, strlen(sip_bodyheader));
asn_set_add(SipBodyHeaders, SipBodyHeader);
asn_set_add(SipBodyHeaders, SipBodyHeader);
asn_set_add(SipBodyHeaders, SipBodyHeader);

  memcpy(&SipBody->sipBodyHeader.list, SipBodyHeaders, sizeof(A_SET_OF(SipHeader_t)));
  OCTET_STRING_fromString(&SipBody->sipBodyContents, "SIP BODY CONTENTS");
  protocolSpecificParameters->choice.sip.sipBody = SipBody;

LAES_SUBJECTSIGNAL(protocolSpecificParameters) = protocolSpecificParameters;

/* signalingMsg */
OCTET_STRING_fromString(&EncapsulatedSignalingMessage->signalingProt, sigprot); 
OCTET_STRING_fromString(&EncapsulatedSignalingMessage->sigMsg, sigmsg); 

asn_set_add(signalingMsg, EncapsulatedSignalingMessage);

LAES_SUBJECTSIGNAL(signalingMsg) = signalingMsg;

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote SubjectSignal message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
