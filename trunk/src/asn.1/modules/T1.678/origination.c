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

int callidentity(CallIdentity_t *CallIdentity, char *main, char *leg);

#define LAES_ORIGINATION(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.origination.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int origination(FILE *fp) {

LAESProtocol_t *LAESProtocol;

MediaInformation_t *MediaInformation;

ProtocolSpecificParameters_t *protocolSpecificParameters;

CallIdentity_t  *CallIdentity;
CallIdentity_t  *CallId1, *CallId2;

PartyIdentity_t *CalledPartyIdentity, *CallingPartyIdentity;
PartyIdentity_t *PartyId1, *PartyId2;

IpAddress_t *CalledIPAddress, *CallingIPAddress;
IpAddress_t *IPAddress1, *IPAddress2;

EncapsulatedSignalingMessage_t *EncapsulatedSignalingMessage;
EncapsulatedSignalingMessage_t *ESM1, *ESM2;

SipHeader_t *SipHeader, *SipBodyHeader;
SipHeader_t *SipFromHeader;
SipHeader_t *SipToHeader;
SipHeader_t *SipViaHeader;
SipHeader_t *SipContactHeader;
SipHeader_t *SipHeaderArray[10];

struct ProtocolSpecificParameters__sip__sipBody *SipBody;

struct Origination__input        *input;
struct Origination__signalingMsg *signalingMsg;
struct Origination__forkedCalls  *forkedCalls;

A_SET_OF(SipHeader_t) *SipHeaders, *SipBodyHeaders;

Location_t *Location;

ForkedCallInformation_t *ForkedCallInformation;
ForkedCallInformation_t *Fork1, *Fork2;

char *sip_data[] = {"1111","2222","3333","4444","5555","6666","7777","8888","9999","0000"};
char location_type[] = "Location Type";
char location_location[] = "Location Location";
char origination_cause[] = "Origination Cause";
char dialed_digits[] = "18005551212";
char sigprot[] = "Encaps Sig Prot"; 
char sigmsg[] = "Encaps Sig Msg"; 
char sip[] = "SIP"; 
char sip_header[] = "SIP HEADER"; 
char sip_bodyheader[] = "SIP BODY HEADER"; 
char sip_bodycontents[] = "SIP BODY CONTENTS"; 
char sdp[] = "SDP"; 
char generic[] = "GENERIC"; 
char caseId[] = "Origination CaseID";
char systemID[] = "Origination SystemID";
char callId_main[] = "Call Id MAIN";
char callId_leg[] = "Call Id LEG";
char called_partyId_context[] = "Called Party Id Context";
char calling_partyId_context[] = "Calling Party Id Context";
char called_ipaddress[] = "000.000.000.000";
char calling_ipaddress[] = "999.999.999.999";

int frac_value = 1234;
int frac_digits = 4;
int force_gmt = 1;
int ret;
int i;

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

ESM1 = calloc(1, sizeof(EncapsulatedSignalingMessage_t));
ESM2 = calloc(1, sizeof(EncapsulatedSignalingMessage_t));
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

CallId1 = calloc(1, sizeof(CallIdentity_t));
CallId2 = calloc(1, sizeof(CallIdentity_t));
CallIdentity = calloc(1, sizeof(CallIdentity_t));
if (!CallIdentity) {
  perror("CallIdentity calloc() failed");
  exit(-1);
}

PartyId1 = calloc(1, sizeof(PartyIdentity_t));
PartyId2 = calloc(1, sizeof(PartyIdentity_t));
CalledPartyIdentity = calloc(1, sizeof(PartyIdentity_t));
if (!CalledPartyIdentity) {
  perror("CalledPartyIdentity calloc() failed");
  exit(-1);
}

CallingPartyIdentity = calloc(1, sizeof(PartyIdentity_t));
if (!CallingPartyIdentity) {
  perror("CallingPartyIdentity calloc() failed");
  exit(-1);
}


IPAddress1 = calloc(1, sizeof(IpAddress_t));
IPAddress2 = calloc(1, sizeof(IpAddress_t));
CalledIPAddress = calloc(1, sizeof(IpAddress_t));
if (!CalledIPAddress) {
  perror("CalledIPAddress calloc() failed");
  exit(-1);
}

CallingIPAddress = calloc(1, sizeof(IpAddress_t));
if (!CallingIPAddress) {
  perror("CallingIPAddress calloc() failed");
  exit(-1);
}

Location = calloc(1, sizeof(Location_t));
if (!Location) {
  perror("Location calloc() failed");
  exit(-1);
}

Fork1 = calloc(1, sizeof(ForkedCallInformation_t));
Fork2 = calloc(1, sizeof(ForkedCallInformation_t));
ForkedCallInformation = calloc(1, sizeof(ForkedCallInformation_t));
if (!ForkedCallInformation) {
  perror("ForkedCallInformation calloc() failed");
  exit(-1);
}

input = calloc(1, sizeof(struct Origination__input));
if (!input) {
  perror("input calloc() failed");
  exit(-1);
}

signalingMsg = calloc(1, sizeof(struct Origination__signalingMsg));
if (!signalingMsg) {
  perror("signalingMsg calloc() failed");
  exit(-1);
}

forkedCalls = calloc(1, sizeof(struct Origination__forkedCalls));
if (!forkedCalls) {
  perror("forkedCalls calloc() failed");
  exit(-1);
}

LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
ret = OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0])); 
assert(ret == 0);

/* Laes_Message */
LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_origination;

/* caseId */
OCTET_STRING_fromString(&LAES_ORIGINATION(caseId), caseId);

/* iAPSystemId */
LAES_ORIGINATION(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, systemID, strlen(systemID));;

/* timestamp */
asn_time2GT_frac(&LAES_ORIGINATION(timestamp),ptm,frac_value, frac_digits, force_gmt);

/* callId */
callidentity(CallIdentity, "MAIN", "LEG");
memcpy(&LAES_ORIGINATION(callId), CallIdentity, sizeof(CallIdentity_t));

/* called  - PartyIdentity*/
ipaddress(CalledIPAddress, "123.456.789.012");
CalledPartyIdentity->ipAddress = CalledIPAddress;
CalledPartyIdentity->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, called_partyId_context, strlen(called_partyId_context));
LAES_ORIGINATION(called) = CalledPartyIdentity;

/* calling - PartyIdentity */
ipaddress(CallingIPAddress, "555.555.555.555");
CallingPartyIdentity->ipAddress = CallingIPAddress;
CallingPartyIdentity->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, calling_partyId_context, strlen(calling_partyId_context));
LAES_ORIGINATION(calling) = CallingPartyIdentity;

/* input */
input->present = Origination__input_PR_userInput;
input->choice.userInput.present = Origination__input__userInput_PR_generic;
OCTET_STRING_fromString(&input->choice.userInput.choice.generic, generic); 
memcpy(&LAES_ORIGINATION(input),input,sizeof(struct Origination__input));

/* location */
OCTET_STRING_fromString(&Location->locationType, location_type);
OCTET_STRING_fromString(&Location->location, location_location);
LAES_ORIGINATION(location) = Location;

/* subjectMedia */
MediaInformation->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
MediaInformation->characteristics->present = MediaInformation__characteristics_PR_sdp;
OCTET_STRING_fromString(&MediaInformation->characteristics->choice.sdp, sdp); 
LAES_ORIGINATION(subjectMedia) = MediaInformation;

  /* originationCause */
  OCTET_STRING_fromString(&LAES_ORIGINATION(originationCause), origination_cause);

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

  SipBodyHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_bodyheader, strlen(sip_bodyheader));
  asn_set_add(SipBodyHeaders, SipBodyHeader);
  asn_set_add(SipBodyHeaders, SipBodyHeader);

  memcpy(&SipBody->sipBodyHeader.list, SipBodyHeaders, sizeof(A_SET_OF(SipHeader_t)));
  OCTET_STRING_fromString(&SipBody->sipBodyContents, sip_bodycontents);
  protocolSpecificParameters->choice.sip.sipBody = SipBody;

  LAES_ORIGINATION(protocolSpecificParameters) = protocolSpecificParameters;

  /* signalingMsg */
  encapsulatedsignalingmessage(ESM1,"MimeType 1", "test message 1");
  asn_set_add(signalingMsg, ESM1);

  encapsulatedsignalingmessage(ESM2,"MimeType 2", "test message 2");
  asn_set_add(signalingMsg, ESM2);

  LAES_ORIGINATION(signalingMsg) = signalingMsg;

  /* forkedCalls */
  callidentity(CallId1, "MAIN 1", "LEG 1");
  ipaddress(IPAddress1, "111.111.111.111");
  PartyId1->ipAddress = IPAddress1;
  PartyId1->context   = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Test 111", 8);
  forkedcallinformation(Fork1, CallId1, PartyId1);
  asn_set_add(forkedCalls, Fork1);

  callidentity(CallId2, "MAIN 2", "LEG 2");
  ipaddress(IPAddress2, "222.222.222.222");
  PartyId2->ipAddress = IPAddress2;
  PartyId2->context   = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "Test 222", 8);
  forkedcallinformation(Fork2, CallId2, PartyId2);
  asn_set_add(forkedCalls, Fork2);

  LAES_ORIGINATION(forkedCalls) = forkedCalls; 

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Origination message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
