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

#define LAES_SERVINGSYSTEM(parm) (LAESProtocol->choice.enhancedProtocol.laesMessage.choice.servingSystem.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int servingsystem(FILE *fp) {

  LAESProtocol_t *LAESProtocol;

  char caseId[]   = "ServingSystem CaseID";
  char iAPSystemId[] = "ServingSystem SystemID";
  CallIdentity_t                   *requestId;
  AddressRegistrationType_t	   registrationType;
  PartyIdentity_t                  *registering;
  PartyIdentity_t                  *requesting;
  PartyIdentity_t                  *registrar;
  Cause_t                          *failureReason;
  ProtocolSpecificParameters_t	   *protocolSpecificParameters;

  struct ServingSystem__signalingMsg        *signalingMsg;
  struct ServingSystem__requestAddressInfo  *requestAddressInfo;
  struct ServingSystem__responseAddressInfo *responseAddressInfo;
  struct ServingSystem__expirationPeriod    *expirationPeriod;

  PartyIdentity_t		   *requestAddressInfo_address;
  PartyIdentity_t		   *responseAddressInfo_address;
  ParameterFormat_t		   *parameterFormat;
  IpAddress_t *registeringIP, *requestingIP, *registrarIP;
  IpAddress_t *requestAddressInfoIP, *responseAddressInfoIP;

  SipHeader_t *SipHeader, *SipBodyHeader;
  SipHeader_t *SipExpiresHeader;
  SipHeader_t *SipFromHeader;
  SipHeader_t *SipToHeader;
  SipHeader_t *SipViaHeader;
  SipHeader_t *SipContactHeader;
  SipHeader_t *SipHeaderArray[10];
  A_SET_OF(SipHeader_t) *SipHeaders, *SipBodyHeaders;
  Generic_t *request_generic, *response_generic;

  struct ProtocolSpecificParameters__sip__sipBody *SipBody;
  EncapsulatedSignalingMessage_t *ESM1, *ESM2;
  CorrelationIdentifier_t *correlationID;
  CallIdentity_t *callID;
  CCCIdentity_t *cccId;
  CCAddress_t *ccAddress;

  int vop_oid[]        = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };
  int ccdelivery_oid[] = { 1, 2, 840, 113737, 2, 1, 0, 1, 1 };

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

  expirationPeriod = calloc(1, sizeof(struct ServingSystem__expirationPeriod));
  if (!expirationPeriod) {
    perror("expirationPeriod calloc() failed");
    exit(-1);
  }

  responseAddressInfo = calloc(1, sizeof(struct ServingSystem__responseAddressInfo));
  if (!responseAddressInfo) {
    perror("responseAddressInfo calloc() failed");
    exit(-1);
  }

  requestAddressInfo = calloc(1, sizeof(struct ServingSystem__requestAddressInfo));
  if (!requestAddressInfo) {
    perror("requestAddressInfo calloc() failed");
    exit(-1);
  }

  requestId = calloc(1, sizeof(CallIdentity_t));
  if (!requestId) {
    perror("requestId calloc() failed");
    exit(-1);
  }

  parameterFormat = calloc(1, sizeof(ParameterFormat_t));
  if (!parameterFormat) {
    perror("parameterFormat calloc() failed");
    exit(-1);
  }

  responseAddressInfo_address = calloc(1, sizeof(PartyIdentity_t));
  if (!responseAddressInfo_address) {
    perror("responseAddressInfo_address calloc() failed");
    exit(-1);
  }

  requestAddressInfo_address = calloc(1, sizeof(PartyIdentity_t));
  if (!requestAddressInfo_address) {
    perror("requestAddressInfo_address calloc() failed");
    exit(-1);
  }

  registering = calloc(1, sizeof(PartyIdentity_t));
  if (!registering) {
    perror("registering calloc() failed");
    exit(-1);
  }

  requesting = calloc(1, sizeof(PartyIdentity_t));
  if (!requesting) {
    perror("requesting calloc() failed");
    exit(-1);
  }

  registrar= calloc(1, sizeof(PartyIdentity_t));
  if (!registrar) {
    perror("registrar calloc() failed");
    exit(-1);
  }

  failureReason = calloc(1, sizeof(Cause_t));
  if (!failureReason) {
    perror("failureReason calloc() failed");
    exit(-1);
  }

  requestId = calloc(1, sizeof(CallIdentity_t));
  if (!requestId) {
    perror("requestId calloc() failed");
    exit(-1);
  }

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

  request_generic = calloc(1, sizeof(struct Generic));
  if(!request_generic) {
    perror("request_generic calloc() failed");
    exit(-1);
  }

  response_generic = calloc(1, sizeof(struct Generic));
  if(!response_generic) {
    perror("response_generic calloc() failed");
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

  responseAddressInfoIP = calloc(1, sizeof(IpAddress_t));
  requestAddressInfoIP = calloc(1, sizeof(IpAddress_t));
  registeringIP = calloc(1, sizeof(IpAddress_t));
  requestingIP = calloc(1, sizeof(IpAddress_t));
  registrarIP = calloc(1, sizeof(IpAddress_t));
  
  protocolSpecificParameters = calloc(1, sizeof(ProtocolSpecificParameters_t));
  if (!protocolSpecificParameters) {
    perror("protocolSpecificParameters calloc() failed");
    exit(-1);
  }

  signalingMsg = calloc(1, sizeof(struct ServingSystem__signalingMsg));
  if (!signalingMsg) {
    perror("signalingMsg calloc() failed");
    exit(-1);
  }

  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;
  ret = OBJECT_IDENTIFIER_set_arcs(&LAESProtocol->choice.enhancedProtocol.protocolIdentifier, vop_oid, sizeof(vop_oid[0]), sizeof(vop_oid) / sizeof(vop_oid[0])); 
  assert(ret == 0);

  /* Laes_Message */
  LAESProtocol->choice.enhancedProtocol.laesMessage.present = LaesMessage_PR_servingSystem;

  /* caseId */
  OCTET_STRING_fromString(&LAES_SERVINGSYSTEM(caseId), caseId);

  /* iAPSystemId */
  LAES_SERVINGSYSTEM(iAPSystemId)  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, iAPSystemId, strlen(iAPSystemId));;

  /* timestamp */
  asn_time2GT_frac(&LAES_SERVINGSYSTEM(timestamp),ptm,frac_value, frac_digits, force_gmt);

  /* systemIdentity */
  LAES_SERVINGSYSTEM(systemIdentity) = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "System Identity", 15);
  
  /* networkAddress */
  LAES_SERVINGSYSTEM(networkAddress) = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Network Address", 15);
  
  /* requestId */
  callidentity(requestId, "RequestId MAIN", "RequestId LEG");
  LAES_SERVINGSYSTEM(requestId) = requestId;

  /* registrationType */
  //registrationType = AddressRegistrationType_unknown;
  //registrationType = AddressRegistrationType_registration;
  //registrationType = AddressRegistrationType_deregistration;
  registrationType = AddressRegistrationType_registrationAndDeregistration;
  LAES_SERVINGSYSTEM(registrationType) = &registrationType;

  /* requesting  - PartyIdentity*/
  ipaddress(requestingIP, "123.456.789.012");
  requesting->ipAddress = requestingIP;
  requesting->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Requesting Address Context", 25);
  LAES_SERVINGSYSTEM(requesting) = requesting;

  /* registering  - PartyIdentity*/
  ipaddress(registeringIP, "123.456.789.012");
  registering->ipAddress = registeringIP;
  registering->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Registering Address Context", 25);
  LAES_SERVINGSYSTEM(registering) = registering;
  
  /* registrar  - PartyIdentity*/
  ipaddress(registrarIP, "123.456.789.012");
  registrar->ipAddress = registrarIP;
  registrar->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Registrar Address Context", 25);
  LAES_SERVINGSYSTEM(registrar) = registrar;

  /* requestAddressInfo */
  //requestAddressInfo->present = ServingSystem__requestAddressInfo_PR_generic;
  //ipaddress(requestAddressInfoIP, "123.456.789.012");
  //requestAddressInfo_address->ipAddress = requestAddressInfoIP;
  //requestAddressInfo_address->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Request Generic Address Info", 28);
  //memcpy(&request_generic->address, requestAddressInfo_address, sizeof(PartyIdentity_t));
  //request_generic->expirationPeriod = 5;
  //asn_sequence_add(&requestAddressInfo->choice.generic, request_generic);
  
  requestAddressInfo->present = ServingSystem__requestAddressInfo_PR_sip;
  for (i=3; i<5; i++) {
    SipHeaderArray[i] = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_data[i], strlen(sip_data[i]));
    asn_set_add(&requestAddressInfo->choice.sip, SipHeaderArray[i]);
  }

  LAES_SERVINGSYSTEM(requestAddressInfo) = requestAddressInfo;

  /* responseAddressInfo */
  //responseAddressInfo->present = ServingSystem__responseAddressInfo_PR_generic;
  //ipaddress(responseAddressInfoIP, "123.456.789.012");
  //responseAddressInfo_address->ipAddress = responseAddressInfoIP;
  //responseAddressInfo_address->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, "Response Generic Address Info", 29);
  //memcpy(&response_generic->address, responseAddressInfo_address, sizeof(PartyIdentity_t));
  //response_generic->expirationPeriod = 10;
  //asn_sequence_add(&responseAddressInfo->choice.generic, response_generic);
  
  responseAddressInfo->present = ServingSystem__responseAddressInfo_PR_sip;
  for (i=1; i<5; i++) {
    SipHeaderArray[i] = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_data[i], strlen(sip_data[i]));
    asn_set_add(&responseAddressInfo->choice.sip, SipHeaderArray[i]);
  }

  LAES_SERVINGSYSTEM(responseAddressInfo) = responseAddressInfo;

  /* failureReason */
  OCTET_STRING_fromString(&failureReason->signalingType, "Signaling Type");

  //parameterFormat->present = ParameterFormat_PR_generic;
  //OCTET_STRING_fromString(&parameterFormat->choice.generic, "GENERIC PARAMETER");
  //cause->cause = parameterFormat;

  parameterFormat->present = ParameterFormat_PR_sip;
  for (i=7; i<9; i++) {
    SipHeaderArray[i] = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_data[i], strlen(sip_data[i]));
    asn_set_add(&parameterFormat->choice.sip, SipHeaderArray[i]);
  }
  failureReason->cause = parameterFormat;

  LAES_SERVINGSYSTEM(failureReason) = failureReason;

  /* expirationPeriod */
  //expirationPeriod->present = ServingSystem__expirationPeriod_PR_generic;
  //expirationPeriod->choice.generic = 12;

  expirationPeriod->present = ServingSystem__expirationPeriod_PR_sip;
  OCTET_STRING_fromString(&expirationPeriod->choice.sip, "Expires 9999");
  LAES_SERVINGSYSTEM(expirationPeriod) = expirationPeriod;

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

  LAES_SERVINGSYSTEM(protocolSpecificParameters) = protocolSpecificParameters;

  /* signalingMsg */
  encapsulatedsignalingmessage(ESM1,"MimeType 1", "test message 1");
  asn_set_add(signalingMsg, ESM1);

  encapsulatedsignalingmessage(ESM2,"MimeType 2", "test message 2");
  asn_set_add(signalingMsg, ESM2);

  LAES_SERVINGSYSTEM(signalingMsg) = signalingMsg;

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote ServingSystem message\n");
    }
  }

/* Also print the constructed LAESProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

return 0;
}
