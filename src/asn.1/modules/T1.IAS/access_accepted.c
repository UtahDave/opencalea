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
#include "IasProtocol.h"

#define IAS_ACCESSACCEPTED(parm) (IasProtocol->iasMessage.choice.access_Accepted.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int access_accepted(FILE *fp) {

  int ias_laes_cmii_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 0, 0 };

  IasProtocol_t               *IasProtocol;
  SubscriberIdentity_t        *subscriberIdentity;
  AccessMethod_t              *accessMethod;
  struct AccessMethod__accessType *accessType;
  NetworkAccessNodeIdentity_t *networkAccessNodeIdentity;
  IPAddress_t		      *iPAddress;
  AccessSessionID_t	      *accessSessionID;
  AccessSessionCharacteristics_t *accessSessionCharacteristics;
  Location_t                  *location;
  ProtocolSignal_t            *protocolSignal;
  struct Value                *signal1, *signal2, *signal3, *signal4, *signal5;
  IpAddress_t 		      *ipaddress1;
  INTEGER_t                   *prefix;

  char caseId[]      = "Access Accepted Case ID";
  char iAPSystemId[] = "Access Accepted System ID";

  int frac_value = 1234;
  int frac_digits = 4;
  int force_gmt = 1;

  time_t rawtime;
  struct tm *timestamp;

  asn_enc_rval_t ec;      /* Encoder return value  */

  time ( &rawtime );
  timestamp = gmtime ( &rawtime );

  prefix = calloc(1, sizeof(INTEGER_t));
  ipaddress1 = calloc(1, sizeof(IpAddress_t));

  signal1 = calloc(1, sizeof(struct Value));
  signal2 = calloc(1, sizeof(struct Value));
  signal3 = calloc(1, sizeof(struct Value));
  signal4 = calloc(1, sizeof(struct Value));
  signal5 = calloc(1, sizeof(struct Value));
  
  IasProtocol = calloc(1, sizeof(IasProtocol_t));
  if(!IasProtocol) {
    perror("IasProtocol calloc() failed");
    exit(-1);
  }

  location = calloc(1, sizeof(Location_t));
  if(!location) {
    perror("location calloc() failed");
    exit(-1);
  }

  accessSessionCharacteristics = calloc(1, sizeof(AccessSessionCharacteristics_t));
  if(!accessSessionCharacteristics) {
    perror("accessSessionCharacteristics calloc() failed");
    exit(-1);
  }

  accessSessionID = calloc(1, sizeof(AccessSessionID_t));
  if(!accessSessionID) {
    perror("accessSessionID calloc() failed");
    exit(-1);
  }

  subscriberIdentity = calloc(1, sizeof(SubscriberIdentity_t));
  if(!subscriberIdentity) {
    perror("subscriberIdentity calloc() failed");
    exit(-1);
  }

  networkAccessNodeIdentity = calloc(1, sizeof(NetworkAccessNodeIdentity_t));
  if(!networkAccessNodeIdentity) {
    perror("networkAccessNodeIdentity calloc() failed");
    exit(-1);
  }

  protocolSignal = calloc(1, sizeof(ProtocolSignal_t));
  if(!protocolSignal) {
    perror("protocolSignal calloc() failed");
    exit(-1);
  }

  accessMethod = calloc(1, sizeof(AccessMethod_t));
  if(!accessMethod) {
    perror("accessMethod calloc() failed");
    exit(-1);
  }

  accessType = calloc(1, sizeof(struct AccessMethod__accessType));
  if(!accessType) {
    perror("accessType calloc() failed");
    exit(-1);
  }

  iPAddress = calloc(1, sizeof(IPAddress_t));
  if(!iPAddress) {
    perror("iPAddress calloc() failed");
    exit(-1);
  }

  OBJECT_IDENTIFIER_set_arcs(&IasProtocol->protocolIdentifier, ias_laes_cmii_oid, sizeof(ias_laes_cmii_oid[0]), sizeof(ias_laes_cmii_oid) / sizeof(ias_laes_cmii_oid[0])); 

  /* Ias_Message */
  IasProtocol->iasMessage.present = IasMessage_PR_access_Accepted;

  /* caseId */
  OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(caseId), caseId);

  /* iAPSystemId */
  OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(iAPSystemId), iAPSystemId);

  /* timestamp */
  asn_time2GT_frac(&IAS_ACCESSACCEPTED(timestamp),timestamp,frac_value, frac_digits, force_gmt);

  /* subscriberIdentity */
  IAS_ACCESSACCEPTED(subscriberIdentity).present = Value_PR_stringVS;
  OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(subscriberIdentity).choice.stringVS, "SUBSCRIBER ID");

  //IAS_ACCESSACCEPTED(subscriberIdentity).present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(subscriberIdentity).choice.stringUTF8, "SUBSCRIBER ID");

  //IAS_ACCESSACCEPTED(subscriberIdentity).present = Value_PR_integer;
  //IAS_ACCESSACCEPTED(subscriberIdentity).choice.integer = 9;

  //IAS_ACCESSACCEPTED(subscriberIdentity).present = Value_PR_octets;
  //OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(subscriberIdentity).choice.octets, "SUBSCRIBER ID");

  //IAS_ACCESSACCEPTED(subscriberIdentity).present = Value_PR_numeric;
  //OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(subscriberIdentity).choice.numeric, "12345");

  /* accessMethod */

  //accessType->present = AccessMethod__accessType_PR_dialUp;
  accessType->present = AccessMethod__accessType_PR_dsl;
  //accessType->present = AccessMethod__accessType_PR_lan;
  //accessType->present = AccessMethod__accessType_PR_cable;
  //accessType->present = AccessMethod__accessType_PR_wiFi;
  //accessType->present = AccessMethod__accessType_PR_wiMax;

  //accessType->present = AccessMethod__accessType_PR_other;
  //OCTET_STRING_fromString(&accessType->choice.other, "12345");

  accessMethod->accessType = accessType;

  accessMethod->accessEquipmentID  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "EQUIPMENT ID", 12);

  accessMethod->partOfMultipleLogin = 0;

  IAS_ACCESSACCEPTED(accessMethod) = accessMethod;

  /* networkAccessNodeIdentity */
  networkAccessNodeIdentity->present = Value_PR_stringVS;
  OCTET_STRING_fromString(&networkAccessNodeIdentity->choice.stringVS, "NETWORK ACCESS NODE ID");

  //networkAccessNodeIdentity->present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&networkAccessNodeIdentity->choice.stringUTF8, "NETWORK ACCESS NODE ID");

  //networkAccessNodeIdentity->present = Value_PR_integer;
  //networkAccessNodeIdentity->choice.integer = 9;

  //networkAccessNodeIdentity->present = Value_PR_octets;
  //OCTET_STRING_fromString(&networkAccessNodeIdentity->choice.octets, "SUBSCRIBER ID");

  //networkAccessNodeIdentity->present = Value_PR_numeric;
  //OCTET_STRING_fromString(&networkAccessNodeIdentity->choice.numeric, "12345");

  IAS_ACCESSACCEPTED(networkAccessNodeIdentity) = networkAccessNodeIdentity;

  /* iPAddress */
  ipaddress(&iPAddress->address, "111.111.111.111");

  iPAddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  //iPAddress->allocationMethod = IPAddress__allocationMethod_PR_dynamic;
  //iPAddress->allocationMethod = IPAddress__allocationMethod_PR_unknown;
  //iPAddress->allocationMethod = IPAddress__allocationMethod_PR_notApplicable;

  iPAddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "12345", 5);;

  prefix = 3;
  iPAddress->prefixLen = &prefix;

  IAS_ACCESSACCEPTED(iPAddress) = iPAddress;

  /* accessSessionID */
  //IAS_ACCESSACCEPTED(accessSessionID).present = Value_PR_stringVS;
  //OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(accessSessionID).choice.stringVS, "ACCESS SESSION ID");

  //IAS_ACCESSACCEPTED(accessSessionID).present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(accessSessionID).choice.stringUTF8, "ACCESS SESSION ID");

  //IAS_ACCESSACCEPTED(accessSessionID).present = Value_PR_integer;
  //IAS_ACCESSACCEPTED(accessSessionID).choice.integer = 9;

  //IAS_ACCESSACCEPTED(accessSessionID).present = Value_PR_octets;
  //OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(accessSessionID).choice.octets, "ACCESS SESSION  ID");

  IAS_ACCESSACCEPTED(accessSessionID).present = Value_PR_numeric;
  OCTET_STRING_fromString(&IAS_ACCESSACCEPTED(accessSessionID).choice.numeric, "12345");

  /* accessSessionCharacteristics */
  accessSessionCharacteristics->present = Value_PR_stringVS;
  OCTET_STRING_fromString(&accessSessionCharacteristics->choice.stringVS, "Access Session Characteristics");

  //accessSessionCharacteristics->present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&accessSessionCharacteristics->choice.stringUTF8, "Access Session Characteristics");

  //accessSessionCharacteristics->present = Value_PR_integer;
  //accessSessionCharacteristics->choice.integer = 9;

  //accessSessionCharacteristics->present = Value_PR_octets;
  //OCTET_STRING_fromString(&accessSessionCharacteristics->choice.octets, "Access Session Characteristics");

  //accessSessionCharacteristics->present = Value_PR_numeric;
  //OCTET_STRING_fromString(&accessSessionCharacteristics->choice.numeric, "12345");

  IAS_ACCESSACCEPTED(accessSessionCharacteristics) = accessSessionCharacteristics;

  /* location */
  OCTET_STRING_fromString(&location->locationType, "TYPE");
  OCTET_STRING_fromString(&location->location, "LOCATION");
  IAS_ACCESSACCEPTED(location) = location;

  /* protocolSignal */
  //protocolSignal->protocol.present = Protocol_PR_radius;

  protocolSignal->protocol.present = Protocol_PR_other;
  OCTET_STRING_fromString(&protocolSignal->protocol.choice.other, "12345");
 
  signal1->present = Value_PR_stringVS;
  OCTET_STRING_fromString(&signal1->choice.stringVS, "SIGNAL 1 stringVS");
  asn_set_add(&protocolSignal->signal, signal1);

  signal2->present = Value_PR_stringUTF8;
  OCTET_STRING_fromString(&signal2->choice.stringUTF8, "SIGNAL 2 stringUTF8");
  asn_set_add(&protocolSignal->signal, signal2);

  signal3->present = Value_PR_integer;
  signal3->choice.integer = 9;
  asn_set_add(&protocolSignal->signal, signal3);

  signal4->present = Value_PR_octets;
  OCTET_STRING_fromString(&signal4->choice.octets, "SUBSCRIBER ID");
  asn_set_add(&protocolSignal->signal, signal4);

  signal5->present = Value_PR_numeric;
  OCTET_STRING_fromString(&signal5->choice.numeric, "12345");
  asn_set_add(&protocolSignal->signal, signal5);

  IAS_ACCESSACCEPTED(protocolSignal) = protocolSignal;

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_IasProtocol, IasProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode IasProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Access-Accepted message\n");
    }
  }

/* Also print the constructed IasProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_IasProtocol, IasProtocol);

return 0;
}
