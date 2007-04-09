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

#define IAS_SESSIONALREADYESTABLISHED(parm) (IasProtocol->iasMessage.choice.session_Already_Established.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int packet_data_session_already_established(FILE *fp) {

  int ias_laes_cmii_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 0, 0 };
  int ias_laes_cmcc_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 1, 0 };
  
  IasProtocol_t               *IasProtocol;
  SubscriberIdentity_t        *subscriberIdentity;
  struct AccessMethod__accessType *accessType;
  PacketDataSessionID_t       *packetDataSessionID;
  LEA_CmC_Delivery_t          *deliveryInformation;
  IPAddress_t		      *iPAddress;
  AccessSessionID_t	      *accessSessionID;
  AccessSessionCharacteristics_t *accessSessionCharacteristics;
  Location_t                  *location;
  struct Value                *signal1, *signal2, *signal3, *signal4, *signal5;
  IpAddress_t 		      *ipaddress1;
  INTEGER_t                   *prefix;
  ContentIdentifier_t         *contentIdentifier;
  DeliveryIdentifier_t        *deliveryIdentifier;
  IAS_CCDeliveryFormat_t      *ccDeliveryFormat;

  IAS_LAES_CmCC_Module_OID_t  *atis_678_ASN1;

  CorrelationIdentifier_t *correlationID;
  CCCIdentity_t *cccId;
  CCAddress_t *ccAddress;
  CallIdentity_t *callID;

  char caseId[]      = "Session Already Established Case ID";
  char iAPSystemId[] = "Session Already Established System ID";

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

  packetDataSessionID = calloc(1, sizeof(PacketDataSessionID_t));
  if(!packetDataSessionID) {
    perror("packetDataSessionID calloc() failed");
    exit(-1);
  }
  
  deliveryInformation = calloc(1, sizeof(LEA_CmC_Delivery_t));
  if(!deliveryInformation) {
    perror("deliveryInformation calloc() failed");
    exit(-1);
  }
  
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

  iPAddress = calloc(1, sizeof(IPAddress_t));
  if(!iPAddress) {
    perror("iPAddress calloc() failed");
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

  OBJECT_IDENTIFIER_set_arcs(&IasProtocol->protocolIdentifier, ias_laes_cmii_oid, sizeof(ias_laes_cmii_oid[0]), sizeof(ias_laes_cmii_oid) / sizeof(ias_laes_cmii_oid[0])); 

  /* Ias_Message */
  IasProtocol->iasMessage.present = IasMessage_PR_session_Already_Established;

  /* caseId */
  OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(caseId), caseId);

  /* iAPSystemId */
  OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(iAPSystemId), iAPSystemId);

  /* timestamp */
  asn_time2GT_frac(&IAS_SESSIONALREADYESTABLISHED(timestamp),timestamp,frac_value, frac_digits, force_gmt);

  /* subscriberIdentity */
  IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).present = Value_PR_stringVS;
  OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).choice.stringVS, "SUBSCRIBER ID");

  //IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).choice.stringUTF8, "SUBSCRIBER ID");

  //IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).present = Value_PR_integer;
  //IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).choice.integer = 9;

  //IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).present = Value_PR_octets;
  //OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).choice.octets, "SUBSCRIBER ID");

  //IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).present = Value_PR_numeric;
  //OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(subscriberIdentity).choice.numeric, "12345");

  /* accessSessionID */
  accessSessionID->present = Value_PR_stringVS;
  OCTET_STRING_fromString(&accessSessionID->choice.stringVS, "ACCESS SESSION ID");

  //accessSessionID->present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&accessSessionID->choice.stringUTF8, "ACCESS SESSION ID");

  //accessSessionID->present = Value_PR_integer;
  //accessSessionID->choice.integer = 9;

  //accessSessionID->present = Value_PR_octets;
  //OCTET_STRING_fromString(&accessSessionID->choice.octets, "ACCESS SESSION  ID");

  //accessSessionID->present = Value_PR_numeric;
  //OCTET_STRING_fromString(&accessSessionID->choice.numeric, "12345");

  IAS_SESSIONALREADYESTABLISHED(accessSessionID) = accessSessionID;

  /* packetDataSessionID */
  IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).present = Value_PR_stringVS;
  OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).choice.stringVS, "SUBSCRIBER ID");

  //IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).choice.stringUTF8, "SUBSCRIBER ID");

  //IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).present = Value_PR_integer;
  //IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).choice.integer = 9;

  //IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).present = Value_PR_octets;
  //OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).choice.octets, "SUBSCRIBER ID");

  //IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).present = Value_PR_numeric;
  //OCTET_STRING_fromString(&IAS_SESSIONALREADYESTABLISHED(packetDataSessionID).choice.numeric, "12345");
 
  /* iPAddress */
  ipaddress(&iPAddress->address, "111.111.111.111");

  iPAddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  //iPAddress->allocationMethod = IPAddress__allocationMethod_PR_dynamic;
  //iPAddress->allocationMethod = IPAddress__allocationMethod_PR_unknown;
  //iPAddress->allocationMethod = IPAddress__allocationMethod_PR_notApplicable;

  iPAddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "12345", 5);;

  prefix = 3;
  iPAddress->prefixLen = &prefix;

  memcpy(&IAS_SESSIONALREADYESTABLISHED(iPAddress), iPAddress, sizeof(IPAddress_t));

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

  IAS_SESSIONALREADYESTABLISHED(accessSessionCharacteristics) = accessSessionCharacteristics;

  /* location */
  OCTET_STRING_fromString(&location->locationType, "TYPE");
  OCTET_STRING_fromString(&location->location, "LOCATION");
  IAS_SESSIONALREADYESTABLISHED(location) = location;

  /* deliveryInformation */

  /* contentIdentifier */

  //deliveryInformation->contentIdentifier.present = ContentIdentifier_PR_correlationID;
  //OCTET_STRING_fromString(correlationID, "CORRELATION ID 123");
  //memcpy(&deliveryInformation->contentIdentifier.choice.correlationID, correlationID, sizeof(CorrelationIdentifier_t));

  deliveryInformation->contentIdentifier.present = ContentIdentifier_PR_callID;
  callidentity(callID, "Delivery Information MAIN", "Delivery Information LEG");
  memcpy(&deliveryInformation->contentIdentifier.choice.callID, callID, sizeof(CallIdentity_t));

  /* deliveryIdentifier */

  //deliveryInformation->deliveryIdentifier.present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_combCCC;
  //OCTET_STRING_fromString(&cccId->choice.combCCC, "User Data combCCC");
  //memcpy(&deliveryInformation->deliveryIdentifier.choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryInformation->deliveryIdentifier.present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_sepCCCpair;
  //OCTET_STRING_fromString(&cccId->choice.sepCCCpair.sepXmitCCC, "User Data sepXmitCCC");
  //OCTET_STRING_fromString(&cccId->choice.sepCCCpair.sepRecvCCC, "User Data sepRecvCCC");
  //memcpy(&deliveryInformation->deliveryIdentifier.choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryInformation->deliveryIdentifier.present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indXmitCCC;
  //OCTET_STRING_fromString(&cccId->choice.indXmitCCC, "User Data indXmitCCC");
  //memcpy(&deliveryInformation->deliveryIdentifier.choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryInformation->deliveryIdentifier.present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indRecvCCC;
  //OCTET_STRING_fromString(&cccId->choice.indRecvCCC, "User Data indRecvCCC");
  //memcpy(&deliveryInformation->deliveryIdentifier.choice.cccId, cccId, sizeof(CCCIdentity_t));

  //deliveryInformation->deliveryIdentifier.present = DeliveryIdentifier_PR_cccId;
  //cccId->present = CCCIdentity_PR_indCCC;
  //OCTET_STRING_fromString(&cccId->choice.indCCC, "User Data indCCC");
  //memcpy(&deliveryInformation->deliveryIdentifier.choice.cccId, cccId, sizeof(CCCIdentity_t));

  deliveryInformation->deliveryIdentifier.present = DeliveryIdentifier_PR_ccAddress;

  ipaddress(&ccAddress->leaIPAddress, "111.111.111.111");
  OCTET_STRING_fromString(&ccAddress->leaPortNumber, "1234");
  memcpy(&deliveryInformation->deliveryIdentifier.choice.ccAddress, ccAddress, sizeof(CCAddress_t));

  /* ccDeliveryFormat */

  //deliveryInformation->ccDeliveryFormat.present = IAS_CCDeliveryFormat_PR_scteDatagram;

  deliveryInformation->ccDeliveryFormat.present = IAS_CCDeliveryFormat_PR_atis_678_ASN1;
  OBJECT_IDENTIFIER_set_arcs(&deliveryInformation->ccDeliveryFormat.choice.atis_678_ASN1, ias_laes_cmcc_oid, sizeof(ias_laes_cmcc_oid[0]), sizeof(ias_laes_cmcc_oid) / sizeof(ias_laes_cmcc_oid[0])); 

  //deliveryInformation->ccDeliveryFormat.present = IAS_CCDeliveryFormat_PR_iasDatagram;

  IAS_SESSIONALREADYESTABLISHED(deliveryInformation) = deliveryInformation;
  
  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_IasProtocol, IasProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode IasProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Packet-Data-Session-Already-Established message\n");
    }
  }

/* Also print the constructed IasProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_IasProtocol, IasProtocol);

return 0;
}
