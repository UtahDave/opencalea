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

#define IAS_SUMMARYREPORT(parm) (IasProtocol->iasMessage.choice.data_Summary_Report.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int packet_data_summary_report(FILE *fp) {

  int ias_laes_cmii_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 0, 0 };
  int ias_laes_cmcc_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 1, 0 };
  
  IasProtocol_t           *IasProtocol;
  ContentIdentifier_t     *contentIdentifier;
  CallIdentity_t 	  *callID;
  CorrelationIdentifier_t *correlationID;
  StreamSet_t		  *streamSet;
  IPAddress_t             *sourceIPaddress;
  IPAddress_t             *destinationIPaddress;
  INTEGER_t               *source_prefix;
  INTEGER_t               *destination_prefix;

  char caseId[]      = "Data Stream Report Case ID";
  char iAPSystemId[] = "Data Stream Report System ID";

  int frac_value = 1234;
  int frac_digits = 4;
  int force_gmt = 1;

  time_t rawtime;
  struct tm *timestamp;

  asn_enc_rval_t ec;      /* Encoder return value  */

  time ( &rawtime );
  timestamp = gmtime ( &rawtime );

  IasProtocol = calloc(1, sizeof(IasProtocol_t));
  if(!IasProtocol) {
    perror("IasProtocol calloc() failed");
    exit(-1);
  }

  source_prefix = calloc(1, sizeof(INTEGER_t));
  if(!source_prefix) {
    perror("source_prefix calloc() failed");
    exit(-1);
  }

  destination_prefix = calloc(1, sizeof(INTEGER_t));
  if(!destination_prefix) {
    perror("destination_prefix calloc() failed");
    exit(-1);
  }

  sourceIPaddress = calloc(1, sizeof(IPAddress_t));
  if(!sourceIPaddress) {
    perror("sourceIPaddress calloc() failed");
    exit(-1);
  }

  destinationIPaddress = calloc(1, sizeof(IPAddress_t));
  if(!destinationIPaddress) {
    perror("destinationIPaddress calloc() failed");
    exit(-1);
  }

  contentIdentifier = calloc(1, sizeof(ContentIdentifier_t));
  if(!contentIdentifier) {
    perror("contentIdentifier calloc() failed");
    exit(-1);
  }

  streamSet = calloc(1, sizeof(StreamSet_t));
  if(!streamSet) {
    perror("streamSet calloc() failed");
    exit(-1);
  }

  callID = calloc(1, sizeof(CallIdentity_t));
  if(!callID) {
    perror("callID calloc() failed");
    exit(-1);
  }

  correlationID = calloc(1, sizeof(CorrelationIdentifier_t));
  if(!correlationID) {
    perror("correlationID calloc() failed");
    exit(-1);
  }

  OBJECT_IDENTIFIER_set_arcs(&IasProtocol->protocolIdentifier, ias_laes_cmii_oid, sizeof(ias_laes_cmii_oid[0]), sizeof(ias_laes_cmii_oid) / sizeof(ias_laes_cmii_oid[0])); 

  /* Ias_Message */
  IasProtocol->iasMessage.present = IasMessage_PR_data_Summary_Report;

  /* caseId */
  OCTET_STRING_fromString(&IAS_SUMMARYREPORT(caseId), caseId);

  /* iAPSystemId */
  OCTET_STRING_fromString(&IAS_SUMMARYREPORT(iAPSystemId), iAPSystemId);

  /* timestamp */
  asn_time2GT_frac(&IAS_SUMMARYREPORT(timestamp),timestamp,frac_value, frac_digits, force_gmt);

  /* contentIdentifier */

  IAS_SUMMARYREPORT(contentIdentifier).present = ContentIdentifier_PR_correlationID;
  OCTET_STRING_fromString(correlationID, "CORRELATION ID 123");
  memcpy(&IAS_SUMMARYREPORT(contentIdentifier).choice.correlationID, correlationID, sizeof(CorrelationIdentifier_t));

  //IAS_SUMMARYREPORT(contentIdentifier).present = ContentIdentifier_PR_callID;
  //callidentity(callID, "Data Stream Report MAIN", "Data Stream Report LEG");
  //memcpy(&IAS_SUMMARYREPORT(contentIdentifier).choice.callID, callID, sizeof(CallIdentity_t));

  /* streamSet */

  /* streamID */
  streamSet->streamID.present = Value_PR_stringVS;
  OCTET_STRING_fromString(&streamSet->streamID.choice.stringVS, "HEADER SET SUBSCRIBER ID");

  //streamSet->streamID.present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&streamSet->streamID.choice.stringUTF8, "HEADER SET SUBSCRIBER ID");

  //streamSet->streamID.present = Value_PR_integer;
  //streamSet->streamID.choice.integer = 9;

  //streamSet->streamID.present = Value_PR_octets;
  //OCTET_STRING_fromString(&streamSet->streamID.choice.octets, "HEADER SET SUBSCRIBER ID");

  //streamSet->streamID.present = Value_PR_numeric;
  //OCTET_STRING_fromString(&streamSet->streamID.choice.numeric, "12345");

  /* sourceIPaddress */
  sourceIPaddress->address.present = IpAddress_PR_ipV4;
  OCTET_STRING_fromString(&sourceIPaddress->address.choice.ipV4, "111.111.111.111");

  sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_dynamic;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_unknown;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_notApplicable;
  sourceIPaddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "12345", 5);
  source_prefix = 3;
  sourceIPaddress->prefixLen = &source_prefix;
  memcpy(&streamSet->sourceIPaddress, sourceIPaddress, sizeof(IPAddress_t));

  /* destinationIPAddress */
  ipaddress(&destinationIPaddress->address, "222.222.222.222");

  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_dynamic;
  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_unknown;
  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_notApplicable;
  //destinationIPaddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "54321", 5);
  //destination_prefix = 2;
  //destinationIPaddress->prefixLen = &destination_prefix;
  memcpy(&streamSet->destinationIPaddress, destinationIPaddress, sizeof(IPAddress_t));

  /* packetCount */
  streamSet->packetCount = 13;

  /* *sourcePortNumber */
  streamSet->sourcePortNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "3333", 4);

  /* *destinationPortNumber */
  streamSet->destinationPortNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "4444", 4);

  memcpy(&IAS_SUMMARYREPORT(streamSet), streamSet, sizeof(StreamSet_t));

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_IasProtocol, IasProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode IasProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Packet-Data-Stream-Report message\n");
    }
  }

/* Also print the constructed IasProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_IasProtocol, IasProtocol);

return 0;
}
