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

#define HEADERREPORT(parm) (IasProtocol->iasMessage.choice.data_Header_Report.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int packet_data_header_report(FILE *fp) {

  int ias_laes_cmii_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 0, 0 };
  int ias_laes_cmcc_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 1, 0 };
  
  IasProtocol_t           *IasProtocol;
  ContentIdentifier_t     *contentIdentifier;
  CallIdentity_t 	  *callID;
  CorrelationIdentifier_t *correlationID;
  HeaderSet_t		  *headerSet;
  IPAddress_t             *sourceIPaddress;
  IPAddress_t             *destinationIPaddress;
  INTEGER_t               *source_prefix;
  INTEGER_t               *destination_prefix;

  char caseId[]      = "Data Header Report Case ID";
  char iAPSystemId[] = "Data Header Report System ID";

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

  headerSet = calloc(1, sizeof(HeaderSet_t));
  if(!headerSet) {
    perror("headerSet calloc() failed");
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
  IasProtocol->iasMessage.present = IasMessage_PR_data_Header_Report;

  /* caseId */
  OCTET_STRING_fromString(&HEADERREPORT(caseId), caseId);

  /* iAPSystemId */
  OCTET_STRING_fromString(&HEADERREPORT(iAPSystemId), iAPSystemId);

  /* timestamp */
  asn_time2GT_frac(&HEADERREPORT(timestamp),timestamp,frac_value, frac_digits, force_gmt);

  /* contentIdentifier */

  HEADERREPORT(contentIdentifier).present = ContentIdentifier_PR_correlationID;
  OCTET_STRING_fromString(correlationID, "CORRELATION ID 123");
  memcpy(&HEADERREPORT(contentIdentifier).choice.correlationID, correlationID, sizeof(CorrelationIdentifier_t));

  //HEADERREPORT(contentIdentifier).present = ContentIdentifier_PR_callID;
  //callidentity(callID, "Data Header Report MAIN", "Data Header Report LEG");
  //memcpy(&HEADERREPORT(contentIdentifier).choice.callID, callID, sizeof(CallIdentity_t));

  /* headerSet */

  /* streamID */
  HEADERREPORT(headerSet).streamID.present = Value_PR_stringVS;
  OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.choice.stringVS, "HEADER SET SUBSCRIBER ID");

  //HEADERREPORT(headerSet).streamID.present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.choice.stringUTF8, "HEADER SET SUBSCRIBER ID");

  //HEADERREPORT(headerSet).streamID.present = Value_PR_integer;
  //HEADERREPORT(headerSet).streamID.choice.integer = 9;

  //HEADERREPORT(headerSet).streamID.present = Value_PR_octets;
  //OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.choice.octets, "HEADER SET SUBSCRIBER ID");

  //HEADERREPORT(headerSet).streamID.present = Value_PR_numeric;
  //OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.choice.numeric, "12345");

  /* sourceIPaddress */
  sourceIPaddress->address.present = IpAddress_PR_ipV4;
  OCTET_STRING_fromString(&sourceIPaddress->address.choice.ipV4, "111.111.111.111");

  sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_dynamic;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_unknown;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_notApplicable;
  //sourceIPaddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "12345", 5);
  //source_prefix = 3;
  //sourceIPaddress->prefixLen = &source_prefix;
  memcpy(&HEADERREPORT(headerSet).sourceIPaddress, sourceIPaddress, sizeof(IPAddress_t));

  /* destinationIPAddress */
  ipaddress(&destinationIPaddress->address, "222.222.222.222");

  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_dynamic;
  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_unknown;
  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_notApplicable;
  //destinationIPaddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "54321", 5);
  destination_prefix = 2;
  destinationIPaddress->prefixLen = &destination_prefix;
  memcpy(&HEADERREPORT(headerSet).destinationIPaddress, destinationIPaddress, sizeof(IPAddress_t));

  /* *sourcePortNumber */
  HEADERREPORT(headerSet).sourcePortNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "3333", 4);

  /* *destinationPortNumber */
  HEADERREPORT(headerSet).destinationPortNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "4444", 4);


  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_IasProtocol, IasProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode IasProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Packet-Data-Header-Report message\n");
    }
  }

/* Also print the constructed IasProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_IasProtocol, IasProtocol);

return 0;
}
