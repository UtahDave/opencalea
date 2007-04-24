/*
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

#include "common.h"
#include "calea.h"

int encode_ias_protocol(HEADER *dfheader, IasProtocol_t *IasProtocol) {

  /*----------------------*/
  /* BER encode the data  */
  /*----------------------*/
  asn_enc_rval_t ec;      /* Encoder return value  */
  char *buffer;

  /* Print the constructed IasProtocol XER encoded (XML) */
  // xer_fprint(stdout, &asn_DEF_IasProtocol, IasProtocol);

  /* first determine the size of the encoded data */
  ec = der_encode(&asn_DEF_IasProtocol, IasProtocol, 0, 0);
  if(ec.encoded == -1) {
    debug_5("Could not encode IasProtocol (at %s)", ec.failed_type ? ec.failed_type->name : "unknown");
    return -1;
  } else {
    /* allocate space to hold the encoded data */
    buffer = (char *)calloc(1, ec.encoded);
    if (!buffer) {
      debug_5("Could not allocate %d bytes for buffer to encode BER", (int)ec.encoded);
      return -1;
    } else {
      bzero(buffer, ec.encoded);
      /* encode the data */
      ec = der_encode_to_buffer(&asn_DEF_IasProtocol, IasProtocol, buffer, ec.encoded);
      if(ec.encoded == -1) {
        debug_5("Could not encode IasProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
        free(buffer);
        return -1;
      } else {
        /* save the address and size of the encoded data */
        dfheader->encoded = buffer;
        dfheader->encoded_size = ec.encoded;
        return 0;
      }
    }
  }

  return -1;
}

int packet_data_header_report(HEADER *dfheader) {

  int ias_laes_cmii_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 0, 0 };
  //int ias_laes_cmcc_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 1, 0 };
  
  IasProtocol_t               *IasProtocol;
  Packet_Data_Header_Report_t *Packet_Data_Header_Report;
  ContentIdentifier_t     *contentIdentifier;
  CallIdentity_t 	  *callID;
  CorrelationIdentifier_t *correlationID;
  HeaderSet_t		  *headerSet;
  IPAddress_t             *sourceIPaddress;
  IPAddress_t             *destinationIPaddress;

  int frac_digits = 4;
  int force_gmt = 1;
  int rc = 0;

  struct tm *UTCtime;

  UTCtime = gmtime ( &dfheader->sec );

  IasProtocol               = CALLOC(IasProtocol_t);
  Packet_Data_Header_Report = CALLOC(Packet_Data_Header_Report_t);
  sourceIPaddress      = CALLOC(IPAddress_t);
  destinationIPaddress = CALLOC(IPAddress_t);
  contentIdentifier    = CALLOC(ContentIdentifier_t);
  callID               = CALLOC(CallIdentity_t);
  correlationID        = CALLOC(CorrelationIdentifier_t);

  headerSet = calloc(1, sizeof(HeaderSet_t));
  if(!headerSet) {
    perror("headerSet calloc() failed");
    exit(-1);
  }

  OBJECT_IDENTIFIER_set_arcs(&IasProtocol->protocolIdentifier, ias_laes_cmii_oid, sizeof(ias_laes_cmii_oid[0]), sizeof(ias_laes_cmii_oid) / sizeof(ias_laes_cmii_oid[0])); 


  /* Ias_Message */
  IasProtocol->iasMessage.present = IasMessage_PR_data_Header_Report;

  IasProtocol->iasMessage.data_Header_Report = Packet_Data_Header_Report;
 
  /* caseId */
  OCTET_STRING_fromString(&Packet_Data_Header_Report->caseId, dfheader->caseId);

  /* iAPSystemId */
  OCTET_STRING_fromString(&Packet_Data_Header_Report->iAPSystemId,  dfheader->iAPSystemId);

  /* timestamp */
  asn_time2GT_frac(&Packet_Data_Header_Report->timestamp, UTCtime, (int)(dfheader->usec), frac_digits, force_gmt);

  /* contentIdentifier */
  Packet_Data_Header_Report->contentIdentifier.present = ContentIdentifier_PR_correlationID;
  OCTET_STRING_fromString(&Packet_Data_Header_Report->contentIdentifier.correlationID, dfheader->correlationID);

  //Packet_Data_Header_Report->contentIdentifier.present = ContentIdentifier_PR_callID;
  //callidentity(callID, "Data Header Report MAIN", "Data Header Report LEG");
  //memcpy(&HEADERREPORT(contentIdentifier).callID, callID, sizeof(CallIdentity_t));

  /* headerSet */

  /* streamID */
  Packet_Data_Header_Report->headerSet.streamID.present = Value_PR_stringVS;
  OCTET_STRING_fromString(&Packet_Data_Header_Report->headerSet.streamID.stringVS, "HEADER SET SUBSCRIBER ID");

  //HEADERREPORT(headerSet).streamID.present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.stringUTF8, "HEADER SET SUBSCRIBER ID");

  //HEADERREPORT(headerSet).streamID.present = Value_PR_integer;
  //HEADERREPORT(headerSet).streamID.integer = 9;

  //HEADERREPORT(headerSet).streamID.present = Value_PR_octets;
  //OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.octets, "HEADER SET SUBSCRIBER ID");

  //HEADERREPORT(headerSet).streamID.present = Value_PR_numeric;
  //OCTET_STRING_fromString(&HEADERREPORT(headerSet).streamID.numeric, "12345");

  /* sourceIPaddress */
  sourceIPaddress->address.present = IpAddress_PR_ipV4;
  OCTET_STRING_fromString(&sourceIPaddress->address.ipV4, dfheader->src_ip);

  sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_dynamic;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_unknown;
  //sourceIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_notApplicable;
  //sourceIPaddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "12345", 5);
  //sourceIPaddress.prefixLen = (long)3;
  memcpy(&Packet_Data_Header_Report->headerSet.sourceIPaddress, sourceIPaddress, sizeof(IPAddress_t));

  /* destinationIPAddress */
  destinationIPaddress->address.present = IpAddress_PR_ipV4;
  OCTET_STRING_fromString(&destinationIPaddress->address.ipV4, dfheader->dst_ip);

  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_static;
  destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_dynamic;
  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_unknown;
  //destinationIPaddress->allocationMethod.present = IPAddress__allocationMethod_PR_notApplicable;
  //destinationIPaddress->iPv6FlowLabel  = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, "54321", 5);
  //destinationIPaddress.prefixLen = (long)2;

  memcpy(&Packet_Data_Header_Report->headerSet.destinationIPaddress, destinationIPaddress, sizeof(IPAddress_t));

  /* *sourcePortNumber */
  Packet_Data_Header_Report->headerSet.sourcePortNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "3333", 4);

  /* *destinationPortNumber */
  Packet_Data_Header_Report->headerSet.destinationPortNumber  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "4444", 4);

  rc = encode_ias_protocol(dfheader, IasProtocol);

  return rc;
}
