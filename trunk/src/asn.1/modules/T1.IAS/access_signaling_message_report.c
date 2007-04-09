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

#define IAS_ACCESSSIGNALINGMESSAGEREPORT(parm) (IasProtocol->iasMessage.choice.access_Signaling_Message_Report.parm)

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int access_signaling_message_report(FILE *fp) {

  int ias_laes_cmii_oid[] = { 1, 2, 840, 113737, 2, 1, 1, 0, 0 };

  IasProtocol_t               *IasProtocol;
  IPAddress_t		      *iPAddress;
  AccessSessionID_t           *accessSessionID;
  InterceptedSignalingMessage_t *ism1, *ism2, *ism3, *ism4, *ism5;
  A_SET_OF(struct InterceptedSignalingMessage) *signalingMsgs;

  char caseId[]      = "Access Session End Case ID";
  char iAPSystemId[] = "Access Session End System ID";

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

  signalingMsgs = calloc(1, sizeof(A_SET_OF(struct InterceptedSignalingMessage)));
  if(!signalingMsgs) {
    perror("signalingMsgs calloc() failed");
    exit(-1);
  }

  ism1 = calloc(1, sizeof(InterceptedSignalingMessage_t));
  ism2 = calloc(1, sizeof(InterceptedSignalingMessage_t));
  ism3 = calloc(1, sizeof(InterceptedSignalingMessage_t));
  ism4 = calloc(1, sizeof(InterceptedSignalingMessage_t));
  ism5 = calloc(1, sizeof(InterceptedSignalingMessage_t));

  accessSessionID = calloc(1, sizeof(AccessSessionID_t));
  if(!accessSessionID) {
    perror("accessSessionID calloc() failed");
    exit(-1);
  }

  OBJECT_IDENTIFIER_set_arcs(&IasProtocol->protocolIdentifier, ias_laes_cmii_oid, sizeof(ias_laes_cmii_oid[0]), sizeof(ias_laes_cmii_oid) / sizeof(ias_laes_cmii_oid[0])); 

  /* Ias_Message */
  IasProtocol->iasMessage.present = IasMessage_PR_access_Signaling_Message_Report;

  /* caseId */
  OCTET_STRING_fromString(&IAS_ACCESSSIGNALINGMESSAGEREPORT(caseId), caseId);

  /* iAPSystemId */
  OCTET_STRING_fromString(&IAS_ACCESSSIGNALINGMESSAGEREPORT(iAPSystemId), iAPSystemId);

  /* timestamp */
  asn_time2GT_frac(&IAS_ACCESSSIGNALINGMESSAGEREPORT(timestamp),timestamp,frac_value, frac_digits, force_gmt);

  /* accessSessionID */
  //IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).present = Value_PR_stringVS;
  //OCTET_STRING_fromString(&IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).choice.stringVS, "ACCESS SESSION ID");

  //IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).present = Value_PR_stringUTF8;
  //OCTET_STRING_fromString(&IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).choice.stringUTF8, "ACCESS SESSION ID");

  //IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).present = Value_PR_integer;
  //IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).choice.integer = 9;

  //IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).present = Value_PR_octets;
  //OCTET_STRING_fromString(&IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID).choice.octets, "ACCESS SESSION  ID");

  accessSessionID->present = Value_PR_numeric;
  OCTET_STRING_fromString(&accessSessionID->choice.numeric, "1234");

  IAS_ACCESSSIGNALINGMESSAGEREPORT(accessSessionID) = accessSessionID;

  /* signalingMsg */
  ism1->messageType = MessageType_radius;
  OCTET_STRING_fromString(&ism1->message, "Intercepted Signaling Message Radius");

  ism2->messageType = MessageType_diameter;
  OCTET_STRING_fromString(&ism2->message, "Intercepted Signaling Message Diameter");

  ism3->messageType = MessageType_xml;
  OCTET_STRING_fromString(&ism3->message, "Intercepted Signaling Message XML");

  ism4->messageType = MessageType_asndot1;
  OCTET_STRING_fromString(&ism4->message, "Intercepted Signaling Message ASN.1");

  ism5->messageType = MessageType_other;
  OCTET_STRING_fromString(&ism5->message, "Intercepted Signaling Message Other");

  asn_set_add(&IAS_ACCESSSIGNALINGMESSAGEREPORT(signalingMsg),ism1);
  asn_set_add(&IAS_ACCESSSIGNALINGMESSAGEREPORT(signalingMsg),ism2);
  asn_set_add(&IAS_ACCESSSIGNALINGMESSAGEREPORT(signalingMsg),ism3);
  asn_set_add(&IAS_ACCESSSIGNALINGMESSAGEREPORT(signalingMsg),ism4);
  asn_set_add(&IAS_ACCESSSIGNALINGMESSAGEREPORT(signalingMsg),ism5);
  
  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/

  if (fp) {
    ec = der_encode(&asn_DEF_IasProtocol, IasProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode IasProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote Access-Signaling-Message-Report message\n");
    }
  }

/* Also print the constructed IasProtocol XER encoded (XML) */
xer_fprint(stdout, &asn_DEF_IasProtocol, IasProtocol);

return 0;
}
