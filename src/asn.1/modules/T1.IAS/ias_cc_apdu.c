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
#include "IAS-CC-APDU.h"
#include "CCDeliveryHeader.h"
#include "PacketDirection.h"

#define CALLOC(parm) (parm *)Calloc(sizeof(parm))

void *Calloc(size_t size);

int ias_cc_apdu(FILE *fp) {

  IAS_CC_APDU_t           *IAS_CC_APDU;
  CCDeliveryHeader_t	  *ccDeliveryHeader;

  ContentIdentifier_t	  *contentIdentifier;
  CorrelationIdentifier_t *correlationID;

  PacketDirection_t	  packetDirection;
  TimeStamp_t		  *timestamp;

  long			  sequenceNumber;

  int ccdelivery_oid[] = { 1, 2, 840, 113737, 2, 1, 0, 1, 1 };

  char caseId[]   = "IAS_CC_APDU CaseID";
  char iapId[] = "IAS_CC_APDU SystemID";

  int frac_value = 1234;
  int frac_digits = 4;
  int force_gmt = 1;
  int ret;
  int i;

  time_t rawtime;
  struct tm *timeStamp;

  asn_enc_rval_t ec;      /* Encoder return value  */

  time ( &rawtime );
  timeStamp = gmtime ( &rawtime );

  IAS_CC_APDU       = CALLOC(IAS_CC_APDU_t);
  ccDeliveryHeader  = CALLOC(CCDeliveryHeader_t);
  correlationID     = CALLOC(CorrelationIdentifier_t);
  contentIdentifier = CALLOC(ContentIdentifier_t);
  timestamp         = CALLOC(TimeStamp_t);

  /* ccDeliveryHeader */

  /* caseId */
  ccDeliveryHeader->correlationInfo.caseId = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, caseId, strlen(caseId));;

  /* iapId */
  ccDeliveryHeader->correlationInfo.iapId = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, iapId, strlen(iapId));;

  /* contentIdentifier */
  ccDeliveryHeader->correlationInfo.contentIdentifier.present = ContentIdentifier_PR_correlationID;
  OCTET_STRING_fromString(correlationID, "CORRELATION ID 123");
  memcpy(&ccDeliveryHeader->correlationInfo.contentIdentifier.correlationID, correlationID, sizeof(CorrelationIdentifier_t));

  /* timestamp */
  asn_time2GT_frac(timestamp, timeStamp,frac_value, frac_digits, force_gmt);
  ccDeliveryHeader->timeStamp = timestamp;

  /* packetDirection */
  //packetDirection = PacketDirection_fromSubject;
  packetDirection = PacketDirection_toSubject;
  ccDeliveryHeader->packetDirection = &packetDirection;

  /* sequenceNumber */
  sequenceNumber = 1;
  ccDeliveryHeader->sequenceNumber = &sequenceNumber;

  /* */  
  IAS_CC_APDU->ccDeliveryHeader = ccDeliveryHeader;

  /* payload */
  OCTET_STRING_fromString(&IAS_CC_APDU->payload, "PAYLOAD DATA");

  encode_ias_cc(fp, IAS_CC_APDU);

return 0;
}
