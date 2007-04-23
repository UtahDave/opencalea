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

#include "common.h"
#include "calea.h"

#define CALLOC(parm) (parm *)Calloc(sizeof(parm))

void *Calloc(size_t size) {
  char *ptr;
  ptr = calloc(1, size);
  if(!ptr) {
    perror("calloc() failed");
    exit(-1);
  }
  return ptr;
}

int encode_ias_cc(HEADER *dfheader, IAS_CC_APDU_t *IAS_CC_APDU) {

  /*----------------------*/
  /* BER encode the data  */
  /*----------------------*/
  asn_enc_rval_t ec;      /* Encoder return value  */
  char *buffer;
  
  /* Print the constructed IAS_CC_APDU XER encoded (XML) */
  xer_fprint(stdout, &asn_DEF_IAS_CC_APDU, IAS_CC_APDU);

  /* first determine the size of the encoded data */
  ec = der_encode(&asn_DEF_IAS_CC_APDU, IAS_CC_APDU, 0, 0);
  if(ec.encoded == -1) {
    debug_5("Could not encode IAS_CC_APDU (at %s)", ec.failed_type ? ec.failed_type->name : "unknown");
    return -1;
  } else {
    /* allocate space to hold the encoded data */
    buffer = (char *)calloc(1, ec.encoded);
    if (!buffer) {
      bzero(buffer, ec.encoded);
      /* encode the data */
      ec = der_encode_to_buffer(&asn_DEF_IAS_CC_APDU, IAS_CC_APDU, buffer, ec.encoded);
      if(ec.encoded == -1) {
        debug_5("Could not encode IAS_CC_APDU (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
        free(buffer);
        return -1;
      } else {
        /* save the address and size of the encoded data */
        dfheader->encoded = buffer;
        dfheader->encoded_size = ec.encoded;
        return 0;
      }
    } else {
      debug_5("Could not allocate %d bytes for buffer to encode BER", (int)ec.encoded);
      return -1;
    }
  }

  return -1;
}

int ias_cc_apdu(HEADER *dfheader) {

  IAS_CC_APDU_t           *IAS_CC_APDU;
  CCDeliveryHeader_t	  *ccDeliveryHeader;

  ContentIdentifier_t	  *contentIdentifier;
  CorrelationIdentifier_t *correlationID;

  PacketDirection_t	  packetDirection;
  TimeStamp_t		  *timeStamp;

  // int ccdelivery_oid[] = { 1, 2, 840, 113737, 2, 1, 0, 1, 1 };

  int frac_digits = 4;
  int force_gmt = 1;
  int rc = 0;

  struct tm *UTCtime;

  UTCtime = gmtime ( &dfheader->sec );

  IAS_CC_APDU       = CALLOC(IAS_CC_APDU_t);
  ccDeliveryHeader  = CALLOC(CCDeliveryHeader_t);
  correlationID     = CALLOC(CorrelationIdentifier_t);
  contentIdentifier = CALLOC(ContentIdentifier_t);
  timeStamp         = CALLOC(TimeStamp_t);

  /* ccDeliveryHeader */
  IAS_CC_APDU->ccDeliveryHeader = ccDeliveryHeader;

  /* caseId */
  ccDeliveryHeader->correlationInfo.caseId = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, dfheader->caseId, strlen(dfheader->caseId));

  /* iAPSystemId */
  ccDeliveryHeader->correlationInfo.iapId = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, dfheader->iAPSystemId, strlen(dfheader->iAPSystemId));;

  /* contentIdentifier */
  ccDeliveryHeader->correlationInfo.contentIdentifier.present = ContentIdentifier_PR_correlationID;
  OCTET_STRING_fromString(correlationID, dfheader->correlationID);
  memcpy(&ccDeliveryHeader->correlationInfo.contentIdentifier.correlationID, correlationID, sizeof(CorrelationIdentifier_t));

  /* timestamp */
  asn_time2GT_frac(timeStamp, UTCtime, (int)(dfheader->usec), frac_digits, force_gmt);
  ccDeliveryHeader->timeStamp = timeStamp;

  /* packetDirection */
  //packetDirection = PacketDirection_fromSubject;
  packetDirection = PacketDirection_toSubject;
  ccDeliveryHeader->packetDirection = &packetDirection;

  /* sequenceNumber */
  ccDeliveryHeader->sequenceNumber = &dfheader->sequenceNumber;

  /* payload */
  OCTET_STRING_fromBuf(&IAS_CC_APDU->payload, dfheader->payload, dfheader->payload_size);

  rc = encode_ias_cc(dfheader, IAS_CC_APDU);

  /* Free Memory Allocations */

  OCTET_STRING_free(&asn_DEF_OCTET_STRING, ccDeliveryHeader->correlationInfo.caseId, 0);
  OCTET_STRING_free(&asn_DEF_OCTET_STRING, ccDeliveryHeader->correlationInfo.iapId, 0);
  free(ccDeliveryHeader);

  CorrelationIdentifier_free(&asn_DEF_CorrelationIdentifier, correlationID, 0);
  //free(correlationID);

  free(timeStamp);

  free(contentIdentifier);

  free(IAS_CC_APDU);

  return rc;

}
