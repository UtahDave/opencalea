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

#include "common.h"
#include "calea.h"

int encode_laes_protocol(HEADER *dfheader, LAESProtocol_t *LAESProtocol) {

  /*----------------------*/
  /* BER encode the data  */
  /*----------------------*/
  asn_enc_rval_t ec;      /* Encoder return value  */
  char *buffer;
 
  dfheader->encoded = 0;
  dfheader->encoded_size = 0;

  /* Print the constructed LAESProtocol XER encoded (XML) */
  // xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);

  /* first determine the size of the encoded data */
  ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, 0, 0);
  if(ec.encoded == -1) {
    debug_5("Could not encode LAESProtocol (at %s)", ec.failed_type ? ec.failed_type->name : "unknown");
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
      ec = der_encode_to_buffer(&asn_DEF_LAESProtocol, LAESProtocol, buffer, ec.encoded);
      if(ec.encoded == -1) {
        debug_5("Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
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

int directsignalreporting(HEADER *dfheader) {

  LAESProtocol_t                 *LAESProtocol;
  EnhancedProtocol_t             *enhancedProtocol;
  DirectSignalReporting_t        *directSignalReporting;
  CorrelationIdentifier_t        *correlationIdentifier;
  EncapsulatedSignalingMessage_t *encapsulatedSignalingMessage;

  struct DirectSignalReporting__signalingMsg *signalingMsg;

  int oid[] = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };

  char sigprot[] = "SIP"; 

  int rc;

  int frac_digits = 4;
  int force_gmt = 1;

  struct tm *UTCtime;

  UTCtime = gmtime ( &dfheader->sec );

  LAESProtocol                 = CALLOC(LAESProtocol_t);
  enhancedProtocol             = CALLOC(EnhancedProtocol_t);
  directSignalReporting        = CALLOC(DirectSignalReporting_t);
  correlationIdentifier        = CALLOC(CorrelationIdentifier_t);
  encapsulatedSignalingMessage = CALLOC(EncapsulatedSignalingMessage_t);

  signalingMsg = CALLOC(struct DirectSignalReporting__signalingMsg);

  LAESProtocol->enhancedProtocol = enhancedProtocol;
  LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;

  rc = OBJECT_IDENTIFIER_set_arcs(&enhancedProtocol->protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0]));
  assert(rc == 0);

  /* LAESMessage: DirectSignalReporting */
  enhancedProtocol->laesMessage.present = LaesMessage_PR_directSignalReporting;
  enhancedProtocol->laesMessage.directSignalReporting = directSignalReporting;

  /* caseId */
  OCTET_STRING_fromString(&directSignalReporting->caseId, dfheader->caseId);

  /* iAPSystemId */
  directSignalReporting->iAPSystemId  = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, dfheader->iAPSystemId, strlen(dfheader->iAPSystemId));;

  /* timestamp */
  asn_time2GT_frac(&directSignalReporting->timestamp, UTCtime, (int)(dfheader->usec), frac_digits, force_gmt);

  /* correlationID */
  OCTET_STRING_fromBuf(correlationIdentifier, dfheader->correlationID, strlen(dfheader->correlationID));
  memcpy(&directSignalReporting->correlationID, correlationIdentifier, sizeof(CorrelationIdentifier_t));

  /* signalingMsg */
  OCTET_STRING_fromString(&encapsulatedSignalingMessage->signalingProt, sigprot);
  OCTET_STRING_fromBuf(&encapsulatedSignalingMessage->sigMsg, dfheader->payload, dfheader->payload_size);

  asn_set_add(signalingMsg, encapsulatedSignalingMessage);
  memcpy(&directSignalReporting->signalingMsg, signalingMsg, sizeof(struct DirectSignalReporting__signalingMsg));

  rc = encode_laes_protocol(dfheader, LAESProtocol);

  /* Free Memory Allocations */

  CorrelationIdentifier_free(&asn_DEF_CorrelationIdentifier, correlationIdentifier, 0);
  //free(correlationID);

  free(enhancedProtocol);
  free(directSignalReporting);
  free(encapsulatedSignalingMessage);

  free(LAESProtocol);

  return rc;

}
