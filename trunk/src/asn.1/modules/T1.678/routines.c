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

#include "LAESProtocol.h"

/* This is a custom function which writes the encoded output into some FILE stream. */
static int write_out(const void *buffer, size_t size, void *app_key) {
FILE *out_fp = app_key;
size_t wrote;
wrote = fwrite(buffer, 1, size, out_fp);
return (wrote == size) ? 0 : -1;
}

int encode(FILE *fp, LAESProtocol_t *LAESProtocol) {

  /*------------------------------------------*/
  /* BER encode the data if FILE fp is open   */
  /*------------------------------------------*/
  asn_enc_rval_t ec;      /* Encoder return value  */

  if (fp) {
    ec = der_encode(&asn_DEF_LAESProtocol, LAESProtocol, write_out, fp);
    if(ec.encoded == -1) {
      fprintf(stderr, "Could not encode LAESProtocol (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
      exit(65); /* better, EX_DATAERR */
    } else {
      fprintf(stderr, "Wrote SubjectSignal message\n");
    }
  }

  /* Also print the constructed LAESProtocol XER encoded (XML) */
  xer_fprint(stdout, &asn_DEF_LAESProtocol, LAESProtocol);
}


/* helper routines */

void *Calloc(size_t size) {
  char *ptr;
  ptr = calloc(1, size);
  if(!ptr) {
    perror("calloc() failed");
    exit(-1);
  }
  return ptr;
}

int ipaddress(IpAddress_t *IPAddress, char *ipaddress) {
  IPAddress->present = IpAddress_PR_ipV4;
  OCTET_STRING_fromString(&IPAddress->ipV4, ipaddress);
}

int callidentity(CallIdentity_t *CallIdentity, char *main, char *leg) {
  OCTET_STRING_fromString(&CallIdentity->main, main);
  CallIdentity->leg = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, leg, strlen(leg));
}

int encapsulatedsignalingmessage(EncapsulatedSignalingMessage_t *EncapsulatedSignalingMessage,
				 char *signalingProt,
				 char *sigMsg) {
  OCTET_STRING_fromString(&EncapsulatedSignalingMessage->signalingProt, signalingProt);
  OCTET_STRING_fromString(&EncapsulatedSignalingMessage->sigMsg, sigMsg);
}

int forkedcallinformation(ForkedCallInformation_t *ForkedCallInformation, 
                          CallIdentity_t          *forkedCallID, 
                          PartyIdentity_t         *calledParty) {
  memcpy(&ForkedCallInformation->forkedCallID, forkedCallID, sizeof(CallIdentity_t));
  memcpy(&ForkedCallInformation->calledParty,  calledParty,  sizeof(PartyIdentity_t));
}
