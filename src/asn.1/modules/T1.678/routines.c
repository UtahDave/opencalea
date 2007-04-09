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

/* helper routines */

int ipaddress(IpAddress_t *IPAddress, char *ipaddress) {
  IPAddress->present = IpAddress_PR_ipV4;
  OCTET_STRING_fromString(&IPAddress->choice.ipV4, ipaddress);
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
