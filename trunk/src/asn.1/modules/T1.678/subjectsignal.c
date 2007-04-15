#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "LAESProtocol.h"

#define CALLOC(parm) (parm *)Calloc(sizeof(parm))

void *Calloc(size_t size);

int subjectsignal(FILE *fp) {

LAESProtocol_t     *LAESProtocol;
EnhancedProtocol_t *enhancedProtocol;
SubjectSignal_t    *subjectSignal;
MediaInformation_t *MediaInformation;

ProtocolSpecificParameters_t *protocolSpecificParameters;

CallIdentity_t  *CallIdentity;

PartyIdentity_t *SignaledPartyIdentity;
PartyIdentity_t *SignalingPartyIdentity;

IpAddress_t *SignaledIPAddress;
IpAddress_t *SignalingIPAddress;

EncapsulatedSignalingMessage_t *EncapsulatedSignalingMessage;

SipHeader_t *SipHeader, *psp_sipBodyHeader;

struct SubjectSignal__input        *input;
struct SubjectSignal__signal       *signal;
struct SubjectSignal__signalingMsg *signalingMsg;
struct SubjectSignal__signal__refer *refer;
struct SubjectSignal__signal__refer__sip *refer_sip;

struct ProtocolSpecificParameters__sip            *psp_sip;
struct ProtocolSpecificParameters__sip__sipHeader *psp_sipHeader;
struct ProtocolSpecificParameters__sip__sipBody   *psp_sipBody;

struct SubjectSignal__input__userInput *userInput;
struct SubjectSignal__input__translationInput *translationInput;

A_SET_OF(SipHeader_t) *SipHeaders, *psp_sipBodyHeaders;

char dialed_digits[] = "18005551212";
char sigprot[] = "Encaps Sig Prot"; 
char sigmsg[] = "Encaps Sig Msg"; 
char sip_header[] = "SIP HEADER"; 
char sip_bodyheader[] = "SIP BODY HEADER"; 
char sip_bodycontents[] = "SIP BODY CONTENTS"; 
char sdp[] = "SDP"; 
char generic[] = "GENERIC"; 
char caseId[] = "TestCase";
char systemID[] = "OpenSER";
char callId_main[] = "Call Id MAIN";
char callId_leg[] = "Call Id LEG";
char signaled_partyId_context[] = "Signaled Party Id Context";
char signaling_partyId_context[] = "Signaling Party Id Context";
char signaledPartyId[] = "Signaled Party Id";
char signalingPartyId[] = "Signaling Party Id";
char signaled_ipaddress[] = "000.000.000.000";
char signaling_ipaddress[] = "999.999.999.999";

int frac_value = 1234;
int frac_digits = 4;
int force_gmt = 1;
int ret;

time_t rawtime;
struct tm *timestamp;

asn_enc_rval_t ec;      /* Encoder return value  */

int oid[] = { 1, 2, 840, 113737, 2, 1, 0, 0, 0, 1 };

time ( &rawtime );
timestamp = gmtime ( &rawtime );

LAESProtocol                 = CALLOC(LAESProtocol_t);
enhancedProtocol             = CALLOC(EnhancedProtocol_t);
EncapsulatedSignalingMessage = CALLOC(EncapsulatedSignalingMessage_t);
subjectSignal                = CALLOC(SubjectSignal_t);
protocolSpecificParameters   = CALLOC(ProtocolSpecificParameters_t);
MediaInformation             = CALLOC(MediaInformation_t);
CallIdentity                 = CALLOC(CallIdentity_t);
SignaledPartyIdentity        = CALLOC(PartyIdentity_t);
SignalingPartyIdentity       = CALLOC(PartyIdentity_t);
SignaledIPAddress            = CALLOC(IpAddress_t);
SignalingIPAddress           = CALLOC(IpAddress_t);

input        = CALLOC(struct SubjectSignal__input);
signal       = CALLOC(struct SubjectSignal__signal);
signalingMsg = CALLOC(struct SubjectSignal__signalingMsg);

psp_sip		 = CALLOC(struct ProtocolSpecificParameters__sip);
psp_sipHeader    = CALLOC(struct ProtocolSpecificParameters__sip__sipHeader);
psp_sipBody      = CALLOC(struct ProtocolSpecificParameters__sip__sipBody);

userInput        = CALLOC(struct SubjectSignal__input__userInput);
translationInput = CALLOC(struct SubjectSignal__input__translationInput);
refer            = CALLOC(struct SubjectSignal__signal__refer);
refer_sip        = CALLOC(struct SubjectSignal__signal__refer__sip);

SipHeaders = calloc(1, sizeof(A_SET_OF(SipHeader_t)));
if(!SipHeaders) {
  perror("SipHeaders calloc() failed");
  exit(-1);
}

psp_sipBodyHeaders = calloc(1, sizeof(A_SET_OF(SipHeader_t)));
if(!psp_sipBodyHeaders) {
  perror("psp_sipBodyHeaders calloc() failed");
  exit(-1);
}

LAESProtocol->enhancedProtocol = enhancedProtocol;
LAESProtocol->present = LAESProtocol_PR_enhancedProtocol;

ret = OBJECT_IDENTIFIER_set_arcs(&enhancedProtocol->protocolIdentifier, oid, sizeof(oid[0]), sizeof(oid) / sizeof(oid[0]));
assert(ret == 0);

/* LAESMessage: SubjectSignal */
enhancedProtocol->laesMessage.present = LaesMessage_PR_subjectSignal;
enhancedProtocol->laesMessage.subjectSignal = subjectSignal;

/* caseId */
OCTET_STRING_fromString(&subjectSignal->caseId, caseId);

/* iAPSystemId */
subjectSignal->iAPSystemId = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, systemID, strlen(systemID));;

/* timestamp */
asn_time2GT_frac(&subjectSignal->timestamp,timestamp,frac_value, frac_digits, force_gmt);

/* callId */
OCTET_STRING_fromString(&CallIdentity->main, callId_main);
CallIdentity->leg = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, callId_leg, strlen(callId_leg));
subjectSignal->callId = CallIdentity;

/* signaledPartyId  - PartyIdentity*/
SignaledIPAddress->present = IpAddress_PR_ipV4;
OCTET_STRING_fromString(&SignaledIPAddress->ipV4, signaled_ipaddress);
SignaledPartyIdentity->ipAddress = SignaledIPAddress;
SignaledPartyIdentity->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, signaled_partyId_context, strlen(signaled_partyId_context));
subjectSignal->signaledPartyId = SignaledPartyIdentity;

/* signalingPartyId - PartyIdentity */
SignalingIPAddress->present = IpAddress_PR_ipV4;
OCTET_STRING_fromString(&SignalingIPAddress->ipV4, signaling_ipaddress);
SignalingPartyIdentity->ipAddress = SignalingIPAddress;
SignalingPartyIdentity->context = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, signaling_partyId_context, strlen(signaling_partyId_context));
subjectSignal->signalingPartyId = SignalingPartyIdentity;

/* input */
subjectSignal->input.present = SubjectSignal__input_PR_userInput;
userInput->present = SubjectSignal__input__userInput_PR_generic;
OCTET_STRING_fromString(&userInput->generic, generic); 
subjectSignal->input.userInput = userInput;

/* subjectMedia */
MediaInformation->characteristics = calloc(1, sizeof(struct MediaInformation__characteristics));
MediaInformation->characteristics->present = MediaInformation__characteristics_PR_sdp;
OCTET_STRING_fromString(&MediaInformation->characteristics->sdp, sdp); 
subjectSignal->subjectMedia = MediaInformation;

/* signal */
subjectSignal->signal.dialedDigits = OCTET_STRING_new_fromBuf(&asn_DEF_VisibleString, dialed_digits, strlen(dialed_digits));

refer->present = SubjectSignal__signal__refer_PR_sip;

SipHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_header, strlen(sip_header));
asn_set_add(&refer_sip->list, SipHeader);
asn_set_add(&refer_sip->list, SipHeader);
asn_set_add(&refer_sip->list, SipHeader);

refer->sip = refer_sip;
subjectSignal->signal.refer = refer;

/* protocolSpecificParameters */
protocolSpecificParameters->present = ProtocolSpecificParameters_PR_sip;

/*------------------*/
/* encode sipHeader */
/*------------------*/
asn_set_add(SipHeaders, SipHeader);
asn_set_add(SipHeaders, SipHeader);
asn_set_add(SipHeaders, SipHeader);

memcpy(&psp_sipHeader->list, SipHeaders, sizeof(A_SET_OF(SipHeader_t)));

psp_sip->sipHeader = psp_sipHeader;

/*----------------------*/
/* encode sipBodyHeader */
/*----------------------*/

psp_sipBodyHeader = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, sip_bodyheader, strlen(sip_bodyheader));

asn_set_add(psp_sipBodyHeaders, psp_sipBodyHeader);
asn_set_add(psp_sipBodyHeaders, psp_sipBodyHeader);
asn_set_add(psp_sipBodyHeaders, psp_sipBodyHeader);

memcpy(&psp_sipBody->sipBodyHeader.list, psp_sipBodyHeaders, sizeof(A_SET_OF(SipHeader_t)));
OCTET_STRING_fromString(&psp_sipBody->sipBodyContents, "SIP BODY CONTENTS");
psp_sip->sipBody = psp_sipBody;

protocolSpecificParameters->sip = psp_sip;
subjectSignal->protocolSpecificParameters = protocolSpecificParameters;

/* signalingMsg */
OCTET_STRING_fromString(&EncapsulatedSignalingMessage->signalingProt, sigprot); 
OCTET_STRING_fromString(&EncapsulatedSignalingMessage->sigMsg, sigmsg); 

asn_set_add(signalingMsg, EncapsulatedSignalingMessage);

subjectSignal->signalingMsg = signalingMsg;

encode(fp, LAESProtocol);
return 0;

}
