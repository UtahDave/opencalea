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

/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "T1S1-LAES-VoP-Abstract-Syntax-Module"
 * 	found in "T1S1-LAES-VoP-Abstract-Syntax-Module.asn"
 * 	`asn1c -funnamed-unions -findirect-choice -fbless-SIZE -fcompound-names -fnative-types`
 */

#ifndef	_LaesMessage_H_
#define	_LaesMessage_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LaesMessage_PR {
	LaesMessage_PR_NOTHING,	/* No components present */
	LaesMessage_PR_answer,
	LaesMessage_PR_ccClose,
	LaesMessage_PR_ccOpen,
	LaesMessage_PR_change,
	LaesMessage_PR_origination,
	LaesMessage_PR_null_6,
	LaesMessage_PR_redirection,
	LaesMessage_PR_release,
	LaesMessage_PR_servingSystem,
	LaesMessage_PR_termAttempt,
	LaesMessage_PR_connTest,
	LaesMessage_PR_confPartyChange,
	LaesMessage_PR_connection,
	LaesMessage_PR_connectionBreak,
	LaesMessage_PR_dialedDgtExtrn,
	LaesMessage_PR_networkSignal,
	LaesMessage_PR_subjectSignal,
	LaesMessage_PR_directSignalReporting,
	LaesMessage_PR_mediaAndAddressReporting,
	LaesMessage_PR_ccChange,
	LaesMessage_PR_ccUnavailable,
	LaesMessage_PR_surveillanceStatus,
	LaesMessage_PR_featureManagement,
	LaesMessage_PR_uuContent
} LaesMessage_PR;

/* Forward declarations */
struct Answer;
struct CCClose;
struct CCOpen;
struct Change;
struct Origination;
struct Redirection;
struct Release;
struct ServingSystem;
struct TerminationAttempt;
struct ConnectionTest;
struct ConfPartyChange;
struct Connection;
struct ConnectionBreak;
struct DialedDigitExtraction;
struct NetworkSignal;
struct SubjectSignal;
struct DirectSignalReporting;
struct MediaAndAddressReporting;
struct CCChange;
struct CCUnavailable;
struct SurveillanceStatus;
struct FeatureManagement;
struct UUContent;

/* LaesMessage */
typedef struct LaesMessage {
	LaesMessage_PR present;
	union {
		struct Answer	*answer;
		struct CCClose	*ccClose;
		struct CCOpen	*ccOpen;
		struct Change	*change;
		struct Origination	*origination;
		NULL_t	 null_6;
		struct Redirection	*redirection;
		struct Release	*release;
		struct ServingSystem	*servingSystem;
		struct TerminationAttempt	*termAttempt;
		struct ConnectionTest	*connTest;
		struct ConfPartyChange	*confPartyChange;
		struct Connection	*connection;
		struct ConnectionBreak	*connectionBreak;
		struct DialedDigitExtraction	*dialedDgtExtrn;
		struct NetworkSignal	*networkSignal;
		struct SubjectSignal	*subjectSignal;
		struct DirectSignalReporting	*directSignalReporting;
		struct MediaAndAddressReporting	*mediaAndAddressReporting;
		struct CCChange	*ccChange;
		struct CCUnavailable	*ccUnavailable;
		struct SurveillanceStatus	*surveillanceStatus;
		struct FeatureManagement	*featureManagement;
		struct UUContent	*uuContent;
	};
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LaesMessage_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LaesMessage;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Answer.h"
#include "CCClose.h"
#include "CCOpen.h"
#include "Change.h"
#include "Origination.h"
#include "Redirection.h"
#include "Release.h"
#include "ServingSystem.h"
#include "TerminationAttempt.h"
#include "ConnectionTest.h"
#include "ConfPartyChange.h"
#include "Connection.h"
#include "ConnectionBreak.h"
#include "DialedDigitExtraction.h"
#include "NetworkSignal.h"
#include "SubjectSignal.h"
#include "DirectSignalReporting.h"
#include "MediaAndAddressReporting.h"
#include "CCChange.h"
#include "CCUnavailable.h"
#include "SurveillanceStatus.h"
#include "FeatureManagement.h"
#include "UUContent.h"

#endif	/* _LaesMessage_H_ */
