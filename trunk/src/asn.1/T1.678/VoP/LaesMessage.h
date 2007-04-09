/*
 * This file is autogenerated by the ASN.1 compiler.
 * Copyright (c) 2003-2007 Lev Walkin <vlm@lionet.info>
 * See http://lionet.info/asn1c
 *
 * Source ASN.1 file is Copyright (c) by US CALEA, included
 * with permission (if included). <<< this depends on whether
 * or not you include the original ASN.1 file into OpenCALEA >>>
 *
 * This file is part of OpenCALEA suite (http://opencalea.org)
 * and is subject to OpenCALEA license (see COPYING file in the
 * root of the opencalea distribution).
 *
 * Copyright (c) 2007 Norman Brandinger <norm@goes.com>
 *
 */

/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "T1S1-LAES-VoP-Abstract-Syntax-Module"
 * 	found in "T1S1-LAES-VoP-Abstract-Syntax-Module.asn"
 * 	`asn1c -fnative-types`
 */

#ifndef	_LaesMessage_H_
#define	_LaesMessage_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Answer.h"
#include "CCClose.h"
#include "CCOpen.h"
#include "Change.h"
#include "Origination.h"
#include <NULL.h>
#include "Redirection.h"
#include "Release.h"
#include "ServingSystem.h"
#include "TerminationAttempt.h"
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

/* LaesMessage */
typedef struct LaesMessage {
	LaesMessage_PR present;
	union LaesMessage_u {
		Answer_t	 answer;
		CCClose_t	 ccClose;
		CCOpen_t	 ccOpen;
		Change_t	 change;
		Origination_t	 origination;
		NULL_t	 null_6;
		Redirection_t	 redirection;
		Release_t	 release;
		ServingSystem_t	 servingSystem;
		TerminationAttempt_t	 termAttempt;
		ConfPartyChange_t	 confPartyChange;
		Connection_t	 connection;
		ConnectionBreak_t	 connectionBreak;
		DialedDigitExtraction_t	 dialedDgtExtrn;
		NetworkSignal_t	 networkSignal;
		SubjectSignal_t	 subjectSignal;
		DirectSignalReporting_t	 directSignalReporting;
		MediaAndAddressReporting_t	 mediaAndAddressReporting;
		CCChange_t	 ccChange;
		CCUnavailable_t	 ccUnavailable;
		SurveillanceStatus_t	 surveillanceStatus;
		FeatureManagement_t	 featureManagement;
		UUContent_t	 uuContent;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LaesMessage_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LaesMessage;

#ifdef __cplusplus
}
#endif

#endif	/* _LaesMessage_H_ */