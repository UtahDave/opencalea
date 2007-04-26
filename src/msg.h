/*
 * Copyright (c) 2007, Jesse Norell <jesse@kci.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Merit Network, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY MERIT NETWORK, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL MERIT NETWORK, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MSG_H
#define _MSG_H

#include "calea.h"


/*
 * Generic OpenCALEA Message
 */

enum e_msgtype {
    MSGTYPE_NONE,               /* 0 = uninitialized or not present */
    MSGTYPE_CONTROL,            /* OpenCALEA Control message */
    MSGTYPE_LOG,                /* Surveillance Log message */
    MSGTYPE_CMII,               /* Communications Identifying Information message */
    MSGTYPE_CII,                /* Call Identifying Information message */
    MSGTYPE_CMC,                /* Communications Content message */
    MSGTYPE_CC                  /* Call Content message */
};
#define MsgType enum e_msgtype

enum e_msgfmt {
    MSGFMT_NONE,                /* 0 = uninitialized or not present */
    MSGFMT_C,                   /* C structure */
    MSGFMT_XML,                 /* eXtensible Markup Language */
    MSGFMT_BER,                 /* Basic Encoding Rules */
    MSGFMT_TXT,                 /* Plain Text */
    MSGFMT_CSV,                 /* Comma Seperated Values */
    MSGFMT_IAS_D31,             /* IAS section D.3.1 CmC in UDP Encapsulation */
    MSGFMT_IAS_D32              /* IAS section D.3.2 CmC in IC-APDU's */
};
#define MsgFmt enum e_msgtype

/* all OpenCALEA messages have this header */
typedef struct {
    MsgType msgtype;
    MsgFmt format;
    int msglen;                 /* Length of msgbody, not including the Msgh */
} msgh_t; 
#define Msgh msgh_t

// Note: msgbody here and data below are pointers;
// you can write the header structure directly to the wire,
// but must copy the msgbody separately

/* a fulll OpenCALEA message */
typedef struct {
    Msgh msgh;
    u_char *msgbody;
} msg_t; 
#define Msg msg_t


/* Message Agent (for Log and Control messages) */

/* Type of Agent */
enum e_agenttype {
    AGENTTYPE_NONE,             /* 0 = uninitialized or not present */
    AGENTTYPE_CONTROLLER,       /* OpenCALEA Controller Daemon */
    AGENTTYPE_CONTROL,          /* OpenCALEA Control Agent */
    AGENTTYPE_DF,               /* Delivery Function Agent */
    AGENTTYPE_LOG,              /* Surveillance Log Agent */
    AGENTTYPE_CMII,             /* Communications Identifying Information Agent */
    AGENTTYPE_CII,              /* Call Identifying Information Agent */
    AGENTTYPE_CMC,              /* Communications Content Agent */
    AGENTTYPE_CC,               /* Call Content Agent */
    AGENTTYPE_DDE               /* Dialed Digit Extraction Agent */
};
#define AgentType enum e_agenttype

enum e_agentsubtype {
    AGENTSUBTYPE_NONE,          /* 0 = uninitialized or not present */
    AGENTSUBTYPE_MANUAL,        /* Manual / Static Addressing CMII Agent */
    AGENTSUBTYPE_RADIUS,        /* RADIUS CMII Agent */
    AGENTSUBTYPE_TACACS,        /* TACACS CMII Agent */
    AGENTSUBTYPE_DHCP,          /* DHCP CMII Agent */
    AGENTSUBTYPE_PPPOE,         /* PPPOE CMII Agent */
    AGENTSUBTYPE_IASTAP,        /* IAS CMC Agent */
    AGENTSUBTYPE_VOPTAP,        /* VOP CC Agent */
    AGENTSUBTYPE_RFC2833,       /* DDE Agent - Digits from RTP payload */
    AGENTSUBTYPE_RTPDDE,        /* DDE Agent - Digits from RTP audio */
    AGENTSUBTYPE_SIPDDE         /* DDE Agent - Digits from SIP */
};
#define AgentSubType enum e_agenttype

typedef struct {
    u_char IAPSystemID[MAX_IAP_SYSTEM_ID_LENGTH];
    AgentType type;
    AgentSubType subtype;
} agent_t;
#define Agent agent_t


/* Extra Message Data */
typedef struct {
    int size;                   /* Length of Data following */
    u_char *data;
    /*  Note: data here and msgbody above are pointers;
     *  you can write the header structure directly to the wire,
     *  but must copy the data separately */
} msgdata_t;
#define MsgData msgdata_t



/*
 * OpenCALEA Log Message
 */

struct {
    Agent agent;                /* Agent Sending Log Message */
    MsgData data;               /* Surveillance Log (actual message text) */
} logmsg_t;
#define LogMsg logmsg_t



/*
 * OpenCALEA Control Message
 */

/* Control Message Commands */
enum e_ctrlcmd {
    CTRLCMD_NONE,               /* 0 = uninitialized or not present */
    CTRLCMD_INTERCEPT_START,    /* Start Intercept */
    CTRLCMD_INTERCEPT_STOP,     /* Stop Intercept */
    CTRLCMD_INTERCEPT_STAT,     /* Get Intercept Status */
    CTRLCMD_AGENT_START,        /* Start Agent */
    CTRLCMD_AGENT_STOP,         /* Stop Agent */
    CTRLCMD_AGENT_STAT,         /* Get Agent Status */
    CTRLCMD_ROUTE_ADD,          /* Add Route to DF */
    CTRLCMD_ROUTE_DEL,          /* Delete Route from DF */
    CTRLCMD_ROUTE_STAT,         /* Get Routes from DF */
    CTRLCMD_REGISTRATION,       /* Register an Agent (including DF) */
    CTRLCMD_SETDF,              /* Change DF Destination */
    CTRLCMD_SETLOG,             /* Change Surveillance Log Destination */
    CTRLCMD_REPLY               /* Reply to command */
};
#define CtrlCmd enum e_ctrlcmd


/* An Intercept */
typedef struct {
    u_char CaseID[MAX_CASE_ID_LENGTH];          /* Intercept CaseID */
    u_char SubjectID[MAX_SUBJECT_ID_LENGTH];    /* Intercept Subject Identifier */
    time_t start;                               /* Intercept Start Time */
    time_t stop;                                /* Intercept Stop Time */
} intercept_t;
#define Intercept intercept_t


/* Type of Intercept Subject */
enum e_isubtype {
    ISUBTYPE_NONE,              /* 0 = uninitialized or not present */
    ISUBTYPE_IP,                /* Intercept Subject is an IP Addr */
    ISUBTYPE_MAC,               /* Intercept Subject is a MAC Addr */
    ISUBTYPE_USERNAME,          /* Intercept Subject is a Username */
    ISUBTYPE_CIRCUIT            /* Intercept Subject is a Circuit ID / pvc */
};
#define SubjectType enum e_isubtype

#define MAX_FORMATTED_ID_LENGTH 256
/* An Intercept Subject */
typedef struct {
    SubjectType subtype;        /* Type of Intercept Subject */
                                /* See Intercept.SubjectID for unformatted Subject ID */
    u_char id[MAX_FORMATTED_ID_LENGTH];         /* Formatted ID (pcap filter, modified username, etc.) */
    u_char protocol[4];         /* "tcp" ("tcp4") or "udp" ("udp4") */
    u_char host[INET_ADDRSTRLEN];  /* IPv4 Addr (will change for ipv6) */
    int port;                   /* tcp/udp port */
} subject_t;
#define Subject subject_t


/* Generic Message Destination */
typedef struct {
    u_char protocol[4];         /* "unix", "tcp" ("tcp4") or "udp" ("udp4") */
    u_char host[INET_ADDRSTRLEN];  /* IPv4 Addr (will change for ipv6) */
    int port;                   /* tcp/udp port */
    u_char sock[128];           /* unix domain socket */
    MsgFmt format;
} msgdest_t;
#define MsgDest msgdest_t


/* Control Message Reply */
enum enum e_cmdreply {
    CMDREPLY_NONE,              /* 0 = uninitialized or not present */
    CMDREPLY_OK,                /* Command Succeeded */
    CMDREPLY_FAIL		/* Command Failed */
};
#define CmdReply enum e_cmdreply


/* an OpenCALEA control message header */
typedef struct {
    CtrlCmd cmd;                /* Control Command */
    Agent agent;                /* Agent initiating or sending command */
    Intercept intercept;        /* Intercept Info */
    struct {
        Agent agent;            /* Target Agent (agents affected by command) */
        Subject subject;        /* Intercept Subject data */
        u_char SessionID[MAX_SESSION_ID_LENGTH];    /* CallID or Packet-Data-Session-ID */
                                                    /* note: there's also an access session id */
        u_char ContentID[MAX_CONTENT_ID_LENGTH];    /* VOP CorrelationID or IAS ContentID */
    } target;
    MsgDest dfhost;
    MsgDest loghost;
    CmdReply reply;
} ctrlh_t;
#define Ctrlh ctrlh_t

/* an OpenCALEA control message in C struct format */
typedef struct {
    Ctrlh ctrlh;                /* Control Message Header */
    MsgData data;               /* Extra Message Data (eg. content of STATUS reply) */
} ctrlmsg_t;
#define CtrlMsg ctrlmsg_t

// note: need a means to start an ias cmii agent for an active session and provide the session id

#endif

