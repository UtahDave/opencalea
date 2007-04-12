ASN_MODULE_SOURCES=	\
	IAS-LAES-CmII-Abstract-Syntax-Module-OID.c	\
	IasProtocol.c	\
	IasMessage.c	\
	Access-Attempt.c	\
	Access-Accepted.c	\
	Access-Failed.c	\
	Access-Session-End.c	\
	Access-Rejected.c	\
	Access-Signaling-Message-Report.c	\
	Packet-Data-Session-Start.c	\
	Packet-Data-Session-Failed.c	\
	Packet-Data-Session-End.c	\
	Packet-Data-Session-Already-Established.c	\
	Packet-Data-Header-Report.c	\
	Packet-Data-Summary-Report.c	\
	AccessMethod.c	\
	IPAddress.c	\
	AccessSessionID.c	\
	AccessSessionCharacteristics.c	\
	HeaderSet.c	\
	InterceptedSignalingMessage.c	\
	IAPSystemIdentity.c	\
	IAS-CCDeliveryFormat.c	\
	LEA-CmC-Delivery.c	\
	MessageType.c	\
	NetworkAccessNodeIdentity.c	\
	PacketDataSessionID.c	\
	PortNumber.c	\
	ProtocolSignal.c	\
	Protocol.c	\
	ReasonForTermination.c	\
	StreamSet.c	\
	SubscriberIdentity.c	\
	Value.c	\
	TimeStamp.c	\
	IAS-LAES-CmCC-Module-OID.c	\
	CCAddress.c	\
	DeliveryIdentifier.c	\
	CaseIdentity.c	\
	CCCIdentity.c	\
	IpAddress.c	\
	IPvalue.c	\
	Location.c	\
	CallIdentity.c	\
	ContentIdentifier.c	\
	CorrelationIdentifier.c

ASN_MODULE_HEADERS=	\
	IAS-LAES-CmII-Abstract-Syntax-Module-OID.h	\
	IasProtocol.h	\
	IasMessage.h	\
	Access-Attempt.h	\
	Access-Accepted.h	\
	Access-Failed.h	\
	Access-Session-End.h	\
	Access-Rejected.h	\
	Access-Signaling-Message-Report.h	\
	Packet-Data-Session-Start.h	\
	Packet-Data-Session-Failed.h	\
	Packet-Data-Session-End.h	\
	Packet-Data-Session-Already-Established.h	\
	Packet-Data-Header-Report.h	\
	Packet-Data-Summary-Report.h	\
	AccessMethod.h	\
	IPAddress.h	\
	AccessSessionID.h	\
	AccessSessionCharacteristics.h	\
	HeaderSet.h	\
	InterceptedSignalingMessage.h	\
	IAPSystemIdentity.h	\
	IAS-CCDeliveryFormat.h	\
	LEA-CmC-Delivery.h	\
	MessageType.h	\
	NetworkAccessNodeIdentity.h	\
	PacketDataSessionID.h	\
	PortNumber.h	\
	ProtocolSignal.h	\
	Protocol.h	\
	ReasonForTermination.h	\
	StreamSet.h	\
	SubscriberIdentity.h	\
	Value.h	\
	TimeStamp.h	\
	IAS-LAES-CmCC-Module-OID.h	\
	CCAddress.h	\
	DeliveryIdentifier.h	\
	CaseIdentity.h	\
	CCCIdentity.h	\
	IpAddress.h	\
	IPvalue.h	\
	Location.h	\
	CallIdentity.h	\
	ContentIdentifier.h	\
	CorrelationIdentifier.h

ASN_MODULE_HEADERS+=UTF8String.h
ASN_MODULE_HEADERS+=BOOLEAN.h
ASN_MODULE_SOURCES+=BOOLEAN.c
ASN_MODULE_HEADERS+=INTEGER.h
ASN_MODULE_HEADERS+=NativeEnumerated.h
ASN_MODULE_HEADERS+=GeneralizedTime.h
ASN_MODULE_SOURCES+=GeneralizedTime.c
ASN_MODULE_SOURCES+=INTEGER.c
ASN_MODULE_HEADERS+=NULL.h
ASN_MODULE_SOURCES+=NULL.c
ASN_MODULE_SOURCES+=NativeEnumerated.c
ASN_MODULE_HEADERS+=NativeInteger.h
ASN_MODULE_SOURCES+=NativeInteger.c
ASN_MODULE_HEADERS+=NumericString.h
ASN_MODULE_SOURCES+=NumericString.c
ASN_MODULE_HEADERS+=OBJECT_IDENTIFIER.h
ASN_MODULE_SOURCES+=OBJECT_IDENTIFIER.c
ASN_MODULE_SOURCES+=UTF8String.c
ASN_MODULE_HEADERS+=VisibleString.h
ASN_MODULE_SOURCES+=VisibleString.c
ASN_MODULE_HEADERS+=asn_SET_OF.h
ASN_MODULE_SOURCES+=asn_SET_OF.c
ASN_MODULE_HEADERS+=constr_CHOICE.h
ASN_MODULE_SOURCES+=constr_CHOICE.c
ASN_MODULE_HEADERS+=constr_SEQUENCE.h
ASN_MODULE_SOURCES+=constr_SEQUENCE.c
ASN_MODULE_HEADERS+=constr_SET_OF.h
ASN_MODULE_SOURCES+=constr_SET_OF.c
ASN_MODULE_HEADERS+=asn_application.h
ASN_MODULE_HEADERS+=asn_system.h
ASN_MODULE_HEADERS+=asn_codecs.h
ASN_MODULE_HEADERS+=asn_internal.h
ASN_MODULE_HEADERS+=OCTET_STRING.h
ASN_MODULE_SOURCES+=OCTET_STRING.c
ASN_MODULE_HEADERS+=BIT_STRING.h
ASN_MODULE_SOURCES+=BIT_STRING.c
ASN_MODULE_SOURCES+=asn_codecs_prim.c
ASN_MODULE_HEADERS+=asn_codecs_prim.h
ASN_MODULE_HEADERS+=ber_tlv_length.h
ASN_MODULE_SOURCES+=ber_tlv_length.c
ASN_MODULE_HEADERS+=ber_tlv_tag.h
ASN_MODULE_SOURCES+=ber_tlv_tag.c
ASN_MODULE_HEADERS+=ber_decoder.h
ASN_MODULE_SOURCES+=ber_decoder.c
ASN_MODULE_HEADERS+=der_encoder.h
ASN_MODULE_SOURCES+=der_encoder.c
ASN_MODULE_HEADERS+=constr_TYPE.h
ASN_MODULE_SOURCES+=constr_TYPE.c
ASN_MODULE_HEADERS+=constraints.h
ASN_MODULE_SOURCES+=constraints.c
ASN_MODULE_HEADERS+=xer_support.h
ASN_MODULE_SOURCES+=xer_support.c
ASN_MODULE_HEADERS+=xer_decoder.h
ASN_MODULE_SOURCES+=xer_decoder.c
ASN_MODULE_HEADERS+=xer_encoder.h
ASN_MODULE_SOURCES+=xer_encoder.c
ASN_MODULE_HEADERS+=per_support.h
ASN_MODULE_SOURCES+=per_support.c
ASN_MODULE_HEADERS+=per_decoder.h
ASN_MODULE_SOURCES+=per_decoder.c
ASN_MODULE_HEADERS+=per_encoder.h
ASN_MODULE_SOURCES+=per_encoder.c

ASN_MODULEdir = $(pkgincludedir)/T1.IAS/CmII

lib_LTLIBRARIES=libias.la
libias_la_SOURCES=$(ASN_MODULE_SOURCES) $(ASN_MODULE_HEADERS)
