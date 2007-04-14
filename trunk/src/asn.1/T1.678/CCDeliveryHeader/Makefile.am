ASN_MODULE_SOURCES=	\
	CCDeliveryHeaderModuleOID.c	\
	CC-APDU.c	\
	CCDeliveryHeader.c	\
	CaseIdentity.c	\
	IAPSystemIdentity.c	\
	TimeStamp.c	\
	PacketDirection.c	\
	CallIdentity.c	\
	ContentIdentifier.c	\
	CorrelationIdentifier.c

ASN_MODULE_HEADERS=	\
	CCDeliveryHeaderModuleOID.h	\
	CC-APDU.h	\
	CCDeliveryHeader.h	\
	CaseIdentity.h	\
	IAPSystemIdentity.h	\
	TimeStamp.h	\
	PacketDirection.h	\
	CallIdentity.h	\
	ContentIdentifier.h	\
	CorrelationIdentifier.h

ASN_MODULE_HEADERS+=UTF8String.h
ASN_MODULE_HEADERS+=INTEGER.h
ASN_MODULE_HEADERS+=NativeEnumerated.h
ASN_MODULE_HEADERS+=GeneralizedTime.h
ASN_MODULE_SOURCES+=GeneralizedTime.c
ASN_MODULE_SOURCES+=INTEGER.c
ASN_MODULE_SOURCES+=NativeEnumerated.c
ASN_MODULE_HEADERS+=NativeInteger.h
ASN_MODULE_SOURCES+=NativeInteger.c
ASN_MODULE_HEADERS+=OBJECT_IDENTIFIER.h
ASN_MODULE_SOURCES+=OBJECT_IDENTIFIER.c
ASN_MODULE_SOURCES+=UTF8String.c
ASN_MODULE_HEADERS+=VisibleString.h
ASN_MODULE_SOURCES+=VisibleString.c
ASN_MODULE_HEADERS+=constr_CHOICE.h
ASN_MODULE_SOURCES+=constr_CHOICE.c
ASN_MODULE_HEADERS+=constr_SEQUENCE.h
ASN_MODULE_SOURCES+=constr_SEQUENCE.c
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

ASN_MODULEdir = $(pkgincludedir)/T1.678/CCDeliveryHeader

lib_LTLIBRARIES=libCCDeliveryHeader.la
libCCDeliveryHeader_la_SOURCES=$(ASN_MODULE_SOURCES) $(ASN_MODULE_HEADERS)
