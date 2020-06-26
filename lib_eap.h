#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <poll.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h> 


#ifndef NGTFF_EAP_H
#define NGTFF_EAP_H

#define NGTFF_EAP_CODE_REQUEST												1
#define NGTFF_EAP_CODE_RESPONSE												2
#define NGTFF_EAP_CODE_SUCCESS												3
#define NGTFF_EAP_CODE_FAILURE												4

#define NGTFF_EAP_TYPE_IDENTITY												1
#define NGTFF_EAP_TYPE_NOTIFICATION											2
#define NGTFF_EAP_TYPE_NAK													3
#define NGTFF_EAP_TYPE_MD5_CHALLANGE										4
#define NGTFF_EAP_TYPE_ONE_TIME_PASSWORD									5
#define NGTFF_EAP_TYPE_GENERIC_TOKEN_CARD									6

#define NGTFF_EAP_SUBTYPE_AKA_Challenge										1
#define NGTFF_EAP_SUBTYPE_AKA_Authentication_Reject							2
#define NGTFF_EAP_SUBTYPE_AKA_Synchronization_Failure						4
#define NGTFF_EAP_SUBTYPE_AKA_Identity										5
#define NGTFF_EAP_SUBTYPE_SIM_Start											10
#define NGTFF_EAP_SUBTYPE_SIM_Challenge										11
#define NGTFF_EAP_SUBTYPE_AKA_Notification_N_SIM_Notification				12
#define NGTFF_EAP_SUBTYPE_AKA_Reauthentication_N_SIM_Reauthentication		13
#define NGTFF_EAP_SUBTYPE_AKA_Client_Error_N_SIM_Client_Error				14

#define NGTFF_EAP_ATTRIBUTE_AT_RAND											1
#define NGTFF_EAP_ATTRIBUTE_AT_AUTN											2
#define NGTFF_EAP_ATTRIBUTE_AT_RES											3
#define NGTFF_EAP_ATTRIBUTE_AT_AUTS											4
#define NGTFF_EAP_ATTRIBUTE_AT_PADDING										6
#define NGTFF_EAP_ATTRIBUTE_AT_NONCE_MT										7
#define NGTFF_EAP_ATTRIBUTE_AT_PERMANENT_ID_REQ								10
#define NGTFF_EAP_ATTRIBUTE_AT_MAC											11
#define NGTFF_EAP_ATTRIBUTE_AT_NOTIFICATION									12
#define NGTFF_EAP_ATTRIBUTE_AT_ANY_ID_REQ									13
#define NGTFF_EAP_ATTRIBUTE_AT_IDENTITY										14
#define NGTFF_EAP_ATTRIBUTE_AT_VERSION_LIST									15
#define NGTFF_EAP_ATTRIBUTE_AT_SELECTED_VERSION								16
#define NGTFF_EAP_ATTRIBUTE_AT_FULLAUTH_ID_REQ								17
#define NGTFF_EAP_ATTRIBUTE_AT_COUNTER										19
#define NGTFF_EAP_ATTRIBUTE_AT_COUNTER_TOO_SMALL							20
#define NGTFF_EAP_ATTRIBUTE_AT_NONCE_S										21
#define NGTFF_EAP_ATTRIBUTE_AT_CLIENT_ERROR_CODE							22
#define NGTFF_EAP_ATTRIBUTE_AT_IV											129
#define NGTFF_EAP_ATTRIBUTE_AT_ENCR_DATA									130
#define NGTFF_EAP_ATTRIBUTE_AT_NEXT_PSEUDONYM								132
#define NGTFF_EAP_ATTRIBUTE_AT_NEXT_REAUTH_ID								133
#define NGTFF_EAP_ATTRIBUTE_AT_CHECKCODE									134
#define NGTFF_EAP_ATTRIBUTE_AT_RESULT_IND									135


// Indicates the length of this attribute in multiples of 4 bytes.
typedef struct __ngtff_eap_attribute
{
	struct __ngtff_eap_attribute * Next;
	
	uint8_t Type;
	uint8_t Length;
	u_char * data;
	uint16_t datalen;
	
} NGTFF_EAP_Attribute;



typedef struct __ngtff_eap_message
{
	uint8_t Code;
	uint8_t Id;
	uint16_t Length;
	uint8_t Type;
	uint8_t SubType;
	
	NGTFF_EAP_Attribute * AttributeHead;
	NGTFF_EAP_Attribute * AttributeCurrent;
	int AttributeCount;	
	
	uint32_t pos;
	uint32_t len;
	u_char data[1024];
	
	u_char * idval;
	uint16_t idlen;
	
	uint32_t error;
} NGTFF_EAPMessage;

void __ngtff_eap_init( NGTFF_EAPMessage * eapMessage, uint8_t code, uint8_t id, uint8_t type, uint8_t subtype);
void __ngtff_eap_set_identifier( NGTFF_EAPMessage * eapMessage, u_char * id, uint16_t idlen);
void __ngtff_eap_add_attribute( NGTFF_EAPMessage * eapMessage, uint8_t type, u_char * data, uint16_t len);
void __ngtff_eap_encode( NGTFF_EAPMessage * eapMessage);
void __ngtff_eap_decode( NGTFF_EAPMessage * eapMessage, u_char * data, uint32_t len);
void __ngtff_eap_print( NGTFF_EAPMessage * eapMessage);

#endif



















