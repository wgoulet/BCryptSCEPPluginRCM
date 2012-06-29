/*
* Copyright (c) RSA Security Inc., 2005-.  All rights reserved.  
* This work contains proprietary, confidential, and trade secret 
* information of RSA Security Inc.  Use, disclosure or reproduction 
* without the express written authorization of RSA Security Inc. is
* prohibited.
*/
#ifndef _RCMSCEPAPI_H_
#define _RCMSCEPAPI_H_

typedef struct 
{ 
    char* _UNSTRUCTUREDNAME;
   	char* _UNSTRUCTUREDADDRESS;
	char* _IPADDRESS;
    char* _SERIALNUMBER;
    char* _PASSWORD;
    char* _JURISDICTIONID;
} SCEPReqInfo;

/* FUNCTIONS THAT A PLUGIN MUST EXPORT*/
/*do not use decorated names; the C language calling sequence will be used.*/
#ifdef __cplusplus
extern "C" {
#endif /* #ifdef __cplusplus */

int RCMSCEP_Initialize(int* iVersion, void* reserved);

int RCMSCEP_CheckAuthorization (SCEPReqInfo* reqInfo);

#ifdef __cplusplus
}
#endif /* #ifdef __cplusplus */

#define RCMSCEP_SUCCESS		    0
#define RCMSCEP_AUTHORIZE		1
#define RCMSCEP_REFUSE		    2
#define RCMSCEP_INTERNAL		3
#define RCMSCEP_VERSION_1		1
#define RCMSCEP_VERSION		    RCMSCEP_VERSION_1;

#endif  /*#ifndef _RCMSCEPAPI_H_*/