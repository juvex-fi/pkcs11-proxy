/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* p11-rpc-private.h - various ids and signatures for our protocol

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GCK_RPC_CALLS_H
#define GCK_RPC_CALLS_H

#include "config.h"

#include <stdlib.h>
#include <stdarg.h>

#include "egg-buffer.h"

#include "pkcs11/pkcs11.h"

/* The calls, must be in sync with array below */
enum {
	GCK_RPC_CALL_ERROR = 0,

	GCK_RPC_CALL_C_Initialize,
	GCK_RPC_CALL_C_Finalize,
	GCK_RPC_CALL_C_GetInfo,
	GCK_RPC_CALL_C_GetSlotList,
	GCK_RPC_CALL_C_GetSlotInfo,
	GCK_RPC_CALL_C_GetTokenInfo,
	GCK_RPC_CALL_C_GetMechanismList,
	GCK_RPC_CALL_C_GetMechanismInfo,
	GCK_RPC_CALL_C_InitToken,
	GCK_RPC_CALL_C_WaitForSlotEvent,

	GCK_RPC_CALL_C_OpenSession,

	GCK_RPC_CALL_C_CloseSession,
	GCK_RPC_CALL_C_CloseAllSessions,
	GCK_RPC_CALL_C_GetFunctionStatus,
	GCK_RPC_CALL_C_CancelFunction,

	GCK_RPC_CALL_C_GetSessionInfo,
	GCK_RPC_CALL_C_InitPIN,
	GCK_RPC_CALL_C_SetPIN,
	GCK_RPC_CALL_C_GetOperationState,
	GCK_RPC_CALL_C_SetOperationState,
	GCK_RPC_CALL_C_Login,
	GCK_RPC_CALL_C_Logout,
	GCK_RPC_CALL_C_CreateObject,
	GCK_RPC_CALL_C_CopyObject,
	GCK_RPC_CALL_C_DestroyObject,
	GCK_RPC_CALL_C_GetObjectSize,
	GCK_RPC_CALL_C_GetAttributeValue,
	GCK_RPC_CALL_C_SetAttributeValue,
	GCK_RPC_CALL_C_FindObjectsInit,
	GCK_RPC_CALL_C_FindObjects,
	GCK_RPC_CALL_C_FindObjectsFinal,
	GCK_RPC_CALL_C_EncryptInit,
	GCK_RPC_CALL_C_Encrypt,
	GCK_RPC_CALL_C_EncryptUpdate,
	GCK_RPC_CALL_C_EncryptFinal,
	GCK_RPC_CALL_C_DecryptInit,
	GCK_RPC_CALL_C_Decrypt,
	GCK_RPC_CALL_C_DecryptUpdate,
	GCK_RPC_CALL_C_DecryptFinal,
	GCK_RPC_CALL_C_DigestInit,
	GCK_RPC_CALL_C_Digest,
	GCK_RPC_CALL_C_DigestUpdate,
	GCK_RPC_CALL_C_DigestKey,
	GCK_RPC_CALL_C_DigestFinal,
	GCK_RPC_CALL_C_SignInit,
	GCK_RPC_CALL_C_Sign,
	GCK_RPC_CALL_C_SignUpdate,
	GCK_RPC_CALL_C_SignFinal,
	GCK_RPC_CALL_C_SignRecoverInit,
	GCK_RPC_CALL_C_SignRecover,
	GCK_RPC_CALL_C_VerifyInit,
	GCK_RPC_CALL_C_Verify,
	GCK_RPC_CALL_C_VerifyUpdate,
	GCK_RPC_CALL_C_VerifyFinal,
	GCK_RPC_CALL_C_VerifyRecoverInit,
	GCK_RPC_CALL_C_VerifyRecover,
	GCK_RPC_CALL_C_DigestEncryptUpdate,
	GCK_RPC_CALL_C_DecryptDigestUpdate,
	GCK_RPC_CALL_C_SignEncryptUpdate,
	GCK_RPC_CALL_C_DecryptVerifyUpdate,
	GCK_RPC_CALL_C_GenerateKey,
	GCK_RPC_CALL_C_GenerateKeyPair,
	GCK_RPC_CALL_C_WrapKey,
	GCK_RPC_CALL_C_UnwrapKey,
	GCK_RPC_CALL_C_DeriveKey,
	GCK_RPC_CALL_C_SeedRandom,
	GCK_RPC_CALL_C_GenerateRandom,

	GCK_RPC_CALL_C_LoginUser,
	GCK_RPC_CALL_C_SessionCancel,
	GCK_RPC_CALL_C_MessageEncryptInit,
	GCK_RPC_CALL_C_EncryptMessage,
	GCK_RPC_CALL_C_EncryptMessageBegin,
	GCK_RPC_CALL_C_EncryptMessageNext,
	GCK_RPC_CALL_C_MessageEncryptFinal,
	GCK_RPC_CALL_C_MessageDecryptInit,
	GCK_RPC_CALL_C_DecryptMessage,
	GCK_RPC_CALL_C_DecryptMessageBegin,
	GCK_RPC_CALL_C_DecryptMessageNext,
	GCK_RPC_CALL_C_MessageDecryptFinal,
	GCK_RPC_CALL_C_MessageSignInit,
	GCK_RPC_CALL_C_SignMessage,
	GCK_RPC_CALL_C_SignMessageBegin,
	GCK_RPC_CALL_C_SignMessageNext,
	GCK_RPC_CALL_C_MessageSignFinal,
	GCK_RPC_CALL_C_MessageVerifyInit,
	GCK_RPC_CALL_C_VerifyMessage,
	GCK_RPC_CALL_C_VerifyMessageBegin,
	GCK_RPC_CALL_C_VerifyMessageNext,
	GCK_RPC_CALL_C_MessageVerifyFinal,
	GCK_RPC_CALL_C_EncapsulateKey,
	GCK_RPC_CALL_C_DecapsulateKey,
	GCK_RPC_CALL_C_VerifySignatureInit,
	GCK_RPC_CALL_C_VerifySignature,
	GCK_RPC_CALL_C_VerifySignatureUpdate,
	GCK_RPC_CALL_C_VerifySignatureFinal,
	GCK_RPC_CALL_C_GetSessionValidationFlags,
	GCK_RPC_CALL_C_AsyncComplete,
	GCK_RPC_CALL_C_AsyncGetID,
	GCK_RPC_CALL_C_AsyncJoin,
	GCK_RPC_CALL_C_WrapKeyAuthenticated,
	GCK_RPC_CALL_C_UnwrapKeyAuthenticated,

	GCK_RPC_CALL_MAX
};

typedef struct _GckRpcCall {
	int call_id;
	const char *name;
	const char *request;
	const char *response;
} GckRpcCall;

/*
 *  a_ = prefix denotes array of _
 *  A  = CK_ATTRIBUTE
 *  f_ = prefix denotes buffer for _
 *  M  = CK_MECHANISM
 *  u  = CK_ULONG
 *  s  = space padded string
 *  v  = CK_VERSION
 *  y  = CK_BYTE
 */

static const GckRpcCall gck_rpc_calls[] = {
	{GCK_RPC_CALL_ERROR, "ERROR", NULL, NULL},
	{GCK_RPC_CALL_C_Initialize, "C_Initialize", "ay", ""},
	{GCK_RPC_CALL_C_Finalize, "C_Finalize", "", ""},
	{GCK_RPC_CALL_C_GetInfo, "C_GetInfo", "", "vsusv"},
	{GCK_RPC_CALL_C_GetSlotList, "C_GetSlotList", "yfu", "au"},
	{GCK_RPC_CALL_C_GetSlotInfo, "C_GetSlotInfo", "u", "ssuvv"},
	{GCK_RPC_CALL_C_GetTokenInfo, "C_GetTokenInfo", "u",
	 "ssssuuuuuuuuuuuvvs"},
	{GCK_RPC_CALL_C_GetMechanismList, "C_GetMechanismList", "ufu", "au"},
	{GCK_RPC_CALL_C_GetMechanismInfo, "C_GetMechanismInfo", "uu", "uuu"},
	{GCK_RPC_CALL_C_InitToken, "C_InitToken", "uays", ""},
	{GCK_RPC_CALL_C_WaitForSlotEvent, "C_WaitForSlotEvent", "u", "u"},
	{GCK_RPC_CALL_C_OpenSession, "C_OpenSession", "uu", "u"},
	{GCK_RPC_CALL_C_CloseSession, "C_CloseSession", "u", ""},
	{GCK_RPC_CALL_C_CloseAllSessions, "C_CloseAllSessions", "u", ""},
	{GCK_RPC_CALL_C_GetFunctionStatus, "C_GetFunctionStatus", "u", ""},
	{GCK_RPC_CALL_C_CancelFunction, "C_CancelFunction", "u", ""},
	{GCK_RPC_CALL_C_GetSessionInfo, "C_GetSessionInfo", "u", "uuuu"},
	{GCK_RPC_CALL_C_InitPIN, "C_InitPIN", "uay", ""},
	{GCK_RPC_CALL_C_SetPIN, "C_SetPIN", "uayay", ""},
	{GCK_RPC_CALL_C_GetOperationState, "C_GetOperationState", "ufy", "ay"},
	{GCK_RPC_CALL_C_SetOperationState, "C_SetOperationState", "uayuu", ""},
	{GCK_RPC_CALL_C_Login, "C_Login", "uuay", ""},
	{GCK_RPC_CALL_C_Logout, "C_Logout", "u", ""},
	{GCK_RPC_CALL_C_CreateObject, "C_CreateObject", "uaA", "u"},
	{GCK_RPC_CALL_C_CopyObject, "C_CopyObject", "uuaA", "u"},
	{GCK_RPC_CALL_C_DestroyObject, "C_DestroyObject", "uu", ""},
	{GCK_RPC_CALL_C_GetObjectSize, "C_GetObjectSize", "uu", "u"},
	{GCK_RPC_CALL_C_GetAttributeValue, "C_GetAttributeValue", "uufA",
	 "aAu"},
	{GCK_RPC_CALL_C_SetAttributeValue, "C_SetAttributeValue", "uuaA", ""},
	{GCK_RPC_CALL_C_FindObjectsInit, "C_FindObjectsInit", "uaA", ""},
	{GCK_RPC_CALL_C_FindObjects, "C_FindObjects", "ufu", "au"},
	{GCK_RPC_CALL_C_FindObjectsFinal, "C_FindObjectsFinal", "u", ""},
	{GCK_RPC_CALL_C_EncryptInit, "C_EncryptInit", "uMu", ""},
	{GCK_RPC_CALL_C_Encrypt, "C_Encrypt", "uayfy", "ay"},
	{GCK_RPC_CALL_C_EncryptUpdate, "C_EncryptUpdate", "uayfy", "ay"},
	{GCK_RPC_CALL_C_EncryptFinal, "C_EncryptFinal", "ufy", "ay"},
	{GCK_RPC_CALL_C_DecryptInit, "C_DecryptInit", "uMu", ""},
	{GCK_RPC_CALL_C_Decrypt, "C_Decrypt", "uayfy", "ay"},
	{GCK_RPC_CALL_C_DecryptUpdate, "C_DecryptUpdate", "uayfy", "ay"},
	{GCK_RPC_CALL_C_DecryptFinal, "C_DecryptFinal", "ufy", "ay"},
	{GCK_RPC_CALL_C_DigestInit, "C_DigestInit", "uM", ""},
	{GCK_RPC_CALL_C_Digest, "C_Digest", "uayfy", "ay"},
	{GCK_RPC_CALL_C_DigestUpdate, "C_DigestUpdate", "uay", ""},
	{GCK_RPC_CALL_C_DigestKey, "C_DigestKey", "uu", ""},
	{GCK_RPC_CALL_C_DigestFinal, "C_DigestFinal", "ufy", "ay"},
	{GCK_RPC_CALL_C_SignInit, "C_SignInit", "uMu", ""},
	{GCK_RPC_CALL_C_Sign, "C_Sign", "uayfy", "ay"},
	{GCK_RPC_CALL_C_SignUpdate, "C_SignUpdate", "uay", ""},
	{GCK_RPC_CALL_C_SignFinal, "C_SignFinal", "ufy", "ay"},
	{GCK_RPC_CALL_C_SignRecoverInit, "C_SignRecoverInit", "uMu", ""},
	{GCK_RPC_CALL_C_SignRecover, "C_SignRecover", "uayfy", "ay"},
	{GCK_RPC_CALL_C_VerifyInit, "C_VerifyInit", "uMu", ""},
	{GCK_RPC_CALL_C_Verify, "C_Verify", "uayay", ""},
	{GCK_RPC_CALL_C_VerifyUpdate, "C_VerifyUpdate", "uay", ""},
	{GCK_RPC_CALL_C_VerifyFinal, "C_VerifyFinal", "uay", ""},
	{GCK_RPC_CALL_C_VerifyRecoverInit, "C_VerifyRecoverInit", "uMu", ""},
	{GCK_RPC_CALL_C_VerifyRecover, "C_VerifyRecover", "uayfy", "ay"},
	{GCK_RPC_CALL_C_DigestEncryptUpdate, "C_DigestEncryptUpdate", "uayfy",
	 "ay"},
	{GCK_RPC_CALL_C_DecryptDigestUpdate, "C_DecryptDigestUpdate", "uayfy",
	 "ay"},
	{GCK_RPC_CALL_C_SignEncryptUpdate, "C_SignEncryptUpdate", "uayfy",
	 "ay"},
	{GCK_RPC_CALL_C_DecryptVerifyUpdate, "C_DecryptVerifyUpdate", "uayfy",
	 "ay"},
	{GCK_RPC_CALL_C_GenerateKey, "C_GenerateKey", "uMaA", "u"},
	{GCK_RPC_CALL_C_GenerateKeyPair, "C_GenerateKeyPair", "uMaAaA", "uu"},
	{GCK_RPC_CALL_C_WrapKey, "C_WrapKey", "uMuufy", "ay"},
	{GCK_RPC_CALL_C_UnwrapKey, "C_UnwrapKey", "uMuayaA", "u"},
	{GCK_RPC_CALL_C_DeriveKey, "C_DeriveKey", "uMuaA", "u"},
	{GCK_RPC_CALL_C_SeedRandom, "C_SeedRandom", "uay", ""},
	{GCK_RPC_CALL_C_GenerateRandom, "C_GenerateRandom", "ufy", "ay"},
	{GCK_RPC_CALL_C_LoginUser, "C_LoginUser", "uuayay", ""},
	{GCK_RPC_CALL_C_SessionCancel, "C_SessionCancel", "uu", ""},
	{GCK_RPC_CALL_C_MessageEncryptInit, "C_MessageEncryptInit", "uMu", ""},
	{GCK_RPC_CALL_C_EncryptMessage, "C_EncryptMessage", "uayayayfy", "ayay"},
	{GCK_RPC_CALL_C_EncryptMessageBegin, "C_EncryptMessageBegin", "uayay", "ay"},
	{GCK_RPC_CALL_C_EncryptMessageNext, "C_EncryptMessageNext", "uayayfyu", "ayay"},
	{GCK_RPC_CALL_C_MessageEncryptFinal, "C_MessageEncryptFinal", "u", ""},
	{GCK_RPC_CALL_C_MessageDecryptInit, "C_MessageDecryptInit", "uMu", ""},
	{GCK_RPC_CALL_C_DecryptMessage, "C_DecryptMessage", "uayayayfy", "ay"},
	{GCK_RPC_CALL_C_DecryptMessageBegin, "C_DecryptMessageBegin", "uayay", ""},
	{GCK_RPC_CALL_C_DecryptMessageNext, "C_DecryptMessageNext", "uayayfyu", "ay"},
	{GCK_RPC_CALL_C_MessageDecryptFinal, "C_MessageDecryptFinal", "u", ""},
	{GCK_RPC_CALL_C_MessageSignInit, "C_MessageSignInit", "uMu", ""},
	{GCK_RPC_CALL_C_SignMessage, "C_SignMessage", "uayayfy", "ay"},
	{GCK_RPC_CALL_C_SignMessageBegin, "C_SignMessageBegin", "uay", ""},
	{GCK_RPC_CALL_C_SignMessageNext, "C_SignMessageNext", "uayayfy", "ay"},
	{GCK_RPC_CALL_C_MessageSignFinal, "C_MessageSignFinal", "u", ""},
	{GCK_RPC_CALL_C_MessageVerifyInit, "C_MessageVerifyInit", "uMu", ""},
	{GCK_RPC_CALL_C_VerifyMessage, "C_VerifyMessage", "uayayay", ""},
	{GCK_RPC_CALL_C_VerifyMessageBegin, "C_VerifyMessageBegin", "uay", ""},
	{GCK_RPC_CALL_C_VerifyMessageNext, "C_VerifyMessageNext", "uayayay", ""},
	{GCK_RPC_CALL_C_MessageVerifyFinal, "C_MessageVerifyFinal", "u", ""},
	{GCK_RPC_CALL_C_EncapsulateKey, "C_EncapsulateKey", "uMuaAfy", "ayu"},
	{GCK_RPC_CALL_C_DecapsulateKey, "C_DecapsulateKey", "uMuaAay", "u"},
	{GCK_RPC_CALL_C_VerifySignatureInit, "C_VerifySignatureInit", "uMuay", ""},
	{GCK_RPC_CALL_C_VerifySignature, "C_VerifySignature", "uay", ""},
	{GCK_RPC_CALL_C_VerifySignatureUpdate, "C_VerifySignatureUpdate", "uay", ""},
	{GCK_RPC_CALL_C_VerifySignatureFinal, "C_VerifySignatureFinal", "u", ""},
	{GCK_RPC_CALL_C_GetSessionValidationFlags, "C_GetSessionValidationFlags", "uu", "u"},
	{GCK_RPC_CALL_C_AsyncComplete, "C_AsyncComplete", "uayufy", "ayuuu"},
	{GCK_RPC_CALL_C_AsyncGetID, "C_AsyncGetID", "uay", "u"},
	{GCK_RPC_CALL_C_AsyncJoin, "C_AsyncJoin", "uayufy", "ay"},
	{GCK_RPC_CALL_C_WrapKeyAuthenticated, "C_WrapKeyAuthenticated", "uMuuayfy", "ay"},
	{GCK_RPC_CALL_C_UnwrapKeyAuthenticated, "C_UnwrapKeyAuthenticated", "uMuayaAay", "u"},
};

#ifdef _DEBUG
#define GCK_RPC_CHECK_CALLS() \
	{ int i; for (i = 0; i < GCK_RPC_CALL_MAX; ++i) assert (gck_rpc_calls[i].call_id == i); }
#endif

#define GCK_RPC_HANDSHAKE \
	"PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-4"
#define GCK_RPC_HANDSHAKE_LEN \
	(sizeof (GCK_RPC_HANDSHAKE) - 1)

#define GCK_RPC_SOCKET_EXT 	"pkcs11"

typedef enum _GckRpcMessageType {
	GCK_RPC_REQUEST = 1,
	GCK_RPC_RESPONSE
} GckRpcMessageType;

typedef struct _GckRpcMessage {
	int call_id;
	GckRpcMessageType call_type;
	const char *signature;
	EggBuffer buffer;

	size_t parsed;
	const char *sigverify;
} GckRpcMessage;

#define GCK_RPC_BYTE_BUFFER_NULL_DATA	1
#define GCK_RPC_BYTE_BUFFER_NULL_COUNT	2

GckRpcMessage *gck_rpc_message_new(EggBufferAllocator allocator);

void gck_rpc_message_free(GckRpcMessage * msg);

void gck_rpc_message_reset(GckRpcMessage * msg);

int gck_rpc_message_equals(GckRpcMessage * m1, GckRpcMessage * m2);

#define                  gck_rpc_message_is_verified(msg)        (!(msg)->sigverify || (msg)->sigverify[0] == 0)

#define                  gck_rpc_message_buffer_error(msg)       (egg_buffer_has_error(&(msg)->buffer))

int gck_rpc_message_prep(GckRpcMessage * msg,
			 int call_id, GckRpcMessageType type);

int gck_rpc_message_parse(GckRpcMessage * msg, GckRpcMessageType type);

int gck_rpc_message_verify_part(GckRpcMessage * msg, const char *part);

int gck_rpc_message_write_byte(GckRpcMessage * msg, CK_BYTE val);

int gck_rpc_message_write_ulong(GckRpcMessage * msg, CK_ULONG val);

int gck_rpc_message_write_space_string(GckRpcMessage * msg,
				       CK_UTF8CHAR * buffer, CK_ULONG length);

int gck_rpc_message_write_byte_buffer(GckRpcMessage * msg, CK_BYTE_PTR arr, CK_ULONG *count_ptr);

int gck_rpc_message_write_byte_array(GckRpcMessage * msg,
				     CK_BYTE_PTR arr, CK_ULONG num);

int gck_rpc_message_write_ulong_buffer(GckRpcMessage * msg, CK_ULONG count);

int gck_rpc_message_write_ulong_array(GckRpcMessage * msg,
				      CK_ULONG_PTR arr, CK_ULONG num);

int gck_rpc_message_write_attribute_buffer(GckRpcMessage * msg,
					   CK_ATTRIBUTE_PTR arr, CK_ULONG num);

int gck_rpc_message_write_attribute_array(GckRpcMessage * msg,
					  CK_ATTRIBUTE_PTR arr, CK_ULONG num);

int gck_rpc_message_write_version(GckRpcMessage * msg, CK_VERSION * version);

int gck_rpc_message_read_byte(GckRpcMessage * msg, CK_BYTE * val);

int gck_rpc_message_read_ulong(GckRpcMessage * msg, CK_ULONG * val);

int gck_rpc_message_read_space_string(GckRpcMessage * msg,
				      CK_UTF8CHAR * buffer, CK_ULONG length);

int gck_rpc_message_read_version(GckRpcMessage * msg, CK_VERSION * version);

void gck_rpc_log(const char *msg, ...);

void gck_rpc_warn(const char *msg, ...);

void gck_rpc_debug(const char *msg, ...);

#ifdef G_DISABLE_ASSERT
#define assert(x)
#else
#include <assert.h>
#endif

/*
 * PKCS#11 mechanism parameters are not easy to serialize. They're
 * completely different for so many mechanisms, they contain
 * pointers to arbitrary memory, and many callers don't initialize
 * them completely or properly.
 *
 * We only support certain mechanisms.
 *
 * Also callers do yucky things like leaving parts of the structure
 * pointing to garbage if they don't think it's going to be used.
 */

int gck_rpc_mechanism_is_supported(CK_MECHANISM_TYPE mech);
void gck_rpc_mechanism_list_purge(CK_MECHANISM_TYPE_PTR mechs,
				  CK_ULONG_PTR n_mechs);
int gck_rpc_mechanism_has_sane_parameters(CK_MECHANISM_TYPE type);
int gck_rpc_mechanism_has_no_parameters(CK_MECHANISM_TYPE mech);

/* Mechanisms with an optional CK_[HASH_]SIGN_ADDITIONAL_CONTEXT parameter.
 * Wire format of the parameter: empty when the caller passed none, otherwise
 * hedgeVariant (8 bytes BE), [hash (8 bytes BE), HASH_SIGN only], context. */
#define GCK_RPC_CONTEXT_SIGN		1
#define GCK_RPC_CONTEXT_HASH_SIGN	2
#define GCK_RPC_CONTEXT_MAX_LEN		255
int gck_rpc_mechanism_context_kind(CK_MECHANISM_TYPE mech);

#ifdef CKM_ML_DSA
#define GCK_RPC_HAVE_V32 1

/*
 * Field-by-field serialization of the pointer-carrying AEAD parameter
 * structures (CK_GCM_PARAMS, CK_GCM_MESSAGE_PARAMS, ...), so that no
 * client pointer ever reaches the daemon's module.
 *
 * Wire blob: kind byte, every CK_ULONG field as 8 bytes BE (table order),
 * then the bytes of the buffers sent in the given phase (table order).
 * After an encrypt-message call the daemon returns the buffers flagged
 * `resp` (generated IV/nonce and tag) as one concatenated byte array.
 */
#define GCK_RPC_PHASE_MECH	1	/* mechanism parameter (input only) */
#define GCK_RPC_PHASE_ENC	2	/* C_Encrypt<Message*> parameter */
#define GCK_RPC_PHASE_DEC	4	/* C_Decrypt<Message*> parameter */
#define GCK_RPC_PARAM_MAX_BUF	65536
#define GCK_RPC_MSGPARAM_BLOB	2400	/* stack blob for message params */
#define GCK_RPC_PARAM_MAX_FIELDS 8

typedef struct {
	int is_buf;		/* 0: CK_ULONG field, 1: CK_BYTE_PTR field */
	size_t off;		/* offset in the CK_* structure */
	int len_idx;		/* buf: index of the field giving its length */
	int len_bits;		/* buf: that field counts bits */
	size_t len_fixed;	/* buf: fixed length (when len_idx < 0) */
	int req;		/* buf: phases in which its bytes are sent */
	int resp;		/* buf: returned after an encrypt-message call */
} GckRpcParamField;

typedef struct {
	int kind;
	int phases;		/* phases this structure may be used in */
	size_t size;		/* sizeof the CK_* structure */
	int nfields;
	const GckRpcParamField *fields;
} GckRpcParamDesc;

typedef struct {
	const GckRpcParamDesc *desc;
	union {
		CK_GCM_PARAMS gcm;
		CK_GCM_MESSAGE_PARAMS gcm_msg;
		CK_CCM_PARAMS ccm;
		CK_CCM_MESSAGE_PARAMS ccm_msg;
		CK_SALSA20_CHACHA20_POLY1305_PARAMS chacha;
		CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS chacha_msg;
	} s;
	size_t lens[GCK_RPC_PARAM_MAX_FIELDS];
} GckRpcParamState;

const GckRpcParamDesc *gck_rpc_param_desc_for_mechanism(CK_MECHANISM_TYPE mech);
const GckRpcParamDesc *gck_rpc_param_desc_for_message(CK_ULONG param_len);
CK_RV gck_rpc_param_encode(const GckRpcParamDesc *d, const void *param,
			   int phase, unsigned char *out, size_t cap,
			   size_t *out_len);
CK_RV gck_rpc_param_decode(const unsigned char *blob, size_t n, int phase,
			   GckRpcParamState *st,
			   void *(*alloc)(void *, size_t), void *ctx);
CK_RV gck_rpc_param_resp_encode(const GckRpcParamState *st,
				unsigned char *out, size_t cap,
				size_t *out_len);
CK_RV gck_rpc_param_resp_apply(const GckRpcParamDesc *d, void *param,
			       const unsigned char *blob, size_t n);
#endif
int gck_rpc_has_bad_sized_ulong_parameter(CK_ATTRIBUTE_PTR attr);
int gck_rpc_has_ulong_parameter(CK_ATTRIBUTE_TYPE type);

/* Parses strings (prefix) to host and port components. */
int gck_rpc_parse_host_port(const char *prefix, char **host, char **port);

#endif /* GCK_RPC_CALLS_H */
