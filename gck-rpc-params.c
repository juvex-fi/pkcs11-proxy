/* gck-rpc-params.c - field-by-field serialization of mechanism parameters
 *
 * A mechanism parameter is a C structure that often holds pointers, which mean
 * nothing in the daemon's address space. Each such structure is described by a
 * table (GckRpcParamDesc); the client turns the caller's structure into a
 * blob, and the daemon rebuilds an equivalent one in its own memory, so no
 * pointer received from a client ever reaches the module. Members the module
 * fills in (versions, IVs, key handles, PRF output) are returned in a reply
 * blob that the client applies to the caller's own structure.
 *
 * Wire blob: a kind byte, then the body of the structure:
 *   1. every CK_ULONG / CK_BBOOL / CK_BYTE member as 8 bytes big endian, and
 *      for pointers to a CK_ULONG a presence byte (and the value if it is an
 *      input); the length members needed by the next step come first
 *   2. in member order, the rest: buffer bytes, inline bytes, and (each with a
 *      presence byte where a NULL pointer is meaningful) pointed-to and nested
 *      structures, arrays of structures, attribute templates, C strings and
 *      nested mechanisms.
 * The reply holds, in the same two steps, only the members flagged `resp`.
 */
#include "config.h"

#include "gck-rpc-layer.h"
#include "gck-rpc-private.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef GCK_RPC_HAVE_V32

#define PARAM_MAX_BLOB	(4u << 20)	/* one encoded parameter */
#define PARAM_MAX_ALLOC	(8u << 20)	/* what one decoded parameter may allocate */
#define ARRAY_MAX	256
#define CSTR_MAX	4096

/* ------------------------------------------------------------------------
 * descriptors
 */

#define PH_MSG  (GCK_RPC_PHASE_ENC | GCK_RPC_PHASE_DEC)
#define PH_MECH GCK_RPC_PHASE_MECH

#define FLD_(t, s, m, idx, fl, fixed, rq, rs, sb) \
	{ t, offsetof(s, m), idx, fl, fixed, rq, rs, sb }
#define U_(s, m)	FLD_(GCK_RPC_F_ULONG, s, m, 0, 0, 0, 0, 0, NULL)
#define UR_(s, m)	FLD_(GCK_RPC_F_ULONG, s, m, 0, 0, 0, 0, 1, NULL)	/* output */
#define Z_(s, m)	FLD_(GCK_RPC_F_BBOOL, s, m, 0, 0, 0, 0, 0, NULL)
#define Y_(s, m)	FLD_(GCK_RPC_F_BYTE, s, m, 0, 0, 0, 0, 0, NULL)
#define B_(s, m, idx, fl, fixed, rq, rs) \
	FLD_(GCK_RPC_F_BUF, s, m, idx, fl, fixed, rq, rs, NULL)
#define OB_(s, m, idx, fl, fixed, rq, rs) \
	FLD_(GCK_RPC_F_OBUF, s, m, idx, fl, fixed, rq, rs, NULL)
#define I_(s, m, n)	FLD_(GCK_RPC_F_INLINE, s, m, 0, 0, n, PH_MECH, 0, NULL)
#define S_(s, m, d, rs)	FLD_(GCK_RPC_F_STRUCT, s, m, 0, 0, 0, PH_MECH, rs, d)
#define IS_(s, m, d, rs) FLD_(GCK_RPC_F_ISTRUCT, s, m, 0, 0, 0, PH_MECH, rs, d)
#define UP_(s, m, rq, rs) FLD_(GCK_RPC_F_ULONGPTR, s, m, 0, 0, 0, rq, rs, NULL)
#define A_(s, m, cnt, d, rs) FLD_(GCK_RPC_F_ARRAY, s, m, cnt, 0, 0, PH_MECH, rs, d)
#define AT_(s, m, cnt)	FLD_(GCK_RPC_F_ATTRS, s, m, cnt, 0, 0, PH_MECH, 0, NULL)
#define CS_(s, m)	FLD_(GCK_RPC_F_CSTR, s, m, 0, 0, 0, PH_MECH, 0, NULL)
#define MP_(s, m)	FLD_(GCK_RPC_F_MECHPTR, s, m, 0, 0, 0, PH_MECH, 0, NULL)

#define BITS GCK_RPC_LEN_BITS
#define PARENT GCK_RPC_LEN_PARENT
#define NF_(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define DESC_(name, kind, phases, type, fields) \
	static const GckRpcParamDesc name = \
		{ kind, phases, sizeof(type), NF_(fields), fields }

/* ---- message-based AEAD: IV/nonce and tag travel both ways ---- */
static const GckRpcParamField gcm_msg_fields[] = {
	B_(CK_GCM_MESSAGE_PARAMS, pIv, 1, 0, 0, PH_MSG, 1),
	U_(CK_GCM_MESSAGE_PARAMS, ulIvLen),
	U_(CK_GCM_MESSAGE_PARAMS, ulIvFixedBits),
	U_(CK_GCM_MESSAGE_PARAMS, ivGenerator),
	B_(CK_GCM_MESSAGE_PARAMS, pTag, 5, BITS, 0, PH_MSG, 1),
	U_(CK_GCM_MESSAGE_PARAMS, ulTagBits),
};
static const GckRpcParamField ccm_msg_fields[] = {
	U_(CK_CCM_MESSAGE_PARAMS, ulDataLen),
	B_(CK_CCM_MESSAGE_PARAMS, pNonce, 2, 0, 0, PH_MSG, 1),
	U_(CK_CCM_MESSAGE_PARAMS, ulNonceLen),
	U_(CK_CCM_MESSAGE_PARAMS, ulNonceFixedBits),
	U_(CK_CCM_MESSAGE_PARAMS, nonceGenerator),
	B_(CK_CCM_MESSAGE_PARAMS, pMAC, 6, 0, 0, PH_MSG, 1),
	U_(CK_CCM_MESSAGE_PARAMS, ulMACLen),
};
static const GckRpcParamField chacha_msg_fields[] = {
	B_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pNonce, 1, 0, 0, PH_MSG, 1),
	U_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, ulNonceLen),
	B_(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pTag, -1, 0, 16, PH_MSG, 1),
};

/* ---- single-part mechanism parameters ---- */
static const GckRpcParamField gcm_fields[] = {
	B_(CK_GCM_PARAMS, pIv, 1, 0, 0, PH_MECH, 0),
	U_(CK_GCM_PARAMS, ulIvLen),
	U_(CK_GCM_PARAMS, ulIvBits),
	B_(CK_GCM_PARAMS, pAAD, 4, 0, 0, PH_MECH, 0),
	U_(CK_GCM_PARAMS, ulAADLen),
	U_(CK_GCM_PARAMS, ulTagBits),
};
static const GckRpcParamField ccm_fields[] = {
	U_(CK_CCM_PARAMS, ulDataLen),
	B_(CK_CCM_PARAMS, pNonce, 2, 0, 0, PH_MECH, 0),
	U_(CK_CCM_PARAMS, ulNonceLen),
	B_(CK_CCM_PARAMS, pAAD, 4, 0, 0, PH_MECH, 0),
	U_(CK_CCM_PARAMS, ulAADLen),
	U_(CK_CCM_PARAMS, ulMACLen),
};
static const GckRpcParamField chacha_fields[] = {
	B_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pNonce, 1, 0, 0, PH_MECH, 0),
	U_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulNonceLen),
	B_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pAAD, 3, 0, 0, PH_MECH, 0),
	U_(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulAADLen),
};
static const GckRpcParamField oaep_fields[] = {
	U_(CK_RSA_PKCS_OAEP_PARAMS, hashAlg),
	U_(CK_RSA_PKCS_OAEP_PARAMS, mgf),
	U_(CK_RSA_PKCS_OAEP_PARAMS, source),
	B_(CK_RSA_PKCS_OAEP_PARAMS, pSourceData, 4, 0, 0, PH_MECH, 0),
	U_(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen),
};
static const GckRpcParamField ecdh1_fields[] = {
	U_(CK_ECDH1_DERIVE_PARAMS, kdf),
	U_(CK_ECDH1_DERIVE_PARAMS, ulSharedDataLen),
	B_(CK_ECDH1_DERIVE_PARAMS, pSharedData, 1, 0, 0, PH_MECH, 0),
	U_(CK_ECDH1_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_ECDH1_DERIVE_PARAMS, pPublicData, 3, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField ecdh_wrap_fields[] = {
	U_(CK_ECDH_AES_KEY_WRAP_PARAMS, ulAESKeyBits),
	U_(CK_ECDH_AES_KEY_WRAP_PARAMS, kdf),
	U_(CK_ECDH_AES_KEY_WRAP_PARAMS, ulSharedDataLen),
	B_(CK_ECDH_AES_KEY_WRAP_PARAMS, pSharedData, 2, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField hkdf_fields[] = {
	Z_(CK_HKDF_PARAMS, bExtract),
	Z_(CK_HKDF_PARAMS, bExpand),
	U_(CK_HKDF_PARAMS, prfHashMechanism),
	U_(CK_HKDF_PARAMS, ulSaltType),
	B_(CK_HKDF_PARAMS, pSalt, 5, 0, 0, PH_MECH, 0),
	U_(CK_HKDF_PARAMS, ulSaltLen),
	U_(CK_HKDF_PARAMS, hSaltKey),
	B_(CK_HKDF_PARAMS, pInfo, 8, 0, 0, PH_MECH, 0),
	U_(CK_HKDF_PARAMS, ulInfoLen),
};
static const GckRpcParamField eddsa_fields[] = {
	Z_(CK_EDDSA_PARAMS, phFlag),
	U_(CK_EDDSA_PARAMS, ulContextDataLen),
	B_(CK_EDDSA_PARAMS, pContextData, 1, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField chacha20_fields[] = {
	B_(CK_CHACHA20_PARAMS, pBlockCounter, 1, BITS, 0, PH_MECH, 0),
	U_(CK_CHACHA20_PARAMS, blockCounterBits),
	B_(CK_CHACHA20_PARAMS, pNonce, 3, BITS, 0, PH_MECH, 0),
	U_(CK_CHACHA20_PARAMS, ulNonceBits),
};
static const GckRpcParamField salsa20_fields[] = {
	B_(CK_SALSA20_PARAMS, pBlockCounter, -1, 0, 8, PH_MECH, 0),
	B_(CK_SALSA20_PARAMS, pNonce, 2, BITS, 0, PH_MECH, 0),
	U_(CK_SALSA20_PARAMS, ulNonceBits),
};
static const GckRpcParamField strdata_fields[] = {
	B_(CK_KEY_DERIVATION_STRING_DATA, pData, 1, 0, 0, PH_MECH, 0),
	U_(CK_KEY_DERIVATION_STRING_DATA, ulLen),
};
static const GckRpcParamField aes_cbc_data_fields[] = {
	I_(CK_AES_CBC_ENCRYPT_DATA_PARAMS, iv, 16),
	B_(CK_AES_CBC_ENCRYPT_DATA_PARAMS, pData, 2, 0, 0, PH_MECH, 0),
	U_(CK_AES_CBC_ENCRYPT_DATA_PARAMS, length),
};
static const GckRpcParamField des_cbc_data_fields[] = {
	I_(CK_DES_CBC_ENCRYPT_DATA_PARAMS, iv, 8),
	B_(CK_DES_CBC_ENCRYPT_DATA_PARAMS, pData, 2, 0, 0, PH_MECH, 0),
	U_(CK_DES_CBC_ENCRYPT_DATA_PARAMS, length),
};
static const GckRpcParamField dsa_gen_fields[] = {
	U_(CK_DSA_PARAMETER_GEN_PARAM, hash),
	B_(CK_DSA_PARAMETER_GEN_PARAM, pSeed, 2, 0, 0, PH_MECH, 0),
	U_(CK_DSA_PARAMETER_GEN_PARAM, ulSeedLen),
	U_(CK_DSA_PARAMETER_GEN_PARAM, ulIndex),
};

/* ---- IKE ---- */
static const GckRpcParamField ike2_prf_plus_fields[] = {
	U_(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, prfMechanism),
	Z_(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, bHasSeedKey),
	U_(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, hSeedKey),
	B_(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, pSeedData, 4, 0, 0, PH_MECH, 0),
	U_(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, ulSeedDataLen),
};
static const GckRpcParamField ike_prf_fields[] = {
	U_(CK_IKE_PRF_DERIVE_PARAMS, prfMechanism),
	Z_(CK_IKE_PRF_DERIVE_PARAMS, bDataAsKey),
	Z_(CK_IKE_PRF_DERIVE_PARAMS, bRekey),
	B_(CK_IKE_PRF_DERIVE_PARAMS, pNi, 4, 0, 0, PH_MECH, 0),
	U_(CK_IKE_PRF_DERIVE_PARAMS, ulNiLen),
	B_(CK_IKE_PRF_DERIVE_PARAMS, pNr, 6, 0, 0, PH_MECH, 0),
	U_(CK_IKE_PRF_DERIVE_PARAMS, ulNrLen),
	U_(CK_IKE_PRF_DERIVE_PARAMS, hNewKey),
};
static const GckRpcParamField ike1_prf_fields[] = {
	U_(CK_IKE1_PRF_DERIVE_PARAMS, prfMechanism),
	Z_(CK_IKE1_PRF_DERIVE_PARAMS, bHasPrevKey),
	U_(CK_IKE1_PRF_DERIVE_PARAMS, hKeygxy),
	U_(CK_IKE1_PRF_DERIVE_PARAMS, hPrevKey),
	B_(CK_IKE1_PRF_DERIVE_PARAMS, pCKYi, 5, 0, 0, PH_MECH, 0),
	U_(CK_IKE1_PRF_DERIVE_PARAMS, ulCKYiLen),
	B_(CK_IKE1_PRF_DERIVE_PARAMS, pCKYr, 7, 0, 0, PH_MECH, 0),
	U_(CK_IKE1_PRF_DERIVE_PARAMS, ulCKYrLen),
	Y_(CK_IKE1_PRF_DERIVE_PARAMS, keyNumber),
};
static const GckRpcParamField ike1_ext_fields[] = {
	U_(CK_IKE1_EXTENDED_DERIVE_PARAMS, prfMechanism),
	Z_(CK_IKE1_EXTENDED_DERIVE_PARAMS, bHasKeygxy),
	U_(CK_IKE1_EXTENDED_DERIVE_PARAMS, hKeygxy),
	B_(CK_IKE1_EXTENDED_DERIVE_PARAMS, pExtraData, 4, 0, 0, PH_MECH, 0),
	U_(CK_IKE1_EXTENDED_DERIVE_PARAMS, ulExtraDataLen),
};

/* ---- Diffie-Hellman variants and other key agreement ---- */
static const GckRpcParamField x942_dh1_fields[] = {
	U_(CK_X9_42_DH1_DERIVE_PARAMS, kdf),
	U_(CK_X9_42_DH1_DERIVE_PARAMS, ulOtherInfoLen),
	B_(CK_X9_42_DH1_DERIVE_PARAMS, pOtherInfo, 1, 0, 0, PH_MECH, 0),
	U_(CK_X9_42_DH1_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_X9_42_DH1_DERIVE_PARAMS, pPublicData, 3, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField x942_dh2_fields[] = {
	U_(CK_X9_42_DH2_DERIVE_PARAMS, kdf),
	U_(CK_X9_42_DH2_DERIVE_PARAMS, ulOtherInfoLen),
	B_(CK_X9_42_DH2_DERIVE_PARAMS, pOtherInfo, 1, 0, 0, PH_MECH, 0),
	U_(CK_X9_42_DH2_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_X9_42_DH2_DERIVE_PARAMS, pPublicData, 3, 0, 0, PH_MECH, 0),
	U_(CK_X9_42_DH2_DERIVE_PARAMS, ulPrivateDataLen),
	U_(CK_X9_42_DH2_DERIVE_PARAMS, hPrivateData),
	U_(CK_X9_42_DH2_DERIVE_PARAMS, ulPublicDataLen2),
	B_(CK_X9_42_DH2_DERIVE_PARAMS, pPublicData2, 7, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField x942_mqv_fields[] = {
	U_(CK_X9_42_MQV_DERIVE_PARAMS, kdf),
	U_(CK_X9_42_MQV_DERIVE_PARAMS, ulOtherInfoLen),
	B_(CK_X9_42_MQV_DERIVE_PARAMS, pOtherInfo, 1, 0, 0, PH_MECH, 0),
	U_(CK_X9_42_MQV_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData, 3, 0, 0, PH_MECH, 0),
	U_(CK_X9_42_MQV_DERIVE_PARAMS, ulPrivateDataLen),
	U_(CK_X9_42_MQV_DERIVE_PARAMS, hPrivateData),
	U_(CK_X9_42_MQV_DERIVE_PARAMS, ulPublicDataLen2),
	B_(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData2, 7, 0, 0, PH_MECH, 0),
	U_(CK_X9_42_MQV_DERIVE_PARAMS, publicKey),
};
static const GckRpcParamField ecmqv_fields[] = {
	U_(CK_ECMQV_DERIVE_PARAMS, kdf),
	U_(CK_ECMQV_DERIVE_PARAMS, ulSharedDataLen),
	B_(CK_ECMQV_DERIVE_PARAMS, pSharedData, 1, 0, 0, PH_MECH, 0),
	U_(CK_ECMQV_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_ECMQV_DERIVE_PARAMS, pPublicData, 3, 0, 0, PH_MECH, 0),
	U_(CK_ECMQV_DERIVE_PARAMS, ulPrivateDataLen),
	U_(CK_ECMQV_DERIVE_PARAMS, hPrivateData),
	U_(CK_ECMQV_DERIVE_PARAMS, ulPublicDataLen2),
	B_(CK_ECMQV_DERIVE_PARAMS, pPublicData2, 7, 0, 0, PH_MECH, 0),
	U_(CK_ECMQV_DERIVE_PARAMS, publicKey),
};
static const GckRpcParamField kea_fields[] = {
	Z_(CK_KEA_DERIVE_PARAMS, isSender),
	U_(CK_KEA_DERIVE_PARAMS, ulRandomLen),
	B_(CK_KEA_DERIVE_PARAMS, pRandomA, 1, 0, 0, PH_MECH, 0),
	B_(CK_KEA_DERIVE_PARAMS, pRandomB, 1, 0, 0, PH_MECH, 0),
	U_(CK_KEA_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_KEA_DERIVE_PARAMS, pPublicData, 4, 0, 0, PH_MECH, 0),
};
static const GckRpcParamField rc5_cbc_fields[] = {
	U_(CK_RC5_CBC_PARAMS, ulWordsize),
	U_(CK_RC5_CBC_PARAMS, ulRounds),
	B_(CK_RC5_CBC_PARAMS, pIv, 3, 0, 0, PH_MECH, 0),
	U_(CK_RC5_CBC_PARAMS, ulIvLen),
};
static const GckRpcParamField gost_derive_fields[] = {
	U_(CK_GOSTR3410_DERIVE_PARAMS, kdf),
	B_(CK_GOSTR3410_DERIVE_PARAMS, pPublicData, 2, 0, 0, PH_MECH, 0),
	U_(CK_GOSTR3410_DERIVE_PARAMS, ulPublicDataLen),
	B_(CK_GOSTR3410_DERIVE_PARAMS, pUKM, 4, 0, 0, PH_MECH, 0),
	U_(CK_GOSTR3410_DERIVE_PARAMS, ulUKMLen),
};
static const GckRpcParamField gost_wrap_fields[] = {
	B_(CK_GOSTR3410_KEY_WRAP_PARAMS, pWrapOID, 1, 0, 0, PH_MECH, 0),
	U_(CK_GOSTR3410_KEY_WRAP_PARAMS, ulWrapOIDLen),
	B_(CK_GOSTR3410_KEY_WRAP_PARAMS, pUKM, 3, 0, 0, PH_MECH, 0),
	U_(CK_GOSTR3410_KEY_WRAP_PARAMS, ulUKMLen),
	U_(CK_GOSTR3410_KEY_WRAP_PARAMS, hKey),
};
static const GckRpcParamField set_oaep_fields[] = {
	Y_(CK_KEY_WRAP_SET_OAEP_PARAMS, bBC),
	B_(CK_KEY_WRAP_SET_OAEP_PARAMS, pX, 2, 0, 0, PH_MECH, 0),
	U_(CK_KEY_WRAP_SET_OAEP_PARAMS, ulXLen),
};

/* ---- one-time passwords: an array of typed values ---- */
static const GckRpcParamField otp_param_fields[] = {
	U_(CK_OTP_PARAM, type),
	B_(CK_OTP_PARAM, pValue, 2, 0, 0, PH_MECH, 0),
	U_(CK_OTP_PARAM, ulValueLen),
};
DESC_(d_otp_param, 0, PH_MECH, CK_OTP_PARAM, otp_param_fields);
static const GckRpcParamField otp_fields[] = {
	A_(CK_OTP_PARAMS, pParams, 1, &d_otp_param, 0),
	U_(CK_OTP_PARAMS, ulCount),
};

/* ---- parameters that hold another mechanism ---- */
static const GckRpcParamField kip_fields[] = {
	MP_(CK_KIP_PARAMS, pMechanism),
	U_(CK_KIP_PARAMS, hKey),
	B_(CK_KIP_PARAMS, pSeed, 3, 0, 0, PH_MECH, 0),
	U_(CK_KIP_PARAMS, ulSeedLen),
};
static const GckRpcParamField cms_sig_fields[] = {
	U_(CK_CMS_SIG_PARAMS, certificateHandle),
	MP_(CK_CMS_SIG_PARAMS, pSigningMechanism),
	MP_(CK_CMS_SIG_PARAMS, pDigestMechanism),
	CS_(CK_CMS_SIG_PARAMS, pContentType),
	B_(CK_CMS_SIG_PARAMS, pRequestedAttributes, 5, 0, 0, PH_MECH, 0),
	U_(CK_CMS_SIG_PARAMS, ulRequestedAttributesLen),
	B_(CK_CMS_SIG_PARAMS, pRequiredAttributes, 7, 0, 0, PH_MECH, 0),
	U_(CK_CMS_SIG_PARAMS, ulRequiredAttributesLen),
};

/* ---- SSL / TLS / WTLS ---- */
static const GckRpcParamField random_fields[] = {
	B_(CK_SSL3_RANDOM_DATA, pClientRandom, 1, 0, 0, PH_MECH, 0),
	U_(CK_SSL3_RANDOM_DATA, ulClientRandomLen),
	B_(CK_SSL3_RANDOM_DATA, pServerRandom, 3, 0, 0, PH_MECH, 0),
	U_(CK_SSL3_RANDOM_DATA, ulServerRandomLen),
};
DESC_(d_random, 0, PH_MECH, CK_SSL3_RANDOM_DATA, random_fields);
/* the WTLS structure has the same layout */
typedef char wtls_random_layout_check[
	(sizeof(CK_WTLS_RANDOM_DATA) == sizeof(CK_SSL3_RANDOM_DATA) &&
	 offsetof(CK_WTLS_RANDOM_DATA, pServerRandom) ==
	 offsetof(CK_SSL3_RANDOM_DATA, pServerRandom)) ? 1 : -1];

static const GckRpcParamField ssl3_master_fields[] = {
	IS_(CK_SSL3_MASTER_KEY_DERIVE_PARAMS, RandomInfo, &d_random, 0),
	OB_(CK_SSL3_MASTER_KEY_DERIVE_PARAMS, pVersion, -1, 0, sizeof(CK_VERSION), PH_MECH, 1),
};
static const GckRpcParamField tls12_master_fields[] = {
	IS_(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, RandomInfo, &d_random, 0),
	OB_(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, pVersion, -1, 0, sizeof(CK_VERSION), PH_MECH, 1),
	U_(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, prfHashMechanism),
};
static const GckRpcParamField tls12_ext_master_fields[] = {
	U_(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, prfHashMechanism),
	B_(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, pSessionHash, 2, 0, 0, PH_MECH, 0),
	U_(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, ulSessionHashLen),
	OB_(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, pVersion, -1, 0, sizeof(CK_VERSION), PH_MECH, 1),
};
static const GckRpcParamField ssl3_key_out_fields[] = {
	UR_(CK_SSL3_KEY_MAT_OUT, hClientMacSecret),
	UR_(CK_SSL3_KEY_MAT_OUT, hServerMacSecret),
	UR_(CK_SSL3_KEY_MAT_OUT, hClientKey),
	UR_(CK_SSL3_KEY_MAT_OUT, hServerKey),
	OB_(CK_SSL3_KEY_MAT_OUT, pIVClient, 2, BITS | PARENT, 0, 0, 1),
	OB_(CK_SSL3_KEY_MAT_OUT, pIVServer, 2, BITS | PARENT, 0, 0, 1),
};
DESC_(d_ssl3_key_out, 0, PH_MECH, CK_SSL3_KEY_MAT_OUT, ssl3_key_out_fields);
static const GckRpcParamField ssl3_key_mat_fields[] = {
	U_(CK_SSL3_KEY_MAT_PARAMS, ulMacSizeInBits),
	U_(CK_SSL3_KEY_MAT_PARAMS, ulKeySizeInBits),
	U_(CK_SSL3_KEY_MAT_PARAMS, ulIVSizeInBits),
	Z_(CK_SSL3_KEY_MAT_PARAMS, bIsExport),
	IS_(CK_SSL3_KEY_MAT_PARAMS, RandomInfo, &d_random, 0),
	S_(CK_SSL3_KEY_MAT_PARAMS, pReturnedKeyMaterial, &d_ssl3_key_out, 1),
};
static const GckRpcParamField tls12_key_mat_fields[] = {
	U_(CK_TLS12_KEY_MAT_PARAMS, ulMacSizeInBits),
	U_(CK_TLS12_KEY_MAT_PARAMS, ulKeySizeInBits),
	U_(CK_TLS12_KEY_MAT_PARAMS, ulIVSizeInBits),
	Z_(CK_TLS12_KEY_MAT_PARAMS, bIsExport),
	IS_(CK_TLS12_KEY_MAT_PARAMS, RandomInfo, &d_random, 0),
	S_(CK_TLS12_KEY_MAT_PARAMS, pReturnedKeyMaterial, &d_ssl3_key_out, 1),
	U_(CK_TLS12_KEY_MAT_PARAMS, prfHashMechanism),
};
static const GckRpcParamField tls_prf_fields[] = {
	B_(CK_TLS_PRF_PARAMS, pSeed, 1, 0, 0, PH_MECH, 0),
	U_(CK_TLS_PRF_PARAMS, ulSeedLen),
	B_(CK_TLS_PRF_PARAMS, pLabel, 3, 0, 0, PH_MECH, 0),
	U_(CK_TLS_PRF_PARAMS, ulLabelLen),
	OB_(CK_TLS_PRF_PARAMS, pOutput, 5, 0, 0, 0, 1),
	UP_(CK_TLS_PRF_PARAMS, pulOutputLen, PH_MECH, 1),
};
static const GckRpcParamField tls_kdf_fields[] = {
	U_(CK_TLS_KDF_PARAMS, prfMechanism),
	B_(CK_TLS_KDF_PARAMS, pLabel, 2, 0, 0, PH_MECH, 0),
	U_(CK_TLS_KDF_PARAMS, ulLabelLength),
	IS_(CK_TLS_KDF_PARAMS, RandomInfo, &d_random, 0),
	B_(CK_TLS_KDF_PARAMS, pContextData, 5, 0, 0, PH_MECH, 0),
	U_(CK_TLS_KDF_PARAMS, ulContextDataLength),
};
static const GckRpcParamField wtls_master_fields[] = {
	U_(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, DigestMechanism),
	IS_(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, RandomInfo, &d_random, 0),
	OB_(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, pVersion, -1, 0, 1, PH_MECH, 1),
};
static const GckRpcParamField wtls_prf_fields[] = {
	U_(CK_WTLS_PRF_PARAMS, DigestMechanism),
	B_(CK_WTLS_PRF_PARAMS, pSeed, 2, 0, 0, PH_MECH, 0),
	U_(CK_WTLS_PRF_PARAMS, ulSeedLen),
	B_(CK_WTLS_PRF_PARAMS, pLabel, 4, 0, 0, PH_MECH, 0),
	U_(CK_WTLS_PRF_PARAMS, ulLabelLen),
	OB_(CK_WTLS_PRF_PARAMS, pOutput, 6, 0, 0, 0, 1),
	UP_(CK_WTLS_PRF_PARAMS, pulOutputLen, PH_MECH, 1),
};
static const GckRpcParamField wtls_key_out_fields[] = {
	UR_(CK_WTLS_KEY_MAT_OUT, hMacSecret),
	UR_(CK_WTLS_KEY_MAT_OUT, hKey),
	OB_(CK_WTLS_KEY_MAT_OUT, pIV, 3, BITS | PARENT, 0, 0, 1),
};
DESC_(d_wtls_key_out, 0, PH_MECH, CK_WTLS_KEY_MAT_OUT, wtls_key_out_fields);
static const GckRpcParamField wtls_key_mat_fields[] = {
	U_(CK_WTLS_KEY_MAT_PARAMS, DigestMechanism),
	U_(CK_WTLS_KEY_MAT_PARAMS, ulMacSizeInBits),
	U_(CK_WTLS_KEY_MAT_PARAMS, ulKeySizeInBits),
	U_(CK_WTLS_KEY_MAT_PARAMS, ulIVSizeInBits),
	U_(CK_WTLS_KEY_MAT_PARAMS, ulSequenceNumber),
	Z_(CK_WTLS_KEY_MAT_PARAMS, bIsExport),
	IS_(CK_WTLS_KEY_MAT_PARAMS, RandomInfo, &d_random, 0),
	S_(CK_WTLS_KEY_MAT_PARAMS, pReturnedKeyMaterial, &d_wtls_key_out, 1),
};

/* ---- password based ---- */
static const GckRpcParamField pbe_fields[] = {
	OB_(CK_PBE_PARAMS, pInitVector, -1, 0, 8, 0, 1),
	B_(CK_PBE_PARAMS, pPassword, 2, 0, 0, PH_MECH, 0),
	U_(CK_PBE_PARAMS, ulPasswordLen),
	B_(CK_PBE_PARAMS, pSalt, 4, 0, 0, PH_MECH, 0),
	U_(CK_PBE_PARAMS, ulSaltLen),
	U_(CK_PBE_PARAMS, ulIteration),
};
static const GckRpcParamField pbkd2_2_fields[] = {
	U_(CK_PKCS5_PBKD2_PARAMS2, saltSource),
	B_(CK_PKCS5_PBKD2_PARAMS2, pSaltSourceData, 2, 0, 0, PH_MECH, 0),
	U_(CK_PKCS5_PBKD2_PARAMS2, ulSaltSourceDataLen),
	U_(CK_PKCS5_PBKD2_PARAMS2, iterations),
	U_(CK_PKCS5_PBKD2_PARAMS2, prf),
	B_(CK_PKCS5_PBKD2_PARAMS2, pPrfData, 6, 0, 0, PH_MECH, 0),
	U_(CK_PKCS5_PBKD2_PARAMS2, ulPrfDataLen),
	B_(CK_PKCS5_PBKD2_PARAMS2, pPassword, 8, 0, 0, PH_MECH, 0),
	U_(CK_PKCS5_PBKD2_PARAMS2, ulPasswordLen),
};
/* the older structure: the password length is behind a pointer */
static const GckRpcParamField pbkd2_fields[] = {
	U_(CK_PKCS5_PBKD2_PARAMS, saltSource),
	B_(CK_PKCS5_PBKD2_PARAMS, pSaltSourceData, 2, 0, 0, PH_MECH, 0),
	U_(CK_PKCS5_PBKD2_PARAMS, ulSaltSourceDataLen),
	U_(CK_PKCS5_PBKD2_PARAMS, iterations),
	U_(CK_PKCS5_PBKD2_PARAMS, prf),
	B_(CK_PKCS5_PBKD2_PARAMS, pPrfData, 6, 0, 0, PH_MECH, 0),
	U_(CK_PKCS5_PBKD2_PARAMS, ulPrfDataLen),
	B_(CK_PKCS5_PBKD2_PARAMS, pPassword, 8, 0, 0, PH_MECH, 0),
	UP_(CK_PKCS5_PBKD2_PARAMS, ulPasswordLen, PH_MECH, 0),
};

/* ---- SP 800-108 KDFs: arrays of structures, with keys coming back ---- */
static const GckRpcParamField prf_data_fields[] = {
	U_(CK_PRF_DATA_PARAM, type),
	B_(CK_PRF_DATA_PARAM, pValue, 2, 0, 0, PH_MECH, 0),
	U_(CK_PRF_DATA_PARAM, ulValueLen),
};
DESC_(d_prf_data, 0, PH_MECH, CK_PRF_DATA_PARAM, prf_data_fields);
static const GckRpcParamField derived_key_fields[] = {
	AT_(CK_DERIVED_KEY, pTemplate, 1),
	U_(CK_DERIVED_KEY, ulAttributeCount),
	UP_(CK_DERIVED_KEY, phKey, 0, 1),
};
DESC_(d_derived_key, 0, PH_MECH, CK_DERIVED_KEY, derived_key_fields);
static const GckRpcParamField sp800_fields[] = {
	U_(CK_SP800_108_KDF_PARAMS, prfType),
	U_(CK_SP800_108_KDF_PARAMS, ulNumberOfDataParams),
	A_(CK_SP800_108_KDF_PARAMS, pDataParams, 1, &d_prf_data, 0),
	U_(CK_SP800_108_KDF_PARAMS, ulAdditionalDerivedKeys),
	A_(CK_SP800_108_KDF_PARAMS, pAdditionalDerivedKeys, 3, &d_derived_key, 1),
};
static const GckRpcParamField sp800_fb_fields[] = {
	U_(CK_SP800_108_FEEDBACK_KDF_PARAMS, prfType),
	U_(CK_SP800_108_FEEDBACK_KDF_PARAMS, ulNumberOfDataParams),
	A_(CK_SP800_108_FEEDBACK_KDF_PARAMS, pDataParams, 1, &d_prf_data, 0),
	U_(CK_SP800_108_FEEDBACK_KDF_PARAMS, ulIVLen),
	B_(CK_SP800_108_FEEDBACK_KDF_PARAMS, pIV, 3, 0, 0, PH_MECH, 0),
	U_(CK_SP800_108_FEEDBACK_KDF_PARAMS, ulAdditionalDerivedKeys),
	A_(CK_SP800_108_FEEDBACK_KDF_PARAMS, pAdditionalDerivedKeys, 5, &d_derived_key, 1),
};

/* ---- RSA-AES key wrap points at an OAEP parameter structure ---- */
DESC_(d_oaep, 7, PH_MECH, CK_RSA_PKCS_OAEP_PARAMS, oaep_fields);
static const GckRpcParamField rsa_aes_wrap_fields[] = {
	U_(CK_RSA_AES_KEY_WRAP_PARAMS, ulAESKeyBits),
	S_(CK_RSA_AES_KEY_WRAP_PARAMS, pOAEPParams, &d_oaep, 0),
};

DESC_(d_gcm_msg, 1, PH_MSG, CK_GCM_MESSAGE_PARAMS, gcm_msg_fields);
DESC_(d_ccm_msg, 2, PH_MSG, CK_CCM_MESSAGE_PARAMS, ccm_msg_fields);
DESC_(d_chacha_msg, 3, PH_MSG, CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, chacha_msg_fields);
DESC_(d_gcm, 4, PH_MECH, CK_GCM_PARAMS, gcm_fields);
DESC_(d_ccm, 5, PH_MECH, CK_CCM_PARAMS, ccm_fields);
DESC_(d_chacha, 6, PH_MECH, CK_SALSA20_CHACHA20_POLY1305_PARAMS, chacha_fields);
DESC_(d_ecdh1, 8, PH_MECH, CK_ECDH1_DERIVE_PARAMS, ecdh1_fields);
DESC_(d_ecdh_wrap, 9, PH_MECH, CK_ECDH_AES_KEY_WRAP_PARAMS, ecdh_wrap_fields);
DESC_(d_hkdf, 10, PH_MECH, CK_HKDF_PARAMS, hkdf_fields);
DESC_(d_eddsa, 11, PH_MECH, CK_EDDSA_PARAMS, eddsa_fields);
DESC_(d_chacha20, 12, PH_MECH, CK_CHACHA20_PARAMS, chacha20_fields);
DESC_(d_salsa20, 13, PH_MECH, CK_SALSA20_PARAMS, salsa20_fields);
DESC_(d_strdata, 14, PH_MECH, CK_KEY_DERIVATION_STRING_DATA, strdata_fields);
DESC_(d_aes_cbc_data, 15, PH_MECH, CK_AES_CBC_ENCRYPT_DATA_PARAMS, aes_cbc_data_fields);
DESC_(d_des_cbc_data, 16, PH_MECH, CK_DES_CBC_ENCRYPT_DATA_PARAMS, des_cbc_data_fields);
DESC_(d_rsa_aes_wrap, 17, PH_MECH, CK_RSA_AES_KEY_WRAP_PARAMS, rsa_aes_wrap_fields);
DESC_(d_dsa_gen, 18, PH_MECH, CK_DSA_PARAMETER_GEN_PARAM, dsa_gen_fields);
DESC_(d_ike2_prf_plus, 19, PH_MECH, CK_IKE2_PRF_PLUS_DERIVE_PARAMS, ike2_prf_plus_fields);
DESC_(d_ike_prf, 20, PH_MECH, CK_IKE_PRF_DERIVE_PARAMS, ike_prf_fields);
DESC_(d_ike1_prf, 21, PH_MECH, CK_IKE1_PRF_DERIVE_PARAMS, ike1_prf_fields);
DESC_(d_ike1_ext, 22, PH_MECH, CK_IKE1_EXTENDED_DERIVE_PARAMS, ike1_ext_fields);
DESC_(d_x942_dh1, 23, PH_MECH, CK_X9_42_DH1_DERIVE_PARAMS, x942_dh1_fields);
DESC_(d_x942_dh2, 24, PH_MECH, CK_X9_42_DH2_DERIVE_PARAMS, x942_dh2_fields);
DESC_(d_x942_mqv, 25, PH_MECH, CK_X9_42_MQV_DERIVE_PARAMS, x942_mqv_fields);
DESC_(d_ecmqv, 26, PH_MECH, CK_ECMQV_DERIVE_PARAMS, ecmqv_fields);
DESC_(d_kea, 27, PH_MECH, CK_KEA_DERIVE_PARAMS, kea_fields);
DESC_(d_rc5_cbc, 28, PH_MECH, CK_RC5_CBC_PARAMS, rc5_cbc_fields);
DESC_(d_gost_derive, 29, PH_MECH, CK_GOSTR3410_DERIVE_PARAMS, gost_derive_fields);
DESC_(d_gost_wrap, 30, PH_MECH, CK_GOSTR3410_KEY_WRAP_PARAMS, gost_wrap_fields);
DESC_(d_set_oaep, 31, PH_MECH, CK_KEY_WRAP_SET_OAEP_PARAMS, set_oaep_fields);
DESC_(d_otp, 32, PH_MECH, CK_OTP_PARAMS, otp_fields);
DESC_(d_kip, 33, PH_MECH, CK_KIP_PARAMS, kip_fields);
DESC_(d_cms_sig, 34, PH_MECH, CK_CMS_SIG_PARAMS, cms_sig_fields);
DESC_(d_tls_kdf, 35, PH_MECH, CK_TLS_KDF_PARAMS, tls_kdf_fields);
DESC_(d_ssl3_master, 36, PH_MECH, CK_SSL3_MASTER_KEY_DERIVE_PARAMS, ssl3_master_fields);
DESC_(d_tls12_master, 37, PH_MECH, CK_TLS12_MASTER_KEY_DERIVE_PARAMS, tls12_master_fields);
DESC_(d_tls12_ext_master, 38, PH_MECH, CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, tls12_ext_master_fields);
DESC_(d_ssl3_key_mat, 39, PH_MECH, CK_SSL3_KEY_MAT_PARAMS, ssl3_key_mat_fields);
DESC_(d_tls12_key_mat, 40, PH_MECH, CK_TLS12_KEY_MAT_PARAMS, tls12_key_mat_fields);
DESC_(d_tls_prf, 41, PH_MECH, CK_TLS_PRF_PARAMS, tls_prf_fields);
DESC_(d_wtls_master, 42, PH_MECH, CK_WTLS_MASTER_KEY_DERIVE_PARAMS, wtls_master_fields);
DESC_(d_wtls_prf, 43, PH_MECH, CK_WTLS_PRF_PARAMS, wtls_prf_fields);
DESC_(d_wtls_key_mat, 44, PH_MECH, CK_WTLS_KEY_MAT_PARAMS, wtls_key_mat_fields);
DESC_(d_pbe, 45, PH_MECH, CK_PBE_PARAMS, pbe_fields);
DESC_(d_pbkd2_2, 46, PH_MECH, CK_PKCS5_PBKD2_PARAMS2, pbkd2_2_fields);
DESC_(d_pbkd2, 47, PH_MECH, CK_PKCS5_PBKD2_PARAMS, pbkd2_fields);
DESC_(d_sp800, 48, PH_MECH, CK_SP800_108_KDF_PARAMS, sp800_fields);
DESC_(d_sp800_fb, 49, PH_MECH, CK_SP800_108_FEEDBACK_KDF_PARAMS, sp800_fb_fields);

static const GckRpcParamDesc *const all_descs[] = {
	&d_gcm_msg, &d_ccm_msg, &d_chacha_msg, &d_gcm, &d_ccm, &d_chacha,
	&d_oaep, &d_ecdh1, &d_ecdh_wrap, &d_hkdf, &d_eddsa, &d_chacha20,
	&d_salsa20, &d_strdata, &d_aes_cbc_data, &d_des_cbc_data, &d_rsa_aes_wrap,
	&d_dsa_gen, &d_ike2_prf_plus, &d_ike_prf, &d_ike1_prf, &d_ike1_ext,
	&d_x942_dh1, &d_x942_dh2, &d_x942_mqv, &d_ecmqv, &d_kea, &d_rc5_cbc,
	&d_gost_derive, &d_gost_wrap, &d_set_oaep, &d_otp, &d_kip, &d_cms_sig,
	&d_tls_kdf, &d_ssl3_master, &d_tls12_master, &d_tls12_ext_master,
	&d_ssl3_key_mat, &d_tls12_key_mat, &d_tls_prf, &d_wtls_master,
	&d_wtls_prf, &d_wtls_key_mat, &d_pbe, &d_pbkd2_2, &d_pbkd2,
	&d_sp800, &d_sp800_fb,
};

const GckRpcParamDesc *const *gck_rpc_param_descs(size_t *n)
{
	*n = sizeof(all_descs) / sizeof(all_descs[0]);
	return all_descs;
}

const GckRpcParamDesc *gck_rpc_param_desc_for_mechanism(CK_MECHANISM_TYPE mech)
{
	switch (mech) {
	case CKM_AES_GCM:
	case CKM_AES_GMAC:
		return &d_gcm;
	case CKM_AES_CCM:
		return &d_ccm;
	case CKM_CHACHA20_POLY1305:
	case CKM_SALSA20_POLY1305:
		return &d_chacha;
	case CKM_RSA_PKCS_OAEP:
		return &d_oaep;
	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
		return &d_ecdh1;
	case CKM_ECDH_AES_KEY_WRAP:
	case CKM_ECDH_COF_AES_KEY_WRAP:
	case CKM_ECDH_X_AES_KEY_WRAP:
		return &d_ecdh_wrap;
	case CKM_HKDF_DERIVE:
	case CKM_HKDF_DATA:
		return &d_hkdf;
	case CKM_EDDSA:
		return &d_eddsa;
	case CKM_CHACHA20:
		return &d_chacha20;
	case CKM_SALSA20:
		return &d_salsa20;
	case CKM_CONCATENATE_BASE_AND_DATA:
	case CKM_CONCATENATE_DATA_AND_BASE:
	case CKM_XOR_BASE_AND_DATA:
	case CKM_AES_ECB_ENCRYPT_DATA:
	case CKM_DES_ECB_ENCRYPT_DATA:
	case CKM_DES3_ECB_ENCRYPT_DATA:
	case CKM_ARIA_ECB_ENCRYPT_DATA:
	case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
	case CKM_SEED_ECB_ENCRYPT_DATA:
		return &d_strdata;
	case CKM_AES_CBC_ENCRYPT_DATA:
	case CKM_ARIA_CBC_ENCRYPT_DATA:
	case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
	case CKM_SEED_CBC_ENCRYPT_DATA:
		/* the ARIA/Camellia/SEED structures have the same layout */
		return &d_aes_cbc_data;
	case CKM_DES_CBC_ENCRYPT_DATA:
	case CKM_DES3_CBC_ENCRYPT_DATA:
		return &d_des_cbc_data;
	case CKM_RSA_AES_KEY_WRAP:
		return &d_rsa_aes_wrap;
	case CKM_DSA_FIPS_G_GEN:
	case CKM_DSA_PROBABILISTIC_PARAMETER_GEN:
	case CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
		return &d_dsa_gen;
	case CKM_IKE2_PRF_PLUS_DERIVE:
		return &d_ike2_prf_plus;
	case CKM_IKE_PRF_DERIVE:
		return &d_ike_prf;
	case CKM_IKE1_PRF_DERIVE:
		return &d_ike1_prf;
	case CKM_IKE1_EXTENDED_DERIVE:
		return &d_ike1_ext;
	case CKM_X9_42_DH_DERIVE:
		return &d_x942_dh1;
	case CKM_X9_42_DH_HYBRID_DERIVE:
		return &d_x942_dh2;
	case CKM_X9_42_MQV_DERIVE:
		return &d_x942_mqv;
	case CKM_ECMQV_DERIVE:
		return &d_ecmqv;
	case CKM_KEA_DERIVE:
	case CKM_KEA_KEY_DERIVE:
		return &d_kea;
	case CKM_RC5_CBC:
	case CKM_RC5_CBC_PAD:
		return &d_rc5_cbc;
	case CKM_GOSTR3410_DERIVE:
		return &d_gost_derive;
	case CKM_GOSTR3410_KEY_WRAP:
		return &d_gost_wrap;
	case CKM_KEY_WRAP_SET_OAEP:
		return &d_set_oaep;
	case CKM_SECURID:
	case CKM_SECURID_KEY_GEN:
	case CKM_HOTP:
	case CKM_HOTP_KEY_GEN:
	case CKM_ACTI:
	case CKM_ACTI_KEY_GEN:
		return &d_otp;
	case CKM_KIP_DERIVE:
	case CKM_KIP_WRAP:
	case CKM_KIP_MAC:
		return &d_kip;
	case CKM_CMS_SIG:
		return &d_cms_sig;
	case CKM_TLS_KDF:
	case CKM_TLS12_KDF:
		return &d_tls_kdf;
	case CKM_SSL3_MASTER_KEY_DERIVE:
	case CKM_SSL3_MASTER_KEY_DERIVE_DH:
	case CKM_TLS_MASTER_KEY_DERIVE:
	case CKM_TLS_MASTER_KEY_DERIVE_DH:
		return &d_ssl3_master;
	case CKM_TLS12_MASTER_KEY_DERIVE:
	case CKM_TLS12_MASTER_KEY_DERIVE_DH:
		return &d_tls12_master;
	case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:
	case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
		return &d_tls12_ext_master;
	case CKM_SSL3_KEY_AND_MAC_DERIVE:
	case CKM_TLS_KEY_AND_MAC_DERIVE:
		return &d_ssl3_key_mat;
	case CKM_TLS12_KEY_AND_MAC_DERIVE:
	case CKM_TLS12_KEY_SAFE_DERIVE:
		return &d_tls12_key_mat;
	case CKM_TLS_PRF:
		return &d_tls_prf;
	case CKM_WTLS_MASTER_KEY_DERIVE:
	case CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:
		return &d_wtls_master;
	case CKM_WTLS_PRF:
		return &d_wtls_prf;
	case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
	case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
		return &d_wtls_key_mat;
	case CKM_PBE_MD2_DES_CBC:
	case CKM_PBE_MD5_DES_CBC:
	case CKM_PBE_MD5_CAST_CBC:
	case CKM_PBE_MD5_CAST3_CBC:
	case CKM_PBE_MD5_CAST5_CBC:
	case CKM_PBE_SHA1_CAST5_CBC:
	case CKM_PBE_SHA1_RC4_128:
	case CKM_PBE_SHA1_RC4_40:
	case CKM_PBE_SHA1_DES3_EDE_CBC:
	case CKM_PBE_SHA1_DES2_EDE_CBC:
	case CKM_PBE_SHA1_RC2_128_CBC:
	case CKM_PBE_SHA1_RC2_40_CBC:
	case CKM_PBA_SHA1_WITH_SHA1_HMAC:
		return &d_pbe;
	case CKM_PKCS5_PBKD2:
		return &d_pbkd2_2;
	case CKM_SP800_108_COUNTER_KDF:
	case CKM_SP800_108_DOUBLE_PIPELINE_KDF:
		return &d_sp800;
	case CKM_SP800_108_FEEDBACK_KDF:
		return &d_sp800_fb;
	default:
		return NULL;
	}
}

/*
 * CKM_PKCS5_PBKD2 takes CK_PKCS5_PBKD2_PARAMS2, but applications written for
 * the older header pass CK_PKCS5_PBKD2_PARAMS. Both have the same size; the
 * last member is a length in one and a pointer to it in the other. No
 * password is anywhere near 4 KiB, and no pointer is anywhere near that low.
 */
const GckRpcParamDesc *gck_rpc_param_desc_select(CK_MECHANISM_TYPE mech,
						 const void *param, CK_ULONG len)
{
	if (mech == CKM_PKCS5_PBKD2 && param != NULL &&
	    len == sizeof(CK_PKCS5_PBKD2_PARAMS)) {
		CK_ULONG last;

		memcpy(&last, (const char *)param +
		       offsetof(CK_PKCS5_PBKD2_PARAMS2, ulPasswordLen), sizeof(last));
		return last > 4096 ? &d_pbkd2 : &d_pbkd2_2;
	}
	return gck_rpc_param_desc_for_mechanism(mech);
}

/* Is a structure of this kind acceptable for the mechanism? */
static int desc_accepts(CK_MECHANISM_TYPE mech, const GckRpcParamDesc *d)
{
	if (mech == CKM_PKCS5_PBKD2)
		return d == &d_pbkd2 || d == &d_pbkd2_2;
	return d == gck_rpc_param_desc_for_mechanism(mech);
}

/* The message structures differ in size, which tells them apart. */
const GckRpcParamDesc *gck_rpc_param_desc_for_message(CK_ULONG param_len)
{
	int i;

	for (i = 0; i < 3; ++i)
		if (all_descs[i]->size == param_len)
			return all_descs[i];
	return NULL;
}

/* ------------------------------------------------------------------------
 * helpers
 */

static uint64_t get_scalar(const void *base, const GckRpcParamField *f)
{
	if (f->type == GCK_RPC_F_ULONG) {
		CK_ULONG v;

		memcpy(&v, (const char *)base + f->off, sizeof(v));
		return v;
	}
	return *((const unsigned char *)base + f->off);
}

static int is_scalar(int type)
{
	return type == GCK_RPC_F_ULONG || type == GCK_RPC_F_BBOOL ||
	       type == GCK_RPC_F_BYTE;
}

static void *ptr_at(const void *base, const GckRpcParamField *f)
{
	void *p;

	memcpy(&p, (const char *)base + f->off, sizeof(p));
	return p;
}

static void set_ptr(void *base, const GckRpcParamField *f, void *p)
{
	memcpy((char *)base + f->off, &p, sizeof(p));
}

/*
 * Value of the member `f->len_idx` of `d` (or of the enclosing structure for
 * GCK_RPC_LEN_PARENT): a CK_ULONG, or the CK_ULONG a pointer refers to.
 * `ov` optionally holds newer values for members of `d` (reply handling).
 */
struct ctx {
	const GckRpcParamDesc *pd;	/* enclosing structure, if any */
	const void *pbase;
};

static CK_RV len_source(const GckRpcParamDesc *d, const void *base,
			const struct ctx *pc, const GckRpcParamField *f,
			const uint64_t *ov, const unsigned char *ov_set,
			uint64_t *v, int *deref)
{
	const GckRpcParamDesc *sd = d;
	const void *sb = base;
	const GckRpcParamField *sf;

	*deref = 0;
	if (f->flags & GCK_RPC_LEN_PARENT) {
		if (!pc || !pc->pd)
			return CKR_MECHANISM_PARAM_INVALID;
		sd = pc->pd;
		sb = pc->pbase;
		ov = NULL;
	}
	if (f->len_idx < 0 || f->len_idx >= sd->nfields)
		return CKR_MECHANISM_PARAM_INVALID;
	sf = &sd->fields[f->len_idx];
	if (ov && ov_set && ov_set[f->len_idx]) {
		*v = ov[f->len_idx];
		*deref = sf->type == GCK_RPC_F_ULONGPTR;
		return CKR_OK;
	}
	if (is_scalar(sf->type)) {
		*v = get_scalar(sb, sf);
	} else if (sf->type == GCK_RPC_F_ULONGPTR) {
		CK_ULONG *p = ptr_at(sb, sf);

		*v = p ? *p : 0;
		*deref = 1;
	} else {
		return CKR_MECHANISM_PARAM_INVALID;
	}
	return CKR_OK;
}

/* Length in bytes of buffer member i. */
static CK_RV buf_len(const GckRpcParamDesc *d, const void *base,
		     const struct ctx *pc, int i, const uint64_t *ov,
		     const unsigned char *ov_set, size_t *len, int *deref)
{
	const GckRpcParamField *f = &d->fields[i];
	uint64_t v;
	CK_RV rv;

	*deref = 0;
	if (f->len_idx < 0) {
		*len = f->len_fixed;
		return CKR_OK;
	}
	rv = len_source(d, base, pc, f, ov, ov_set, &v, deref);
	if (rv != CKR_OK)
		return rv;
	if (f->flags & GCK_RPC_LEN_BITS) {
		if (v > (uint64_t)GCK_RPC_PARAM_MAX_BUF * 8)
			return CKR_MECHANISM_PARAM_INVALID;
		v = (v + 7) / 8;
	}
	if (v > GCK_RPC_PARAM_MAX_BUF)
		return CKR_MECHANISM_PARAM_INVALID;
	*len = (size_t)v;
	return CKR_OK;
}

/* Number of elements of array / attribute member i. */
static CK_RV elem_count(const GckRpcParamDesc *d, const void *base,
			const struct ctx *pc, int i, size_t *n)
{
	uint64_t v;
	int deref;
	CK_RV rv = len_source(d, base, pc, &d->fields[i], NULL, NULL, &v, &deref);

	if (rv != CKR_OK)
		return rv;
	if (v > ARRAY_MAX)
		return CKR_MECHANISM_PARAM_INVALID;
	*n = (size_t)v;
	return CKR_OK;
}

static void put_be64(unsigned char *p, uint64_t v)
{
	int i;

	for (i = 7; i >= 0; --i)
		*p++ = (unsigned char)(v >> (8 * i));
}

static uint64_t get_be64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 8; ++i)
		v = (v << 8) | p[i];
	return v;
}

/* ------------------------------------------------------------------------
 * output buffer
 */

struct pwr {
	unsigned char *out;
	size_t cap, n;
	int dyn;		/* grow with realloc */
};

static CK_RV pw_put(struct pwr *w, const void *data, size_t len)
{
	if (len > w->cap - w->n) {
		size_t need, cap;
		unsigned char *p;

		if (!w->dyn)
			return CKR_MECHANISM_PARAM_INVALID;
		need = w->n + len;
		if (need > PARAM_MAX_BLOB)
			return CKR_MECHANISM_PARAM_INVALID;
		cap = w->cap ? w->cap : 256;
		while (cap < need)
			cap *= 2;
		p = realloc(w->out, cap);
		if (!p)
			return CKR_HOST_MEMORY;
		w->out = p;
		w->cap = cap;
	}
	if (len)
		memcpy(w->out + w->n, data, len);
	w->n += len;
	return CKR_OK;
}

static CK_RV pw_u8(struct pwr *w, unsigned v)
{
	unsigned char c = (unsigned char)v;

	return pw_put(w, &c, 1);
}

static CK_RV pw_u32(struct pwr *w, uint32_t v)
{
	unsigned char x[4] = { v >> 24, v >> 16, v >> 8, v };

	return pw_put(w, x, 4);
}

static CK_RV pw_u64(struct pwr *w, uint64_t v)
{
	unsigned char x[8];

	put_be64(x, v);
	return pw_put(w, x, 8);
}

/* ------------------------------------------------------------------------
 * encoding (client: the caller's structure -> blob)
 */

static CK_RV mech_enc(const CK_MECHANISM *mech, unsigned char **blob,
		      size_t *n, int depth);

static CK_RV enc_body(const GckRpcParamDesc *d, const void *base,
		      const struct ctx *pc, int phase, struct pwr *w, int depth)
{
	struct ctx here = { d, base };
	size_t len;
	int deref, i;
	CK_RV rv;

	if (depth >= GCK_RPC_PARAM_MAX_DEPTH)
		return CKR_MECHANISM_PARAM_INVALID;

	/* 1. scalars and pointers to a CK_ULONG */
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];

		if (is_scalar(f->type)) {
			if ((rv = pw_u64(w, get_scalar(base, f))) != CKR_OK)
				return rv;
		} else if (f->type == GCK_RPC_F_ULONGPTR) {
			CK_ULONG *p = ptr_at(base, f);

			if ((rv = pw_u8(w, p != NULL)) != CKR_OK)
				return rv;
			if (p && (f->req & phase) && (rv = pw_u64(w, *p)) != CKR_OK)
				return rv;
		}
	}
	/* 2. the rest, in order */
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		void *p;

		switch (f->type) {
		case GCK_RPC_F_BUF:
		case GCK_RPC_F_OBUF:
			p = ptr_at(base, f);
			if ((rv = buf_len(d, base, pc, i, NULL, NULL, &len, &deref)) != CKR_OK)
				return rv;
			if (f->type == GCK_RPC_F_OBUF) {
				if ((rv = pw_u8(w, p != NULL)) != CKR_OK)
					return rv;
				if (!p)
					break;
			}
			if (!(f->req & phase))
				break;
			if (len && !p)
				return CKR_MECHANISM_PARAM_INVALID;
			if ((rv = pw_put(w, p, len)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_INLINE:
			if ((f->req & phase) &&
			    (rv = pw_put(w, (const char *)base + f->off, f->len_fixed)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_STRUCT:
			p = ptr_at(base, f);
			if ((rv = pw_u8(w, p != NULL)) != CKR_OK)
				return rv;
			if (p && (rv = enc_body(f->sub, p, &here, phase, w, depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ISTRUCT:
			if ((rv = enc_body(f->sub, (const char *)base + f->off, &here,
					   phase, w, depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ARRAY: {
			size_t n, k;

			p = ptr_at(base, f);
			if ((rv = elem_count(d, base, pc, i, &n)) != CKR_OK)
				return rv;
			if (n && !p)
				return CKR_MECHANISM_PARAM_INVALID;
			for (k = 0; k < n; ++k)
				if ((rv = enc_body(f->sub, (const char *)p + k * f->sub->size,
						   &here, phase, w, depth + 1)) != CKR_OK)
					return rv;
			break;
		}
		case GCK_RPC_F_ATTRS: {
			size_t n;
			GckRpcTplBuf tb;

			p = ptr_at(base, f);
			if ((rv = elem_count(d, base, pc, i, &n)) != CKR_OK)
				return rv;
			if (n && !p)
				return CKR_MECHANISM_PARAM_INVALID;
			if (!n)
				break;
			if (!gck_rpc_template_encode(&tb, p, n, 0))
				return CKR_MECHANISM_PARAM_INVALID;
			rv = pw_u32(w, (uint32_t)tb.len);
			if (rv == CKR_OK)
				rv = pw_put(w, tb.p, tb.len);
			free(tb.p);
			if (rv != CKR_OK)
				return rv;
			break;
		}
		case GCK_RPC_F_CSTR:
			p = ptr_at(base, f);
			if ((rv = pw_u8(w, p != NULL)) != CKR_OK)
				return rv;
			if (p) {
				len = strnlen(p, CSTR_MAX + 1);
				if (len > CSTR_MAX)
					return CKR_MECHANISM_PARAM_INVALID;
				if ((rv = pw_u32(w, (uint32_t)len)) != CKR_OK ||
				    (rv = pw_put(w, p, len)) != CKR_OK)
					return rv;
			}
			break;
		case GCK_RPC_F_MECHPTR: {
			const CK_MECHANISM *m = ptr_at(base, f);
			unsigned char *pb = NULL;
			size_t pn = 0;

			if ((rv = pw_u8(w, m != NULL)) != CKR_OK)
				return rv;
			if (!m)
				break;
			if ((rv = mech_enc(m, &pb, &pn, depth + 1)) != CKR_OK)
				return rv;
			rv = pw_u64(w, m->mechanism);
			if (rv == CKR_OK)
				rv = pw_u32(w, (uint32_t)pn);
			if (rv == CKR_OK)
				rv = pw_put(w, pb, pn);
			free(pb);
			if (rv != CKR_OK)
				return rv;
			break;
		}
		}
	}
	return CKR_OK;
}

CK_RV gck_rpc_param_encode(const GckRpcParamDesc *d, const void *param,
			   int phase, unsigned char *out, size_t cap,
			   size_t *out_len)
{
	struct pwr w = { out, cap, 0, 0 };
	size_t len;
	int deref, i;
	CK_RV rv;

	if (!d || !param || !(d->phases & phase))
		return CKR_MECHANISM_PARAM_INVALID;
	if ((rv = pw_u8(&w, d->kind)) != CKR_OK)
		return rv;
	if ((rv = enc_body(d, param, NULL, phase, &w, 0)) != CKR_OK)
		return rv;

	if (phase == GCK_RPC_PHASE_ENC) {
		/* The returned IV/nonce and tag must fit a blob of this size */
		size_t resp = 0;

		for (i = 0; i < d->nfields; ++i) {
			if (d->fields[i].type != GCK_RPC_F_BUF || !d->fields[i].resp)
				continue;
			if ((rv = buf_len(d, param, NULL, i, NULL, NULL, &len, &deref)) != CKR_OK)
				return rv;
			resp += len;
		}
		if (resp > cap)
			return CKR_MECHANISM_PARAM_INVALID;
	}
	*out_len = w.n;
	return CKR_OK;
}

CK_RV gck_rpc_param_encode_alloc(const GckRpcParamDesc *d, const void *param,
				 int phase, unsigned char **out, size_t *out_len)
{
	struct pwr w = { NULL, 0, 0, 1 };
	CK_RV rv;

	*out = NULL;
	*out_len = 0;
	if (!d || !param || !(d->phases & phase))
		return CKR_MECHANISM_PARAM_INVALID;
	if ((rv = pw_u8(&w, d->kind)) == CKR_OK)
		rv = enc_body(d, param, NULL, phase, &w, 0);
	if (rv != CKR_OK) {
		free(w.out);
		return rv;
	}
	*out = w.out;
	*out_len = w.n;
	return CKR_OK;
}

/* ------------------------------------------------------------------------
 * decoding (daemon: blob -> a structure in the daemon's own memory)
 */

struct prd {
	const unsigned char *p;
	size_t n, pos;
	void *(*alloc)(void *, size_t);
	void *ctx;
	size_t allocated;
};

static void *pr_alloc0(struct prd *r, size_t n)
{
	void *m;

	if (n > PARAM_MAX_ALLOC - r->allocated)
		return NULL;
	r->allocated += n;
	m = r->alloc(r->ctx, n ? n : 1);
	if (m)
		memset(m, 0, n ? n : 1);
	return m;
}

static int pr_get(struct prd *r, void *out, size_t n)
{
	if (n > r->n - r->pos)
		return 0;
	if (out)
		memcpy(out, r->p + r->pos, n);
	r->pos += n;
	return 1;
}

static int pr_u8(struct prd *r, unsigned char *v)
{
	return pr_get(r, v, 1);
}

static int pr_u32(struct prd *r, uint32_t *v)
{
	unsigned char x[4];

	if (!pr_get(r, x, 4))
		return 0;
	*v = (uint32_t)x[0] << 24 | (uint32_t)x[1] << 16 | (uint32_t)x[2] << 8 | x[3];
	return 1;
}

static int pr_u64(struct prd *r, uint64_t *v)
{
	unsigned char x[8];

	if (!pr_get(r, x, 8))
		return 0;
	*v = get_be64(x);
	return 1;
}

static void set_scalar(void *base, const GckRpcParamField *f, uint64_t v)
{
	if (f->type == GCK_RPC_F_ULONG) {
		CK_ULONG u = (CK_ULONG)v;

		memcpy((char *)base + f->off, &u, sizeof(u));
	} else if (f->type == GCK_RPC_F_BBOOL) {
		*((unsigned char *)base + f->off) = v ? 1 : 0;
	} else {
		*((unsigned char *)base + f->off) = (unsigned char)v;
	}
}

static CK_RV mech_dec(CK_MECHANISM_TYPE type, const unsigned char *blob, size_t n,
		      void *(*alloc)(void *, size_t), void *actx,
		      CK_MECHANISM_PTR out, GckRpcParamState *st, int depth,
		      size_t *allocated);

/* `lens` (top level only) records each buffer's capacity */
static CK_RV dec_body(const GckRpcParamDesc *d, int phase, struct prd *r,
		      void *base, const struct ctx *pc, size_t *lens, int depth)
{
	struct ctx here = { d, base };
	size_t len;
	int deref, i;
	CK_RV rv;

	if (depth >= GCK_RPC_PARAM_MAX_DEPTH || d->nfields > GCK_RPC_PARAM_MAX_FIELDS)
		return CKR_MECHANISM_PARAM_INVALID;

	/* 1. scalars and pointers to a CK_ULONG */
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		uint64_t v;

		if (is_scalar(f->type)) {
			if (!pr_u64(r, &v))
				return CKR_MECHANISM_PARAM_INVALID;
			if (f->type == GCK_RPC_F_ULONG && (uint64_t)(CK_ULONG)v != v)
				return CKR_MECHANISM_PARAM_INVALID;
			set_scalar(base, f, v);
		} else if (f->type == GCK_RPC_F_ULONGPTR) {
			unsigned char present;
			CK_ULONG *p;

			if (!pr_u8(r, &present) || present > 1)
				return CKR_MECHANISM_PARAM_INVALID;
			if (!present)
				continue;
			p = pr_alloc0(r, sizeof(CK_ULONG));
			if (!p)
				return CKR_DEVICE_MEMORY;
			if (f->req & phase) {
				if (!pr_u64(r, &v) || (uint64_t)(CK_ULONG)v != v)
					return CKR_MECHANISM_PARAM_INVALID;
				*p = (CK_ULONG)v;
			}
			set_ptr(base, f, p);
		}
	}
	/* 2. the rest, in order */
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		unsigned char present;

		switch (f->type) {
		case GCK_RPC_F_BUF:
		case GCK_RPC_F_OBUF: {
			unsigned char *mem;

			if ((rv = buf_len(d, base, pc, i, NULL, NULL, &len, &deref)) != CKR_OK)
				return rv;
			if (lens)
				lens[i] = len;
			if (f->type == GCK_RPC_F_OBUF) {
				if (!pr_u8(r, &present) || present > 1)
					return CKR_MECHANISM_PARAM_INVALID;
				if (!present)
					break;
			}
			/* every buffer gets private, writable backing */
			mem = (len || f->type == GCK_RPC_F_OBUF) ? pr_alloc0(r, len) : NULL;
			if ((len || f->type == GCK_RPC_F_OBUF) && !mem)
				return CKR_DEVICE_MEMORY;
			if ((f->req & phase) && !pr_get(r, mem, len))
				return CKR_MECHANISM_PARAM_INVALID;
			set_ptr(base, f, mem);
			break;
		}
		case GCK_RPC_F_INLINE:
			if ((f->req & phase) &&
			    !pr_get(r, (char *)base + f->off, f->len_fixed))
				return CKR_MECHANISM_PARAM_INVALID;
			break;
		case GCK_RPC_F_STRUCT: {
			void *sub;

			if (!pr_u8(r, &present) || present > 1)
				return CKR_MECHANISM_PARAM_INVALID;
			if (!present)
				break;
			sub = pr_alloc0(r, f->sub->size);
			if (!sub)
				return CKR_DEVICE_MEMORY;
			if ((rv = dec_body(f->sub, phase, r, sub, &here, NULL, depth + 1)) != CKR_OK)
				return rv;
			set_ptr(base, f, sub);
			break;
		}
		case GCK_RPC_F_ISTRUCT:
			if ((rv = dec_body(f->sub, phase, r, (char *)base + f->off, &here,
					   NULL, depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ARRAY: {
			size_t n, k;
			char *arr;

			if ((rv = elem_count(d, base, pc, i, &n)) != CKR_OK)
				return rv;
			if (!n)
				break;
			arr = pr_alloc0(r, n * f->sub->size);
			if (!arr)
				return CKR_DEVICE_MEMORY;
			for (k = 0; k < n; ++k)
				if ((rv = dec_body(f->sub, phase, r, arr + k * f->sub->size,
						   &here, NULL, depth + 1)) != CKR_OK)
					return rv;
			set_ptr(base, f, arr);
			break;
		}
		case GCK_RPC_F_ATTRS: {
			size_t n;
			uint32_t tl;
			CK_ATTRIBUTE_PTR attrs;
			CK_ULONG na;

			if ((rv = elem_count(d, base, pc, i, &n)) != CKR_OK)
				return rv;
			if (!n)
				break;
			if (!pr_u32(r, &tl) || tl > r->n - r->pos)
				return CKR_MECHANISM_PARAM_INVALID;
			rv = gck_rpc_template_decode(r->p + r->pos, tl, 0, r->alloc, r->ctx,
						     &attrs, &na);
			if (rv != CKR_OK)
				return CKR_MECHANISM_PARAM_INVALID;
			if (na != n)
				return CKR_MECHANISM_PARAM_INVALID;
			r->pos += tl;
			r->allocated += tl + n * sizeof(CK_ATTRIBUTE);
			if (r->allocated > PARAM_MAX_ALLOC)
				return CKR_DEVICE_MEMORY;
			set_ptr(base, f, attrs);
			break;
		}
		case GCK_RPC_F_CSTR: {
			uint32_t sl;
			char *s;

			if (!pr_u8(r, &present) || present > 1)
				return CKR_MECHANISM_PARAM_INVALID;
			if (!present)
				break;
			if (!pr_u32(r, &sl) || sl > CSTR_MAX || sl > r->n - r->pos)
				return CKR_MECHANISM_PARAM_INVALID;
			s = pr_alloc0(r, (size_t)sl + 1);
			if (!s)
				return CKR_DEVICE_MEMORY;
			pr_get(r, s, sl);
			set_ptr(base, f, s);
			break;
		}
		case GCK_RPC_F_MECHPTR: {
			CK_MECHANISM_PTR m;
			GckRpcParamState *nst;
			uint64_t type;
			uint32_t pl;

			if (!pr_u8(r, &present) || present > 1)
				return CKR_MECHANISM_PARAM_INVALID;
			if (!present)
				break;
			if (!pr_u64(r, &type) || !pr_u32(r, &pl) || pl > r->n - r->pos)
				return CKR_MECHANISM_PARAM_INVALID;
			m = pr_alloc0(r, sizeof(*m));
			nst = pr_alloc0(r, sizeof(*nst));
			if (!m || !nst)
				return CKR_DEVICE_MEMORY;
			rv = mech_dec((CK_MECHANISM_TYPE)type, r->p + r->pos, pl,
				      r->alloc, r->ctx, m, nst, depth + 1, &r->allocated);
			if (rv != CKR_OK)
				return rv;
			r->pos += pl;
			set_ptr(base, f, m);
			break;
		}
		}
	}
	return CKR_OK;
}

static CK_RV param_decode(const unsigned char *blob, size_t n, int phase,
			  GckRpcParamState *st, void *(*alloc)(void *, size_t),
			  void *ctx, int depth, size_t *allocated)
{
	const GckRpcParamDesc *d = NULL;
	struct prd r = { blob, n, 1, alloc, ctx, allocated ? *allocated : 0 };
	CK_RV rv;
	size_t i;

	memset(st, 0, sizeof(*st));
	if (n < 1)
		return CKR_MECHANISM_PARAM_INVALID;
	for (i = 0; i < sizeof(all_descs) / sizeof(all_descs[0]); ++i)
		if (all_descs[i]->kind == blob[0])
			d = all_descs[i];
	if (!d || !(d->phases & phase) || d->size > sizeof(st->s))
		return CKR_MECHANISM_PARAM_INVALID;

	rv = dec_body(d, phase, &r, &st->s, NULL, st->lens, depth);
	if (rv != CKR_OK)
		return rv;
	if (r.pos != n)
		return CKR_MECHANISM_PARAM_INVALID;
	if (allocated)
		*allocated = r.allocated;
	st->desc = d;
	return CKR_OK;
}

CK_RV gck_rpc_param_decode(const unsigned char *blob, size_t n, int phase,
			   GckRpcParamState *st,
			   void *(*alloc)(void *, size_t), void *ctx)
{
	return param_decode(blob, n, phase, st, alloc, ctx, 0, NULL);
}

/* ------------------------------------------------------------------------
 * replies: what the module wrote into the structure
 */

static CK_RV resp_enc(const GckRpcParamDesc *d, const void *base,
		      const struct ctx *pc, const size_t *caps, struct pwr *w,
		      int depth)
{
	struct ctx here = { d, base };
	size_t len;
	int deref, i;
	CK_RV rv;

	if (depth >= GCK_RPC_PARAM_MAX_DEPTH)
		return CKR_MECHANISM_PARAM_INVALID;

	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];

		if (!f->resp)
			continue;
		if (is_scalar(f->type)) {
			if ((rv = pw_u64(w, get_scalar(base, f))) != CKR_OK)
				return rv;
		} else if (f->type == GCK_RPC_F_ULONGPTR) {
			CK_ULONG *p = ptr_at(base, f);

			if (p && (rv = pw_u64(w, *p)) != CKR_OK)
				return rv;
		}
	}
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		void *p;

		if (!f->resp)
			continue;
		switch (f->type) {
		case GCK_RPC_F_BUF:
		case GCK_RPC_F_OBUF:
			p = ptr_at(base, f);
			if (!p)
				break;
			if ((rv = buf_len(d, base, pc, i, NULL, NULL, &len, &deref)) != CKR_OK)
				return rv;
			if (caps && caps[i] < len)
				return CKR_DEVICE_ERROR;	/* the module overran its buffer */
			if ((rv = pw_put(w, p, len)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_STRUCT:
			p = ptr_at(base, f);
			if (p && (rv = resp_enc(f->sub, p, &here, NULL, w, depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ISTRUCT:
			if ((rv = resp_enc(f->sub, (const char *)base + f->off, &here, NULL,
					   w, depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ARRAY: {
			size_t n, k;

			p = ptr_at(base, f);
			if ((rv = elem_count(d, base, pc, i, &n)) != CKR_OK)
				return rv;
			for (k = 0; p && k < n; ++k)
				if ((rv = resp_enc(f->sub, (const char *)p + k * f->sub->size,
						   &here, NULL, w, depth + 1)) != CKR_OK)
					return rv;
			break;
		}
		}
	}
	return CKR_OK;
}

CK_RV gck_rpc_param_resp_encode(const GckRpcParamState *st, unsigned char *out,
				size_t cap, size_t *out_len)
{
	struct pwr w = { out, cap, 0, 0 };
	CK_RV rv;

	if (st->desc == NULL) {
		*out_len = 0;
		return CKR_OK;
	}
	rv = resp_enc(st->desc, &st->s, NULL, st->lens, &w, 0);
	if (rv != CKR_OK)
		return rv;
	*out_len = w.n;
	return CKR_OK;
}

CK_RV gck_rpc_param_resp_encode_alloc(const GckRpcParamState *st,
				      unsigned char **out, size_t *out_len)
{
	struct pwr w = { NULL, 0, 0, 1 };
	CK_RV rv;

	*out = NULL;
	*out_len = 0;
	if (st->desc == NULL)
		return CKR_OK;
	rv = resp_enc(st->desc, &st->s, NULL, st->lens, &w, 0);
	if (rv != CKR_OK) {
		free(w.out);
		return rv;
	}
	*out = w.out;
	*out_len = w.n;
	return CKR_OK;
}

struct rrd {
	const unsigned char *p;
	size_t n, pos;
	int dry;
};

static CK_RV resp_app(const GckRpcParamDesc *d, void *base, const struct ctx *pc,
		      struct rrd *r, int depth)
{
	struct ctx here = { d, base };
	uint64_t newv[GCK_RPC_PARAM_MAX_FIELDS], oldv[GCK_RPC_PARAM_MAX_FIELDS];
	unsigned char set[GCK_RPC_PARAM_MAX_FIELDS];
	size_t len;
	int deref, i;
	CK_RV rv;

	if (depth >= GCK_RPC_PARAM_MAX_DEPTH || d->nfields > GCK_RPC_PARAM_MAX_FIELDS)
		return CKR_DEVICE_ERROR;
	memset(set, 0, sizeof(set));

	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];

		if (!f->resp)
			continue;
		if (is_scalar(f->type)) {
			if (r->n - r->pos < 8)
				return CKR_DEVICE_ERROR;
			newv[i] = get_be64(r->p + r->pos);
			r->pos += 8;
			set[i] = 1;
			if (f->type == GCK_RPC_F_ULONG && (uint64_t)(CK_ULONG)newv[i] != newv[i])
				return CKR_DEVICE_ERROR;
			if (!r->dry)
				set_scalar(base, f, newv[i]);
		} else if (f->type == GCK_RPC_F_ULONGPTR) {
			CK_ULONG *p = ptr_at(base, f);

			if (!p)
				continue;
			if (r->n - r->pos < 8)
				return CKR_DEVICE_ERROR;
			newv[i] = get_be64(r->p + r->pos);
			r->pos += 8;
			if ((uint64_t)(CK_ULONG)newv[i] != newv[i])
				return CKR_DEVICE_ERROR;
			oldv[i] = *p;
			set[i] = 1;
			if (!r->dry)
				*p = (CK_ULONG)newv[i];
		}
	}
	for (i = 0; i < d->nfields; ++i) {
		const GckRpcParamField *f = &d->fields[i];
		void *p;

		if (!f->resp)
			continue;
		switch (f->type) {
		case GCK_RPC_F_BUF:
		case GCK_RPC_F_OBUF: {
			size_t cap;
			int src_ptr;

			p = ptr_at(base, f);
			if (!p)
				break;
			rv = buf_len(d, base, pc, i, newv, set, &len, &deref);
			if (rv != CKR_OK)
				return CKR_DEVICE_ERROR;
			/* the room the caller gave: the old value of a length
			 * the module updated, else the length itself */
			src_ptr = f->len_idx >= 0 && !(f->flags & GCK_RPC_LEN_PARENT) &&
				  d->fields[f->len_idx].type == GCK_RPC_F_ULONGPTR &&
				  set[f->len_idx];
			cap = src_ptr ? (size_t)oldv[f->len_idx] : len;
			if (len > cap || len > r->n - r->pos)
				return CKR_DEVICE_ERROR;
			if (!r->dry && len)
				memcpy(p, r->p + r->pos, len);
			r->pos += len;
			break;
		}
		case GCK_RPC_F_STRUCT:
			p = ptr_at(base, f);
			if (p && (rv = resp_app(f->sub, p, &here, r, depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ISTRUCT:
			if ((rv = resp_app(f->sub, (char *)base + f->off, &here, r,
					   depth + 1)) != CKR_OK)
				return rv;
			break;
		case GCK_RPC_F_ARRAY: {
			size_t n, k;

			p = ptr_at(base, f);
			if (elem_count(d, base, pc, i, &n) != CKR_OK)
				return CKR_DEVICE_ERROR;
			for (k = 0; p && k < n; ++k)
				if ((rv = resp_app(f->sub, (char *)p + k * f->sub->size,
						   &here, r, depth + 1)) != CKR_OK)
					return rv;
			break;
		}
		}
	}
	return CKR_OK;
}

CK_RV gck_rpc_param_resp_apply(const GckRpcParamDesc *d, void *param,
			       const unsigned char *blob, size_t n)
{
	struct rrd r = { blob, n, 0, 1 };
	CK_RV rv;

	if (!d)
		return n == 0 ? CKR_OK : CKR_DEVICE_ERROR;
	/* check the whole blob first, so a bad one leaves the caller's
	 * structure untouched */
	rv = resp_app(d, param, NULL, &r, 0);
	if (rv != CKR_OK || r.pos != n)
		return CKR_DEVICE_ERROR;
	r.pos = 0;
	r.dry = 0;
	rv = resp_app(d, param, NULL, &r, 0);
	return rv;
}

/* ------------------------------------------------------------------------
 * whole mechanism parameters
 */

#ifdef CKM_ML_DSA
/* the optional additional context of ML-DSA/SLH-DSA */
static CK_RV ctx_enc(const CK_MECHANISM *mech, unsigned char **blob, size_t *n)
{
	int hashed = gck_rpc_mechanism_context_kind(mech->mechanism) ==
		     GCK_RPC_CONTEXT_HASH_SIGN;
	size_t expect = hashed ? sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT) :
				 sizeof(CK_SIGN_ADDITIONAL_CONTEXT);
	CK_ULONG hedge, ctx_len;
	CK_MECHANISM_TYPE hash = 0;
	CK_BYTE_PTR ctx;
	unsigned char *b;
	size_t off = 0;
	int i;

	if (mech->pParameter == NULL && mech->ulParameterLen == 0)
		return CKR_OK;		/* no context: an empty parameter */
	if (mech->pParameter == NULL || mech->ulParameterLen != expect)
		return CKR_MECHANISM_PARAM_INVALID;
	if (hashed) {
		const CK_HASH_SIGN_ADDITIONAL_CONTEXT *p = mech->pParameter;

		hedge = p->hedgeVariant; hash = p->hash;
		ctx = p->pContext; ctx_len = p->ulContextLen;
	} else {
		const CK_SIGN_ADDITIONAL_CONTEXT *p = mech->pParameter;

		hedge = p->hedgeVariant;
		ctx = p->pContext; ctx_len = p->ulContextLen;
	}
	if (ctx_len > GCK_RPC_CONTEXT_MAX_LEN || (ctx_len != 0 && ctx == NULL))
		return CKR_MECHANISM_PARAM_INVALID;
	b = malloc(16 + ctx_len);
	if (!b)
		return CKR_HOST_MEMORY;
	for (i = 7; i >= 0; --i)
		b[off++] = (unsigned char)((uint64_t)hedge >> (8 * i));
	if (hashed)
		for (i = 7; i >= 0; --i)
			b[off++] = (unsigned char)((uint64_t)hash >> (8 * i));
	if (ctx_len)
		memcpy(b + off, ctx, ctx_len);
	*blob = b;
	*n = off + ctx_len;
	return CKR_OK;
}

static CK_RV ctx_dec(CK_MECHANISM_TYPE type, const unsigned char *p, size_t n,
		     void *(*alloc)(void *, size_t), void *actx,
		     CK_MECHANISM_PTR out)
{
	int kind = gck_rpc_mechanism_context_kind(type);
	size_t hdr = (kind == GCK_RPC_CONTEXT_HASH_SIGN) ? 16 : 8, i, ctx_len;
	uint64_t hedge = 0, hash = 0;
	CK_BYTE_PTR ctx = NULL;

	out->pParameter = NULL;
	out->ulParameterLen = 0;
	if (n == 0)
		return CKR_OK;
	if (n < hdr || n - hdr > GCK_RPC_CONTEXT_MAX_LEN)
		return CKR_MECHANISM_PARAM_INVALID;
	ctx_len = n - hdr;
	for (i = 0; i < 8; ++i)
		hedge = (hedge << 8) | p[i];
	if (kind == GCK_RPC_CONTEXT_HASH_SIGN)
		for (i = 8; i < 16; ++i)
			hash = (hash << 8) | p[i];
	if (ctx_len) {
		ctx = alloc(actx, ctx_len);
		if (!ctx)
			return CKR_DEVICE_MEMORY;
		memcpy(ctx, p + hdr, ctx_len);
	}
	if (kind == GCK_RPC_CONTEXT_HASH_SIGN) {
		CK_HASH_SIGN_ADDITIONAL_CONTEXT *c = alloc(actx, sizeof(*c));

		if (!c)
			return CKR_DEVICE_MEMORY;
		c->hedgeVariant = hedge; c->pContext = ctx;
		c->ulContextLen = ctx_len; c->hash = hash;
		out->pParameter = c;
		out->ulParameterLen = sizeof(*c);
	} else {
		CK_SIGN_ADDITIONAL_CONTEXT *c = alloc(actx, sizeof(*c));

		if (!c)
			return CKR_DEVICE_MEMORY;
		c->hedgeVariant = hedge; c->pContext = ctx; c->ulContextLen = ctx_len;
		out->pParameter = c;
		out->ulParameterLen = sizeof(*c);
	}
	return CKR_OK;
}
#endif

static CK_RV mech_enc(const CK_MECHANISM *mech, unsigned char **blob,
		      size_t *n, int depth)
{
	CK_MECHANISM_TYPE type = mech->mechanism;
	const GckRpcParamDesc *d;
	CK_RV rv;

	*blob = NULL;
	*n = 0;
	if (depth >= GCK_RPC_PARAM_MAX_DEPTH)
		return CKR_MECHANISM_PARAM_INVALID;
	if (!gck_rpc_mechanism_is_supported(type))
		return CKR_MECHANISM_INVALID;

	if (gck_rpc_mechanism_has_no_parameters(type))
		return CKR_OK;

	if (gck_rpc_mechanism_has_sane_parameters(type)) {
		if ((mech->pParameter == NULL && mech->ulParameterLen != 0) ||
		    !gck_rpc_mechanism_flat_param_len_ok(type, mech->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;
		if (mech->ulParameterLen) {
			*blob = malloc(mech->ulParameterLen);
			if (!*blob)
				return CKR_HOST_MEMORY;
			memcpy(*blob, mech->pParameter, mech->ulParameterLen);
			*n = mech->ulParameterLen;
		}
		return CKR_OK;
	}
#ifdef CKM_ML_DSA
	if (gck_rpc_mechanism_context_kind(type))
		return ctx_enc(mech, blob, n);
#endif
	if (mech->pParameter == NULL && mech->ulParameterLen == 0)
		return CKR_OK;		/* message-mode mechanisms, pure EdDSA, ... */
	d = gck_rpc_param_desc_select(type, mech->pParameter, mech->ulParameterLen);
	if (!d || mech->pParameter == NULL || mech->ulParameterLen != d->size)
		return CKR_MECHANISM_PARAM_INVALID;
	rv = gck_rpc_param_encode_alloc(d, mech->pParameter, GCK_RPC_PHASE_MECH,
					blob, n);
	return rv;
}

CK_RV gck_rpc_mech_param_encode(const CK_MECHANISM *mech, unsigned char **blob,
				size_t *n)
{
	return mech_enc(mech, blob, n, 0);
}

static CK_RV mech_dec(CK_MECHANISM_TYPE type, const unsigned char *blob, size_t n,
		      void *(*alloc)(void *, size_t), void *actx,
		      CK_MECHANISM_PTR out, GckRpcParamState *st, int depth,
		      size_t *allocated)
{
	CK_RV rv;

	out->mechanism = type;
	out->pParameter = NULL;
	out->ulParameterLen = 0;
	memset(st, 0, sizeof(*st));
	if (depth >= GCK_RPC_PARAM_MAX_DEPTH)
		return CKR_MECHANISM_PARAM_INVALID;

	/*
	 * The daemon is the trust boundary: it must not rely on the client
	 * library having filtered mechanisms or parameters. The parameter is
	 * never passed on as the client's raw bytes unless it is a flat
	 * structure of the exact expected size.
	 */
	if (!gck_rpc_mechanism_is_supported(type))
		return CKR_MECHANISM_INVALID;
	if (gck_rpc_mechanism_has_no_parameters(type))
		return CKR_OK;
	if (gck_rpc_mechanism_has_sane_parameters(type)) {
		void *copy;

		if (!gck_rpc_mechanism_flat_param_len_ok(type, n))
			return CKR_MECHANISM_PARAM_INVALID;
		if (n == 0)
			return CKR_OK;
		copy = alloc(actx, n);		/* aligned, private copy */
		if (copy == NULL)
			return CKR_DEVICE_MEMORY;
		memcpy(copy, blob, n);
		out->pParameter = copy;
		out->ulParameterLen = n;
		return CKR_OK;
	}
#ifdef CKM_ML_DSA
	if (gck_rpc_mechanism_context_kind(type))
		return ctx_dec(type, blob, n, alloc, actx, out);
#endif
	if (n == 0)
		return CKR_OK;
	rv = param_decode(blob, n, GCK_RPC_PHASE_MECH, st, alloc, actx, depth, allocated);
	if (rv != CKR_OK)
		return rv;
	if (!desc_accepts(type, st->desc))
		return CKR_MECHANISM_PARAM_INVALID;
	out->pParameter = &st->s;
	out->ulParameterLen = st->desc->size;
	return CKR_OK;
}

CK_RV gck_rpc_mech_param_decode(CK_MECHANISM_TYPE type, const unsigned char *blob,
				size_t n, void *(*alloc)(void *, size_t),
				void *ctx, CK_MECHANISM_PTR out,
				GckRpcParamState *st)
{
	size_t allocated = 0;

	return mech_dec(type, blob, n, alloc, ctx, out, st, 0, &allocated);
}

/* Apply a reply blob to the caller's mechanism parameter. */
CK_RV gck_rpc_mech_param_apply_resp(const CK_MECHANISM *mech,
				    const unsigned char *blob, size_t n)
{
	const GckRpcParamDesc *d;

	if (!mech->pParameter)
		return n == 0 ? CKR_OK : CKR_DEVICE_ERROR;
	d = gck_rpc_param_desc_select(mech->mechanism, mech->pParameter,
				      mech->ulParameterLen);
	return gck_rpc_param_resp_apply(d, mech->pParameter, blob, n);
}

#endif /* GCK_RPC_HAVE_V32 */
