/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <TEEencrypt_ta.h>

#define MAX 86
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
int rootkey;
struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key);
TEE_Result check_params(uint32_t param_types);
TEE_Result RSA_create_key_pair(void *session);
TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4]);

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{   
	struct rsa_session *sess;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*sess_ctx = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *sess_ctx);

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		//EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}
TEE_Result check_params(uint32_t param_types) {	//when RSA
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nData to encrypt: %s\n", (char*)plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	//TEE_FreeOperation(sess->key_handle);
	return ret;
}

TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	void *plain_txt = params[1].memref.buffer;
	size_t plain_len = params[1].memref.size;
	void *cipher = params[0].memref.buffer;
	size_t cipher_len = params[0].memref.size;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("\n========== Preparing decryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char *) cipher);
	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
				cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char *) plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	//TEE_FreeTransientObject(sess->key_handle);
	return ret;
}

static TEE_Result enc_value(TEE_Param params[4])
{
	char* plain = (char*)params[0].memref.buffer;
	int plain_len = strlen(params[0].memref.buffer);
	char encrypted[MAX] = {0,};
	int key = 0;
	void* key_ptr = &key;

	DMSG("**Encryption**\n");
	DMSG("Plaintext : %s, Length: %d", plain, plain_len);
	memcpy(encrypted, plain, plain_len);
	TEE_GenerateRandom(key_ptr, 1);	//1byte size random value(0~255)
	key %= 26;

	for(int i=0; i<plain_len;i++){
 		if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] = (encrypted[i]-'A'+key)%26 + 'A';
		}
		else if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] = (encrypted[i]-'a'+key)%26 + 'a';
		}
	}
	DMSG ("Ciphertext :  %s, Key: %d", encrypted, key);
	memcpy(plain, encrypted, plain_len);
	//encrypt key with Rootkey	
	key = (key+rootkey)%26;
	((char*)params[1].memref.buffer)[0] = (key/10)+'0';
	((char*)params[1].memref.buffer)[1] = (key%10)+'0';
	((char*)params[1].memref.buffer)[2] = '\n';
	((char*)params[1].memref.buffer)[3] = '\0';
	return TEE_SUCCESS;
}

static TEE_Result dec_value(TEE_Param params[4])
{
	char* encrypted = (char*)params[0].memref.buffer;
	int encrypted_len = strlen(params[0].memref.buffer);
	char decrypted[MAX] = {0,};
	int key;
	DMSG("has been called");
	DMSG("**Decryption**\n");
	DMSG("Ciphertext : %s, Length: %d", encrypted, encrypted_len);
	memcpy(decrypted, encrypted, encrypted_len);
	key = (((char*)params[1].memref.buffer)[0]-'0')*10
		+ (((char*)params[1].memref.buffer)[1]-'0');
	//decrypt key with Rootkey
	key = (key-rootkey+26)%26;	
	for(int i=0; i<encrypted_len;i++){
 		if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] = (decrypted[i]-'A'-key+26)%26 + 'A';
		}
		else if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] = (decrypted[i]-'a'-key+26)%26 + 'a';
		}
	}
	DMSG ("Plaintext :  %s, Key: %d", decrypted, key);
	memcpy(encrypted, decrypted, encrypted_len);
	((char*)params[1].memref.buffer)[0] = '\0';
	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *session,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	//(void)&sess_ctx; /* Unused parameter */
	rootkey = 17;	//ROOTKEY

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return dec_value(params);
	case TA_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(session);
	case TA_RSA_CMD_ENCRYPT:
		return RSA_encrypt(session, param_types, params);
	case TA_RSA_CMD_DECRYPT:
		return RSA_decrypt(session, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
