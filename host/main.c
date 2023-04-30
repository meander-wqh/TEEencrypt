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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define MAX 86
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_sz;
}
int main(int argc, char* argv[])
{
	if(argc < 3) {
		printf("error: requires more arguments.\n");	
		return -1;
	}
	FILE* fp_in = fopen(argv[2], "r");
	char* filename_out;
	if(fp_in == NULL) {
		printf("error: cannot open the file: \'%s\'\n", argv[2]);	
		return -1;
	}
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char inputtext[MAX] = {0,};
	char outputtext[MAX] = {0,};
	char keytext[MAX] = {0,};

	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);
	//params [0]:Text	[1]:Key
	op.params[0].tmpref.buffer = inputtext;
	op.params[0].tmpref.size = MAX;
	op.params[1].tmpref.buffer = keytext;
	op.params[1].tmpref.size = MAX;
	if(strcmp(argv[1], "-e") == 0) {
		if(argc<4 || strcmp(argv[3], "Caesar")==0) {
			fread(inputtext, sizeof(char), MAX, fp_in);//text
			memcpy(op.params[0].tmpref.buffer, inputtext, MAX);
			printf("**Encryption**\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
			memcpy(keytext, op.params[1].tmpref.buffer, MAX);
			memcpy(outputtext, op.params[0].tmpref.buffer, MAX);
		}else if(strcmp(argv[3], "RSA")==0) {
			//generate RSA key:
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
			printf("\n=========== Keys already generated. ==========\n");
			//prepare plaintext:
			fread(inputtext, sizeof(char), MAX, fp_in);//text
			memcpy(op.params[0].tmpref.buffer, inputtext, MAX);
			//encryption:
			printf("\n============ RSA ENCRYPT CA SIDE ============\n");
			memcpy(op.params[0].tmpref.buffer, inputtext, MAX);
			prepare_op(&op, inputtext, RSA_MAX_PLAIN_LEN_1024, outputtext, RSA_CIPHER_LEN_1024);
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT, &op, &err_origin);
			printf("\nThe text sent was encrypted: %s\n", outputtext);
			//decryption test:
			char out_outputtext[MAX] = {0,};
			printf("\n============ RSA DECRYPT CA SIDE ============\n");
			prepare_op(&op, outputtext, RSA_CIPHER_LEN_1024, out_outputtext, RSA_MAX_PLAIN_LEN_1024);
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_DECRYPT, &op, &err_origin);
			printf("\nThe text sent was decrypted: %s\n", (char*)out_outputtext);
			char emptytext[MAX] = {0,};
			op.params[1].tmpref.buffer = emptytext;
		}else {
			printf("error: wrong algorithm: \'%s\'\n", argv[3]);	
			return -1;
		}
		filename_out = "ciphertext.txt";
		
	}else if(strcmp(argv[1], "-d") == 0) {
		if(argc<4 || strcmp(argv[3], "Caesar")==0) {
			fgets(keytext, MAX, fp_in);	//key
			memcpy(op.params[1].tmpref.buffer, keytext, MAX);
			fread(inputtext, sizeof(char), MAX, fp_in);//text
			memcpy(op.params[0].tmpref.buffer, inputtext, MAX);
			printf("**Decryption**\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
			filename_out = "plaintext.txt";
			memcpy(keytext, op.params[1].tmpref.buffer, MAX);
			memcpy(outputtext, op.params[0].tmpref.buffer, MAX);
		}else if(strcmp(argv[3], "RSA")==0) {
			printf("\n============ RSA DECRYPT CA SIDE ============\n");
			prepare_op(&op, inputtext, RSA_MAX_PLAIN_LEN_1024, outputtext, RSA_CIPHER_LEN_1024);
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_DECRYPT, &op, &err_origin);
			printf("\nThe text sent was decrypted: %s\n", outputtext);
		}
	}else {
		printf("error: invalid option: \'%s\'\n", argv[1]);	
		return -1;
	}
	fclose(fp_in);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("\'%s\': %s\n", filename_out, outputtext);
	FILE* fp_out = fopen(filename_out, "w");
	fputs(keytext, fp_out); //key
	fwrite(outputtext, sizeof(char), MAX, fp_out); //text
	fclose(fp_out);
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
