#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "b64/b64.h"
#include <oqs/oqs.h>
#include <oqs/kem_kyber.h>
#define NELEMS(x)  (sizeof(x) / sizeof(x[0]))
#pragma warning(disable : 4996)
#pragma warning(disable : 6386)

/* Cleaning up memory etc */
void cleanup_stack(uint8_t* ciphertext, size_t ciphertext_len,
	uint8_t* public_key, size_t public_key_len,
	uint8_t* secret_key, size_t secret_key_len,
	uint8_t* shared_secret1, uint8_t* shared_secret2,
	size_t shared_secret_len);

int main(void) {
	// kyber512-PKE
	OQS_STATUS rc;
	uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
	uint8_t ciphertext1[OQS_KEM_kyber_512_length_ciphertext] = {""};
	uint8_t ciphertext2[OQS_KEM_kyber_512_length_ciphertext] = {""};
	uint8_t message[OQS_KEM_kyber_512_length_shared_secret] = { "" };
	uint8_t encoded_cipher[1024];
	// read ./input/message.txt
	FILE* f_input;
	FILE* f_encryption;
	FILE* f_decryption;
	size_t fileSize;
	uint8_t* decoded;
	uint8_t* encoded;
	size_t encoded_size;
	size_t decoded_size;
	uint8_t file_text[30000] = { "" };
	f_input = fopen("./input/message2.txt","r");
	
	// check file size
	fseek(f_input, 0L, SEEK_END);
	fileSize = 0;
	if (ftell(f_input) > 0) {
		fileSize = ftell(f_input);
	}
	fseek(f_input, 0L, SEEK_SET);
	
	fread(file_text, fileSize, 1, f_input);
	fclose(f_input);

	// generate public key and private key
	rc = OQS_KEM_kyber_512_keypair(public_key, secret_key);

	// append ciphertext to output file ./output/ciphertext.txt
	f_encryption = fopen("./Outputs/Encryption/ciphertext.txt","w+");
	int i = 0;
	int j = 0;
	int k = 0;
	
	while(i < fileSize) {
		for (j = 0; j < 32; j++) {
			if (i + j < fileSize) {
				message[j] = file_text[i + j];
			}
		}
		rc = OQS_KEM_kyber_512_encrypt(ciphertext1, message, public_key);
		encoded = b64_encode(ciphertext1, sizeof(ciphertext1));
		encoded_size = strlen(encoded);
		fprintf(f_encryption, "%s", encoded);

		i += 32;
	}
	fclose(f_encryption);

	// clear file text
	for (i = 0; i < fileSize; i++) {
		file_text[i] = 0x0;
	}

	// decrypt ciphertext and append to output file ./outputs/decryption/message.txt
	f_encryption = fopen("./Outputs/Encryption/ciphertext.txt", "r");
	f_decryption = fopen("./Outputs/Decryption/message.txt", "w+");
	// check file size
	fseek(f_encryption, 0L, SEEK_END);
	fileSize = 0;
	if (ftell(f_encryption) > 0) {
		fileSize = ftell(f_encryption);
	}
	fseek(f_encryption, 0L, SEEK_SET);
	fread(file_text, fileSize, 1, f_encryption);
	fclose(f_encryption);

	
	i = 0;
	j = 0;
	
	uint8_t decrypted_message[OQS_KEM_kyber_512_length_shared_secret] = {""};
	while (i < fileSize-1) {
		for (j = 0; j < 1024; j += 1) {
			if (i + j < fileSize) {
				encoded_cipher[j] = file_text[i + j];
			}
		}
		encoded_size = sizeof(encoded_cipher);
		decoded = b64_decode(encoded_cipher, encoded_size);
		rc = OQS_KEM_kyber_512_decrypt(decrypted_message, decoded, secret_key);
		fprintf(f_decryption, "%s", decrypted_message);
		i += 1024;
	}
	for (k = 0; k < fileSize; k++) {
		file_text[k] = 0x0;
	}
	fclose(f_decryption);
	
	//rc = OQS_KEM_kyber_512_decrypt(message2, ciphertext, secret_key);

	// compare if message1 is the same as message2
	//if (strcmp(message1, message2) == 0) {
	//	printf("Kyber512-PKE Successful\n");
	//	printf("\nMessage 1: %s\nMessage 2: %s", message1, message2);
	//	int public_key_len = sizeof(public_key);
	//	int secret_key_len = sizeof(secret_key);
	//	int ciphertext_len = sizeof(ciphertext);
	//	printf("\n\nPublic Key Size: %d\n", public_key_len);
	//	printf("Public Key:\n");
	//	for (int i = 0; i < sizeof(public_key); i++)
	//		printf("%02X", public_key[i]);
	//	printf("\n\nSecret Key Size: %d\n", secret_key_len);
	//	printf("Secret Key: \n");
	//	for (int i = 0; i < sizeof(secret_key); i++)
	//		printf("%02X", secret_key[i]);
	//	printf("\n\n");
	//	printf("\n\nCiphertext Size: %d\n", ciphertext_len);
	//	printf("Ciphertext: \n");
	//	for (int i = 0; i < ciphertext_len; i++)
	//		printf("%02X", ciphertext[i]);
	//	printf("\n\n");
	//}
	//else {
	//	printf("Kyber768-PKE Unsuccessful");
	//}
	// clean up memory
	//cleanup_stack(ciphertext, OQS_KEM_kyber_512_length_ciphertext,
	//			  public_key, OQS_KEM_kyber_512_length_public_key, 
	//	          secret_key, OQS_KEM_kyber_512_length_secret_key,
	//			  message1, message2, OQS_KEM_kyber_512_length_shared_secret);
	
	// return
	return 0;
}

// cleans memory
void cleanup_stack(uint8_t* ciphertext, size_t ciphertext_length,
	uint8_t* public_key, size_t public_key_len,
	uint8_t* secret_key, size_t secret_key_len,
	uint8_t* shared_secret1, uint8_t* shared_secret2,
	size_t shared_secret_len) {
	OQS_MEM_cleanse(ciphertext, ciphertext_length);
	OQS_MEM_cleanse(public_key, public_key_len);
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret1, shared_secret_len);
	OQS_MEM_cleanse(shared_secret2, shared_secret_len);
}