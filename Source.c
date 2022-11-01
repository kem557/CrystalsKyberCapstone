#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "b64/b64.h"
#include <oqs/oqs.h>
#include <oqs/kem_kyber.h>
#pragma warning(disable : 4996)
#pragma warning(disable : 6386)

int main(void) {
	// kyber768-PKE
	OQS_STATUS rc;
	uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
	uint8_t ciphertext1[OQS_KEM_kyber_768_length_ciphertext] = {""};
	uint8_t ciphertext2[OQS_KEM_kyber_768_length_ciphertext] = {""};
	uint8_t encoded_cipher[1452];
	// read ./input/message-2mb.txt
	FILE* f_input;
	FILE* f_encryption;
	FILE* f_decryption;
	size_t fileSize;
	uint8_t* decoded = malloc(1088);
	uint8_t* encoded = malloc(1452);
	size_t encoded_size;
	size_t decoded_size;
	uint8_t buffer[1452];
	uint8_t buffer32[32];
	uint8_t decrypted_message[32] = "";
	char* output_file_text[32];
	char* b64_buf;
	f_input = fopen("./input/lotus1.jpg","rb");
	
	// check file size
	fseek(f_input, 0L, SEEK_END);
	fileSize = 0;
	if (ftell(f_input) > 0) {
		fileSize = ftell(f_input);
	}
	fseek(f_input, 0L, SEEK_SET);	

	// generate public key and private key
	rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);

	// append ciphertext to output file ./output/ciphertext.txt
	f_encryption = fopen("./Outputs/Encryption/ciphertext.txt","w+");
	int i = 0;
	int j = 0;
	int k = 0;
	
	while(i < fileSize) {
		for (k = 0; k < 32; k++) buffer32[k] = 0x0;
		fread(buffer32, 1, 32, f_input);
		rc = OQS_KEM_kyber_768_encrypt(ciphertext1, buffer32, public_key);
		free(encoded);
		encoded = b64_encode(ciphertext1, sizeof(ciphertext1));
		fprintf(f_encryption, "%s", encoded);

		i += 32;
	}
	fclose(f_input);
	fclose(f_encryption);

	// clear encoded ciphertext
	encoded = "";

	// decrypt ciphertext and append to output file ./outputs/decryption/message.txt
	f_encryption = fopen("./Outputs/Encryption/ciphertext.txt", "r");
	f_decryption = fopen("./Outputs/Decryption/lotus1.jpg", "wb+ ");
	// check file size
	fseek(f_encryption, 0L, SEEK_END);
	fileSize = 0;
	if (ftell(f_encryption) > 0) {
		fileSize = ftell(f_encryption);
	}
	fseek(f_encryption, 0L, SEEK_SET);

	// index through encoded file
	i = 0;
	j = 0;
	while (j < fileSize-1) {
		fread(encoded_cipher, 1452, 1, f_encryption);
		encoded_size = sizeof(encoded_cipher);
		free(decoded);
		decoded = b64_decode(encoded_cipher, encoded_size);
		for (k = 0; k < 32; k++) buffer32[k] = 0x0;
		rc = OQS_KEM_kyber_768_decrypt(buffer32, decoded, secret_key);
		for (k = 0; k < 32; k++) fprintf(f_decryption, "%c", buffer32[k]);
		j += 1452;
	}
	for (k = 0; k < 32; k++) buffer32[k] = 0x0;
	fclose(f_decryption);
	fclose(f_encryption);
	return 0;
}