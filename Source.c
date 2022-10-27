#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <oqs/kem_kyber.h>
#pragma warning(disable : 4996)
#pragma warning(disable : 6386)

/* Cleaning up memory etc */
void cleanup_stack(uint8_t* ciphertext, size_t ciphertext_len,
	uint8_t* public_key, size_t public_key_len,
	uint8_t* secret_key, size_t secret_key_len,
	uint8_t* shared_secret1, uint8_t* shared_secret2,
	size_t shared_secret_len);

int main(void) {
	// read message.txt
	FILE* fp;
	size_t fileSize;
	fp = fopen("message.txt","r");
	// check file size
	fseek(fp, 0L, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	// kyber512-PKE
	OQS_STATUS rc;
	uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
	uint8_t ciphertext[OQS_KEM_kyber_512_length_ciphertext];
	uint8_t message1[OQS_KEM_kyber_512_length_shared_secret] = { "" };
	fread(message1,fileSize, 2, fp);
	uint8_t message2[OQS_KEM_kyber_512_length_shared_secret] = { "" };

	rc = OQS_KEM_kyber_512_keypair(public_key, secret_key);
	rc = OQS_KEM_kyber_512_encrypt(ciphertext, message1, public_key);
	rc = OQS_KEM_kyber_512_decrypt(message2, ciphertext, secret_key);

	// compare if message1 is the same as message2
	if (strcmp(message1,message2) == 0) {
		printf("Kyber512-PKE Successful\n");
		printf("\nMessage 1: %s\nMessage 2: %s", message1, message2);
		int public_key_len = sizeof(public_key);
		int secret_key_len = sizeof(secret_key);
		int ciphertext_len = sizeof(ciphertext);
		printf("\n\nPublic Key Size: %d\n", public_key_len);
		printf("Public Key:\n");
		for (int i = 0; i < sizeof(public_key); i++)
			printf("%02X", public_key[i]);
		printf("\n\nSecret Key Size: %d\n", secret_key_len);
		printf("Secret Key: \n");
		for (int i = 0; i < sizeof(secret_key); i++)
			printf("%02X", secret_key[i]);
		printf("\n\n");
		printf("\n\nCiphertext Size: %d\n", ciphertext_len);
		printf("Ciphertext: \n");
		for (int i = 0; i < ciphertext_len; i++)
			printf("%02X", ciphertext[i]);
		printf("\n\n");
	}
	else {
		printf("Kyber768-PKE Unsuccessful");
	}

	// clean up memory
	cleanup_stack(ciphertext, OQS_KEM_kyber_512_length_ciphertext,
				  public_key, OQS_KEM_kyber_512_length_public_key, 
		          secret_key, OQS_KEM_kyber_512_length_secret_key,
				  message1, message2, OQS_KEM_kyber_512_length_shared_secret);
	// return
	return EXIT_SUCCESS;
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
