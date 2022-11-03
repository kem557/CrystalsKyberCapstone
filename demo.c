#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "b64/b64.h"
#include <oqs/oqs.h>
#include <oqs/kem_kyber.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <Windows.h> 
#pragma warning(disable : 4996)
#pragma warning(disable : 6386)
#pragma warning(disable : 6262)

int main(void) {
	/*
	Kyber Encryption/Decryption Demo
	How to use:
		1 *configure kyber_implementation variable to which kyber implimentation you
		want to use. Options: 'Kyber512', 'Kyber768', 'Kyber1024'

		2 *configure input_file_path variable to the path of file you want to encrypt.
		
		3 *configure encryption_file_path variable to the path of where you want
		the ciphertext output file to be created.

		4 *configure decryption_file_path variable to the path of where you want
		the decrypted output file to be created.

		The current configuration should use Kyber512 to encrypt and decrypt a file
		./input/lotus.kpg to ciphertext file ./Outputs/Encryption/ciphertext.txt",
		and then decrypt the ciphertext file to output file "./Outputs/Decryption/lotus_decrypted.jpg"
	*/
	char* kyber_implementation = "Kyber512";
	char* input_file_path = "./input/lotus.jpg";
	char* encryption_file_path = "./Outputs/Encryption/ciphertext.txt";
	char* decryption_file_path = "./Outputs/Decryption/lotus_decrypted.jpg";

	// Check if kyber_implementation variable is valid implimentation
	if (kyber_implementation == "Kyber512" || kyber_implementation == "Kyber768"
		|| kyber_implementation == "Kyber1024") {
		printf("Kyber encryption initialized using %s\n\n", kyber_implementation);
	}
	else {
		printf("Invalid Kyber implimentation\nValid implimentations:\t'Kyber512','Kyber768','Kyber1024'\n\n");
		return 0;
	}
	
	// Initialize Kyber512 variables
	uint8_t public_key_512[OQS_KEM_kyber_512_length_public_key] = { "" };
	uint8_t secret_key_512[OQS_KEM_kyber_512_length_secret_key] = { "" };
	uint8_t ciphertext1_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };
	uint8_t ciphertext2_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };
	uint8_t encoded_cipher_512[1024];
	uint8_t* decoded_512 = malloc(OQS_KEM_kyber_512_length_ciphertext);
	uint8_t* encoded_512 = malloc(1024);

	// Initialize Kyber768 variables
	uint8_t public_key_768[OQS_KEM_kyber_768_length_public_key] = { "" };
	uint8_t secret_key_768[OQS_KEM_kyber_768_length_secret_key] = { "" };
	uint8_t ciphertext1_768[OQS_KEM_kyber_768_length_ciphertext] = { "" };
	uint8_t ciphertext2_768[OQS_KEM_kyber_768_length_ciphertext] = { "" };
	uint8_t encoded_cipher_768[1452];
	uint8_t* decoded_768 = malloc(OQS_KEM_kyber_768_length_ciphertext);
	uint8_t* encoded_768 = malloc(1452);

	// Initialize Kyber1024 variables
	uint8_t public_key_1024[OQS_KEM_kyber_1024_length_public_key] = {""};
	uint8_t secret_key_1024[OQS_KEM_kyber_1024_length_secret_key] = {""};
	uint8_t ciphertext1_1024[OQS_KEM_kyber_1024_length_ciphertext] = { "" };
	uint8_t ciphertext2_1024[OQS_KEM_kyber_1024_length_ciphertext] = { "" };
	uint8_t encoded_cipher_1024[2092];
	uint8_t* decoded_1024 = malloc(OQS_KEM_kyber_1024_length_ciphertext);
	uint8_t* encoded_1024 = malloc(2092);

	// Initialize program variables
	OQS_STATUS rc;
	FILE* f_input;
	FILE* f_encryption;
	FILE* f_decryption;
	size_t encoded_size;
	uint8_t buffer32[32] = "";
	uint8_t decrypted_message[32] = "";
	long long fileSize;
	long long i = 0;
	long long j = 0;
	int k = 0;

	// check file size
	f_input = fopen(input_file_path, "rb");
	if (!f_input) {
		printf("Invalid input file path, file might not exist: %s\nProgram End.\n", input_file_path);
		return 0;
	}
	_fseeki64(f_input, 0, SEEK_END);
	fileSize = _ftelli64(f_input);
	_fseeki64(f_input, 0, SEEK_SET);

	// generate public key and private key
	if (kyber_implementation == "Kyber512") {
		rc = OQS_KEM_kyber_512_keypair(public_key_512, secret_key_512);
	}
	else if (kyber_implementation == "Kyber768") {
		rc = OQS_KEM_kyber_768_keypair(public_key_768, secret_key_768);
	}
	else {
		rc = OQS_KEM_kyber_1024_keypair(public_key_1024, secret_key_1024);
	}

	// append ciphertext to output file
	f_encryption = fopen(encryption_file_path,"w+");
	printf("Beginning to encrypt file:\t %s\n", input_file_path);

	// read input file in 32 Byte increments
	while(i < fileSize) {
		for (k = 0; k < 32; k++) buffer32[k] = 0x0;
		fread(buffer32, 1, 32, f_input);

		/* 
		encrypt 32 Byte message, encode ciphertext
		to base64, write encoded ciphertext to file
		*/
		if (kyber_implementation == "Kyber512") {
			rc = OQS_KEM_kyber_512_encrypt(ciphertext1_512, buffer32, public_key_512);
			free(encoded_512);
			encoded_512 = b64_encode(ciphertext1_512, sizeof(ciphertext1_512));
			fprintf(f_encryption, "%s", encoded_512);
		}
		else if (kyber_implementation == "Kyber768") {
			rc = OQS_KEM_kyber_768_encrypt(ciphertext1_768, buffer32, public_key_768);
			free(encoded_768);
			encoded_768 = b64_encode(ciphertext1_768, sizeof(ciphertext1_768));
			fprintf(f_encryption, "%s", encoded_768);
		}
		else {
			rc = OQS_KEM_kyber_1024_encrypt(ciphertext1_1024, buffer32, public_key_1024);
			free(encoded_1024);
			encoded_1024 = b64_encode(ciphertext1_1024, sizeof(ciphertext1_1024));
			fprintf(f_encryption, "%s", encoded_1024);
		}
		
		printf("Encrypted %llu Bytes of %llu Bytes\tPercent done: %f\n",i+33,fileSize, 100.0 * i / fileSize);
		i += 32;
	}
	fclose(f_input);
	fclose(f_encryption);
	printf("Finished encrypting file:\t %s\n", input_file_path);
	printf("Ciphertext file saved to file path: %s\n", encryption_file_path);

	// clear encoded ciphertext
	encoded_512 = "";
	encoded_768 = "";
	encoded_1024 = "";
	fileSize = 1;

	// decrypt ciphertext and append to output file ./outputs/decryption/message.txt
	f_encryption = fopen(encryption_file_path, "r");
	f_decryption = fopen(decryption_file_path, "wb+ ");
	// check file size
	_fseeki64(f_encryption, 0, SEEK_END);
	fileSize = _ftelli64(f_encryption);
	_fseeki64(f_encryption, 0, SEEK_SET);
	// index through encoded file
	i = 0;
	j = 0;
	printf("Beginning to decrypt ciphertext file: %s\n", encryption_file_path);

	// read encoded ciphertext file in increments
	while (j < fileSize) {
		/*
		read encoded ciphertext, decode from base64,
		decrypt ciphertext, write decrypted bytes to output file
		*/
		if (kyber_implementation == "Kyber512") {
			fread(encoded_cipher_512, 1024, 1, f_encryption);
			encoded_size = sizeof(encoded_cipher_512);
			free(decoded_512);
			decoded_512 = b64_decode(encoded_cipher_512, encoded_size);
			for (k = 0; k < 32; k++) buffer32[k] = 0x0;
			rc = OQS_KEM_kyber_512_decrypt(buffer32, decoded_512, secret_key_512);
			for (k = 0; k < 32; k++) fprintf(f_decryption, "%c", buffer32[k]);
			printf("Decrypted %llu Bytes of %llu Bytes\tPercent done: %f\n", j + 1024, fileSize, 100.0 * j / fileSize);
			j += 1024;
		}
		else if (kyber_implementation == "Kyber768") {
			fread(encoded_cipher_768, 1452, 1, f_encryption);
			encoded_size = sizeof(encoded_cipher_768);
			free(decoded_768);
			decoded_768 = b64_decode(encoded_cipher_768, encoded_size);
			for (k = 0; k < 32; k++) buffer32[k] = 0x0;
			rc = OQS_KEM_kyber_768_decrypt(buffer32, decoded_768, secret_key_768);
			for (k = 0; k < 32; k++) fprintf(f_decryption, "%c", buffer32[k]);
			printf("Decrypted %llu Bytes of %llu Bytes\tPercent done: %f\n", j + 1452, fileSize, 100.0 * j / fileSize);
			j += 1452;
			
		}
		else {
			fread(encoded_cipher_1024, 2092, 1, f_encryption);
			encoded_size = sizeof(encoded_cipher_1024);
			free(decoded_1024);
			decoded_1024 = b64_decode(encoded_cipher_1024, encoded_size);
			for (k = 0; k < 32; k++) buffer32[k] = 0x0;
			rc = OQS_KEM_kyber_1024_decrypt(buffer32, decoded_1024, secret_key_1024);
			for (k = 0; k < 32; k++) fprintf(f_decryption, "%c", buffer32[k]);
			printf("Decrypted %llu Bytes of %llu Bytes\tPercent done: %f\n", j + 2092, fileSize, 100.0 * j / fileSize);
			j += 2092;
		}
	}
	for (k = 0; k < 32; k++) buffer32[k] = 0x0;
	fclose(f_decryption);
	fclose(f_encryption);
	printf("Finished decrypting ciphertext file: %s\n", encryption_file_path);
	printf("Decrypted file saved to file path: %s\nProgram End.\n\n", decryption_file_path);
	return 0;
}