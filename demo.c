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
#include "./qdbmp/qdbmp.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 6386)
#pragma warning(disable : 6262)
#pragma warning(disable : 4996)


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
	char* kyber_implementation = "Kyber1024";
	char* input_file_path = "./input/monkey1.bmp";
	char* encryption_file_path = "./Outputs/Encryption/monkey1.bmp";
	char* decryption_file_path = "./Outputs/Decryption/monkey1.bmp";

	// Initialize Kyber512 variables
	uint8_t public_key_512[OQS_KEM_kyber_512_length_public_key] = { "" };
	uint8_t secret_key_512[OQS_KEM_kyber_512_length_secret_key] = { "" };
	uint8_t ciphertext_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };

	// Initialize Kyber768 variables
	uint8_t public_key_768[OQS_KEM_kyber_768_length_public_key] = { "" };
	uint8_t secret_key_768[OQS_KEM_kyber_768_length_secret_key] = { "" };
	uint8_t ciphertext_768[OQS_KEM_kyber_768_length_ciphertext] = { "" };

	// Initialize Kyber1024 variables
	uint8_t public_key_1024[OQS_KEM_kyber_1024_length_public_key] = { "" };
	uint8_t secret_key_1024[OQS_KEM_kyber_1024_length_secret_key] = { "" };
	uint8_t ciphertext_1024[OQS_KEM_kyber_1024_length_ciphertext] = { "" };

	// Initialize program variables
	OQS_STATUS rc;
	FILE* f_input;
	FILE* f_encryption;
	FILE* f_decryption;
	size_t encoded_size;
	uint8_t buffer32[32] = "";
	uint8_t decrypted_message[32] = "";
	uint8_t header[54] = "";
	long long fileSize;
	long long i = 0;
	int k = 0;

	/*

	Keygen

	*/
	OQS_KEM_kyber_512_keypair(public_key_512, secret_key_512);
	OQS_KEM_kyber_768_keypair(public_key_768, secret_key_768);
	OQS_KEM_kyber_1024_keypair(public_key_1024, secret_key_1024);

	/*
	
	Encryption

	*/
	f_input = fopen(input_file_path, "rb");
	if (!f_input) {
		printf("Invalid file path, file might not exist: %s\nProgram End.\n", input_file_path);
		return 0;
	}
	_fseeki64(f_input, 0, SEEK_END);
	fileSize = _ftelli64(f_input);
	_fseeki64(f_input, 0, SEEK_SET);

	fread(header,1,54,f_input);

	f_encryption = fopen(encryption_file_path, "wb+");
	fwrite(header,54,1,f_encryption);
	i = 0;
	while (i < fileSize - 54) {
		for (k = 0; k < 32; k++) buffer32[k] = 0x0;
		fread(buffer32, 1, 32, f_input);
		if (kyber_implementation == "Kyber512") {
			OQS_KEM_kyber_512_encrypt(ciphertext_512, buffer32, public_key_512);
			fwrite(ciphertext_512, 1, OQS_KEM_kyber_512_length_ciphertext, f_encryption);
		}
		else if (kyber_implementation == "Kyber768") {
			
			OQS_KEM_kyber_768_encrypt(ciphertext_768, buffer32, public_key_768);
			fwrite(ciphertext_768, 1, OQS_KEM_kyber_768_length_ciphertext, f_encryption);
		}
		else if (kyber_implementation == "Kyber1024") {
			OQS_KEM_kyber_1024_encrypt(ciphertext_1024, buffer32, public_key_1024);
			fwrite(ciphertext_1024, 1, OQS_KEM_kyber_1024_length_ciphertext, f_encryption);
		}
		i += 32;
	}
	fclose(f_input);
	fclose(f_encryption);

	/*
	
	Decryption 
	
	*/
	f_encryption = fopen(encryption_file_path, "rb");
	if (!f_encryption) {
		printf("Invalid file path, file might not exist: %s\nProgram End.\n", encryption_file_path);
		return 0;
	}
	_fseeki64(f_encryption, 0, SEEK_END);
	fileSize = _ftelli64(f_encryption);
	_fseeki64(f_encryption, 0, SEEK_SET);

	fread(header, 1, 54, f_encryption);

	f_decryption = fopen(decryption_file_path, "wb+");
	fwrite(header, 54, 1, f_decryption);
	i = 0;
	while (i < fileSize - 54) {
		for (k = 0; k < 32; k++) buffer32[k] = 0x0;
		if (kyber_implementation == "Kyber512") {
			for (k = 0; k < OQS_KEM_kyber_512_length_ciphertext; k++) ciphertext_512[k] = 0x0;
			fread(ciphertext_512, 1, OQS_KEM_kyber_512_length_ciphertext, f_encryption);
			OQS_KEM_kyber_512_decrypt(buffer32, ciphertext_512, secret_key_512);
			
			i += OQS_KEM_kyber_512_length_ciphertext;
		}
		else if (kyber_implementation == "Kyber768") {
			for (k = 0; k < OQS_KEM_kyber_768_length_ciphertext; k++) ciphertext_768[k] = 0x0;
			fread(ciphertext_768, 1, OQS_KEM_kyber_768_length_ciphertext, f_encryption);
			OQS_KEM_kyber_768_decrypt(buffer32, ciphertext_768, secret_key_768);
			i += OQS_KEM_kyber_768_length_ciphertext;
		}
		else if (kyber_implementation == "Kyber1024") {
			for (k = 0; k < OQS_KEM_kyber_1024_length_ciphertext; k++) ciphertext_1024[k] = 0x0;
			fread(ciphertext_1024, 1, OQS_KEM_kyber_1024_length_ciphertext, f_encryption);
			OQS_KEM_kyber_1024_decrypt(buffer32, ciphertext_1024, secret_key_1024);
			i += OQS_KEM_kyber_1024_length_ciphertext;
		}
		fwrite(buffer32, 1, 32, f_decryption);
	}
	fclose(f_encryption);
	fclose(f_decryption);
	return 0;
}