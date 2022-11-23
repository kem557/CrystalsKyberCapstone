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
	char* kyber_implementation = "Kyber512";
	char* input_file_path = "./input/monkey2.bmp";
	char* encryption_file_path = "./Outputs/Encryption/enc_monkey2.bmp";
	char* decryption_file_path = "./Outputs/Decryption/dec_monkey2.bmp";

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
	uint8_t ciphertext_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };
	uint8_t encoded_cipher_512[1024];
	uint8_t* decoded_512 = malloc(OQS_KEM_kyber_512_length_ciphertext);
	uint8_t* encoded_512 = malloc(1024);

	// Initialize Kyber768 variables
	uint8_t public_key_768[OQS_KEM_kyber_768_length_public_key] = { "" };
	uint8_t secret_key_768[OQS_KEM_kyber_768_length_secret_key] = { "" };
	uint8_t ciphertext_768[OQS_KEM_kyber_768_length_ciphertext] = { "" };
	uint8_t encoded_cipher_768[1452];
	uint8_t* decoded_768 = malloc(OQS_KEM_kyber_768_length_ciphertext);
	uint8_t* encoded_768 = malloc(1452);

	// Initialize Kyber1024 variables
	uint8_t public_key_1024[OQS_KEM_kyber_1024_length_public_key] = {""};
	uint8_t secret_key_1024[OQS_KEM_kyber_1024_length_secret_key] = {""};
	uint8_t ciphertext_1024[OQS_KEM_kyber_1024_length_ciphertext] = { "" };
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

	BMP* bmp;
	BMP* bmp2;
	BMP* bmp3;
	BMP* bmp4;
	UINT    width, height;
	USHORT	depth;

	/* Read an image file */
	bmp = BMP_ReadFile(input_file_path);

	/* Get image's dimensions */
	width = BMP_GetWidth(bmp);
	height = BMP_GetHeight(bmp);
	UINT	width2 = width*24;
	UINT	height2 = height;
	depth = BMP_GetDepth(bmp);
	bmp2 = BMP_Create(width2, height2,depth);
	/* Iterate through all the image's pixels */
	UCHAR r;
	UCHAR g;
	UCHAR b;
	UCHAR r2;
	UCHAR g2;
	UCHAR b2;
	i = 0;
	int i2 = 0;
	long long t = 0;
	long long t2 = 0;
	long long x1 = 0;
	long long y1 = -1;
	long long x2 = 0;
	long long y2 = -1;
	uint8_t Rbuffer32[32] = "";
	uint8_t Gbuffer32[32] = "";
	uint8_t Bbuffer32[32] = "";
	uint8_t Rciphertext_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };
	uint8_t Gciphertext_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };
	uint8_t Bciphertext_512[OQS_KEM_kyber_512_length_ciphertext] = { "" };
	for (t = 0; t < width*height; t++)
	{
		x1 = t % (width);
		if (x1 == 0) {
			y1++;
		}
		/* Get pixel's RGB values */
		BMP_GetPixelRGB(bmp, x1, y1, &r, &g, &b);
		Rbuffer32[i] = r;
		Gbuffer32[i] = g;
		Bbuffer32[i] = b;
		i++;

		// encrypt pixel values
		if (i == 32 || t == width*height) {
			i = 0;
			rc = OQS_KEM_kyber_512_encrypt(Rciphertext_512, Rbuffer32, public_key_512);
			rc = OQS_KEM_kyber_512_encrypt(Gciphertext_512, Gbuffer32, public_key_512);
			rc = OQS_KEM_kyber_512_encrypt(Bciphertext_512, Bbuffer32, public_key_512);
			for (int u = 0; u < 32; u++) {
				Rbuffer32[u] = 0x0;
				Gbuffer32[u] = 0x0;
				Bbuffer32[u] = 0x0;
			}
			// set new pixel values to encypted image
			for (j = 0; j < 768; j++) {
				
				x2 = t2 % (width2);
				if (x2 == 0) {
					y2++;
				}
				BMP_SetPixelRGB(bmp2, x2, y2, Rciphertext_512[j], Gciphertext_512[j], Bciphertext_512[j]);

				Rciphertext_512[j] = 0x0;
				Gciphertext_512[j] = 0x0;
				Bciphertext_512[j] = 0x0;
				t2 += 1;
			}
		}
	}
	BMP_WriteFile(bmp2,encryption_file_path);
	BMP_Free(bmp);
	BMP_Free(bmp2);

	bmp3 = BMP_ReadFile(encryption_file_path);
	height = BMP_GetHeight(bmp3);
	width = BMP_GetWidth(bmp3);
	depth = BMP_GetDepth(bmp3);
	height2 = height;
	width2 = width/24;
	bmp4 = BMP_Create(width2, height2, depth);
	x1 = 0;
	y1 = 0;
	x2 = 0;
	y2 = 0;
	k = 0;
	i = 0;
	j = 0;
	for (t = 0; t < width * height; t++) {
		x1 = t % width;
		if (x1 == 0) {
			y1++;
		}
		/* Get pixel's RGB values */
		BMP_GetPixelRGB(bmp3, x1, y1, &r, &g, &b);
		Rciphertext_512[i] = r;
		Gciphertext_512[i] = g;
		Bciphertext_512[i] = b;
		i++;

		// encrypt pixel values
		if (i == 768 || t == width * height) {
			i = 0;
			rc = OQS_KEM_kyber_512_decrypt(Rbuffer32, Rciphertext_512, secret_key_512);
			rc = OQS_KEM_kyber_512_decrypt(Gbuffer32, Gciphertext_512, secret_key_512);
			rc = OQS_KEM_kyber_512_decrypt(Bbuffer32, Bciphertext_512, secret_key_512);
			for (int u = 0; u < 768; u++) {
				Rciphertext_512[u] = 0x0;
				Gciphertext_512[u] = 0x0;
				Bciphertext_512[u] = 0x0;
			}
			// set new pixel values to encypted image
			for (j = 0; j < 32; j++) {

				x2 = t2 % width2;
				if (x2 == 0) {
					y2++;
				}
				BMP_SetPixelRGB(bmp4, x2, y2, Rbuffer32[j], Gbuffer32[j], Bbuffer32[j]);
				t2 += 1;
			}
		}
	}
	BMP_WriteFile(bmp4, decryption_file_path);
	BMP_Free(bmp3);
	BMP_Free(bmp4);

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
			rc = OQS_KEM_kyber_512_encrypt(ciphertext_512, buffer32, public_key_512);
			free(encoded_512);
			encoded_512 = b64_encode(ciphertext_512, sizeof(ciphertext_512));
			fprintf(f_encryption, "%s", encoded_512);
		}
		else if (kyber_implementation == "Kyber768") {
			rc = OQS_KEM_kyber_768_encrypt(ciphertext_768, buffer32, public_key_768);
			free(encoded_768);
			encoded_768 = b64_encode(ciphertext_768, sizeof(ciphertext_768));
			fprintf(f_encryption, "%s", encoded_768);
		}
		else {
			rc = OQS_KEM_kyber_1024_encrypt(ciphertext_1024, buffer32, public_key_1024);
			free(encoded_1024);
			encoded_1024 = b64_encode(ciphertext_1024, sizeof(ciphertext_1024));
			fprintf(f_encryption, "%s", encoded_1024);
		}
		
		printf("Encrypted %llu Bytes of %llu Bytes\tPercent done: %f\n",i+32,fileSize, 100.0 * i / fileSize);
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