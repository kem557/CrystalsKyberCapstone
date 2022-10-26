#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

 /* Cleaning up memory etc */
void cleanup_stack(uint8_t* secret_key, size_t secret_key_len,
	uint8_t* shared_secret1, uint8_t* shared_secret2,
	size_t shared_secret_len);

int main(void) {
	OQS_STATUS rc;
	uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
	uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
	uint8_t shared_secret1[OQS_KEM_kyber_768_length_shared_secret];
	uint8_t shared_secret2[OQS_KEM_kyber_768_length_shared_secret];

	// Person 1 generates public key
	rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);

	// Person 2 recieves public key from Person 1, Person 2 encapsulates public key to get ciphertext and shared secret
	rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret1, public_key);

	// Person 2 sends ciphertext to Person 1, Person 1 uses secret key to decapsulate ciphertext, recieves shared secret
	rc = OQS_KEM_kyber_768_decaps(shared_secret2, ciphertext, secret_key);

	// Compare shared secrets for similarity, 0 differences means shared secrets are the same
	int shared_secret_diff = compare_shared_secret(shared_secret1, shared_secret2, OQS_KEM_kyber_768_length_shared_secret);
	if (shared_secret_diff < 2) {
		printf("Kyber768-KEM Successful\n");
		printf("# of char differences in shared secret: ");
		printf("%d\n\n",shared_secret_diff);
	}
	else {
		printf("Kyber768-KEM Unseccessful");
		printf("# of char differences in shared secret: ");
		printf("%d", shared_secret_diff);
	}

	// clean up memory
	cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
				  shared_secret1, shared_secret2, OQS_KEM_kyber_768_length_shared_secret);

	// return
	return EXIT_SUCCESS;
}

int compare_shared_secret(uint8_t* shared_secret1, uint8_t* shared_secret2, size_t shared_secret_len) {
	int diff = 0;
	for (int i = 0; i < shared_secret_len; i++) {
		unsigned char char1 = shared_secret1[i];
		unsigned char char2 = shared_secret2[i];
		if (char1 != char2) {
			diff += 1;
		}
	}
	return abs(diff);
}

void cleanup_stack(uint8_t* secret_key, size_t secret_key_len,
	uint8_t* shared_secret1, uint8_t* shared_secret2,
	size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret1, shared_secret_len);
	OQS_MEM_cleanse(shared_secret2, shared_secret_len);
}
