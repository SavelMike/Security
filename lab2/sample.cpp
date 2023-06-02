#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#endif /* __PROGTEST__ */

// Initial context
uint64_t IV[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
		  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

// Round constants
uint64_t K[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
		  0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
		  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
		  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
		  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
		  0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
		  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
		  0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
		  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
		  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
		  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
		  0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
		  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
		  0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
		  0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
		  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};


// 80-entry message schedule array w[0..79] of 64-bit words
uint64_t W[80];

// Sha512 hash storage
uint64_t sha512[8];

uint64_t rotateRight(uint64_t x, int nBits)
{
	return (x >> nBits) | (x << (64 - nBits));
}

// Auxilary routines for SHA512 algorithm 
uint64_t Sigma0(uint64_t x)
{
	return rotateRight(x, 28) ^ rotateRight(x, 34) ^ rotateRight(x, 39); 
}

uint64_t Sigma1(uint64_t x)
{
	return rotateRight(x, 14) ^ rotateRight(x, 18) ^ rotateRight(x, 41); 
}

uint64_t sigma0(uint64_t x)
{
	// s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7) SHA512
	return rotateRight(x, 1) ^ rotateRight(x, 8) ^ (x >> 7); 
}

uint64_t sigma1(uint64_t x)
{
	// s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6) SHA512
	return rotateRight(x, 19) ^ rotateRight(x, 61) ^ (x >> 6); 
}

uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
	return (x & y) ^ ((~x) & z); 
}

uint64_t Ma(uint64_t x, uint64_t y, uint64_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

// Return true if n_bit`th bit in val is zero
bool is_zero_bit(uint64_t val, int n_bit)
{
	uint64_t mask = (uint64_t)1 << n_bit;
	val &= mask;
	
	return !val;
}

bool is_zero_bit8(uint8_t val, int n_bit)
{
	uint8_t mask = (uint8_t)1 << n_bit;
	val &= mask;
	
	return !val;
}


uint64_t byte_reverse64(uint64_t in64)
{
	uint64_t out64;
	unsigned char* in8_p = (unsigned char*)&in64;
	unsigned char* out8_p = (unsigned char*)&out64;
	int i;

	for (i = 0; i < 8; i++) {
		out8_p[i] = in8_p[7 - i];
	}

	return out64;
}

// Initilize message schedule array (W[80])
// Arg M - 1024 bit chunk (128 Byte or 16 64-bit integers)
void initW(uint64_t* M)
{
	int i;

	// Copy chunk into first 16 words w[0..15] of the message schedule array
	for (i = 0; i < 16; i++) {
		W[i] = byte_reverse64(M[i]);
	}
	
	// Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array:
	for (; i < 80; i++) {
		W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
	}
}

// Calculating SHA512 hash for \a message
//     Output: \a hash string representation of sha512 hash in hex digits
// TODO:  only works for message that is less than 112 symbols long
void SHA_512(const char* message, char* hash)
{
	uint64_t chunk[16];
	unsigned int i;
	char* chunkC = (char*)chunk;
	unsigned long long nl;
		
	// Begin with the original message of length L bits
	unsigned int len = strlen(message);
	if (len > 128 - 16 - 1) {
		printf("String is too long\n");
		exit(1);
	}
	for (i = 0; i < len; i++) {
		chunkC[i] = message[i];
	}
	
	// Append a single '1' bit
	chunkC[i++] = 128;

	// Pad with zero up to 8 byte boundary
	unsigned int n = (i + 7) & ~7;
	for (; i < n; i++) {
		chunkC[i] = 0;
	}

	// Pad with zeroes by 64 integers but 14's and 15's elements
	i /= 8;
	for (; i < 14; i++) {
		chunk[i] = 0;
	}
	
	// Length of message in bits in 2 64-bit integers
	chunk[i++] = 0;
	nl = strlen(message) * 8;
	chunk[i] = byte_reverse64(nl);
	initW(chunk);

	// Initialize hash with IV:
	for (i = 0; i < 8; i++) {
		sha512[i] = IV[i];
	}
	
	for (i = 0; i < 80; i++) {
		// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
		uint64_t S1 = Sigma1(sha512[4]);
		// ch := (e and f) xor ((not e) and g)
		uint64_t ch = Ch(sha512[4], sha512[5], sha512[6]);
		// temp1 := h + S1 + ch + k[i] + w[i]
		uint64_t temp1 = sha512[7] + S1 + ch + K[i] + W[i]; 
		// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
		uint64_t S0 = Sigma0(sha512[0]);
		// maj := (a and b) xor (a and c) xor (b and c)
		uint64_t maj = Ma(sha512[0], sha512[1], sha512[2]); 
		// temp2 := S0 + maj
		uint64_t temp2 = S0 + maj;

		sha512[7] = sha512[6];
		sha512[6] = sha512[5];
		sha512[5] = sha512[4];
		sha512[4] = sha512[3] + temp1;
		sha512[3] = sha512[2];
		sha512[2] = sha512[1];
		sha512[1] = sha512[0];
		sha512[0] = temp1 + temp2;
	}

	// Add the IV to the current hash value:
	for (i = 0; i < 8; i++) {
		sha512[i] += IV[i];
	}

	// Compose hex representation of hash
	hash[0] = 0;
	for (i = 0; i < 8; i++) {
		sprintf(hash + strlen(hash), "%016lx", sha512[i]);
	}
}

// Return true if sha512 starts with exactly \a bits zeroes
bool is_required_hash(int bits)
{
	int j;
	int k;
	bool rc;

	for (j = 0; j < 8; j++) {
		for (k = 63; k >= 0; --k) {
			rc = is_zero_bit(sha512[j], k);
			if (bits != 0) {
				// More zero bits required
				if (rc) {
					// Zero bit found
					bits--;
					continue;
				} else {
					// Not zero bit
					return false;
				}
			} else {
				if (rc) {
					// Found extra zero bit
					return false;
				} else {
					return true;
				}
			}
		}
	}

	// Only zeroes in hash
	if (bits == 0) {
		return true;
	}
	
	return false;
}

// 
int findHash (int bits, char ** message, char ** hash) {
	if (bits > 512) {
		return 0;
	}

	// Malloc memory for 111B long message
	*message = new char[112];
	// Malloc memory for 128 symbol long SHA512 hash hex representation  
	*hash = new char[129];
	
	char c;
	int n;
	int j;

	// Generate strings pattern:
	//   a, aa, aaa, ..., a(111)
	//   b, bb, bbb, ..., b(111)
	//   ...
	//   z, zz, zzz, ..., z(111)
	for (c = 'a'; c <= 'z'; c++) {
		for (n = 1; n <= 111; n++) {
			for (j = 0; j < n; j++) {
				(*message)[j] = c;
			}
			(*message)[n] = 0;
			SHA_512(*message, *hash);
			if (is_required_hash(bits)) {
				printf("message = %s; hash = %s; bits = %d\n", *message, *hash, bits);
				return 1;
			}
		}
	}

	delete [] *message;
	delete [] *hash;
	
	return 0;
}

int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
	/* TODO or use dummy implementation */
	return 1;
}

#ifndef __PROGTEST__

int checkHash(int bits, char * hexString) {
	int i;
	unsigned char c;
	unsigned char low;
	unsigned char high;
	bool rc;
	int k;
	
	for (i = 0; i < 128; i += 2) {
		// Build unsigned char of its hex representation
		if (isdigit(hexString[i + 1])) {
			low = hexString[i + 1] - '0';
		} else {
			low = hexString[i + 1] - 'a' + 10;
		}

		if (isdigit(hexString[i])) {
			high = hexString[i] - '0';
		} else {
			high = hexString[i] - 'a' + 10;
		}
		c = (high << 4) | low;
		for (k = 7; k >= 0; k--) {
			rc = is_zero_bit8(c, k);
			if (bits != 0) {
				// More zero bits required
				if (rc) {
					// Zero bit found
					bits--;
					continue;
				} else {
					// Not zero bit
					return 0;
				}
			} else {
				if (rc) {
					// Found extra zero bit
					return 0;
				} else {
					return 1;
				}
			}	
		}
	}

	return (bits == 0);
}

int main (int argc, char** argv) {	
	char * message, * hash;

	assert(findHash(512, &message, &hash) == 1);
	assert(message && hash && checkHash(512, hash));
	free(message);
	free(hash);
	assert(findHash(5, &message, &hash) == 1);
	assert(message && hash && checkHash(5, hash));
	free(message);
	free(hash);
	assert(findHash(2, &message, &hash) == 1);
	assert(message && hash && checkHash(2, hash));
	free(message);
	free(hash);
	assert(findHash(3, &message, &hash) == 1);
	assert(message && hash && checkHash(3, hash));
	free(message);
	free(hash);
	assert(findHash(-1, &message, &hash) == 0);

	return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

