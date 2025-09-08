#ifndef CA_CRYPTMGR_TWOFISH_IMPL__H__
#define CA_CRYPTMGR_TWOFISH_IMPL__H__

#pragma once

typedef unsigned char BYTE;
typedef unsigned long DWORD;		/* 32-bit unsigned quantity */
typedef DWORD twofish_fullSbox[4][256];

enum
{
	TWOFISH_DIR_ENCRYPT = 0,      /* Are we encrpyting? */
	TWOFISH_DIR_DECRYPT = 1,      /* Are we decrpyting? */
};

enum
{
	TWOFISH_MODE_ECB = 1,      /* Are we ciphering in ECB mode? */
	TWOFISH_MODE_CBC = 2,      /* Are we ciphering in CBC mode? */
	TWOFISH_MODE_CFB1 = 3,      /* Are we ciphering in 1-bit CFB mode? */
};

enum
{
	TWOFISH_MAX_KEY_SIZE = 64,   /* # of ASCII chars needed to represent a key */
	TWOFISH_MAX_KEY_BITS = 256,  /* max number of bits of key */
	TWOFISH_MAX_IV_SIZE = 16,   /* # of bytes needed to represent an IV */

	TWOFISH_MAX_ROUNDS = 16,   /* max # rounds (for allocating subkey array) */
	TWOFISH_BLOCK_SIZE = 128,  /* number of bits per block */
	TWOFISH_BLOCK_BYTES = TWOFISH_BLOCK_SIZE / 8,

	TWOFISH_INPUT_WHITEN = 0,    /* subkey array indices */
	TWOFISH_OUTPUT_WHITEN = (TWOFISH_INPUT_WHITEN + TWOFISH_BLOCK_SIZE / 32),
	TWOFISH_ROUND_SUBKEYS = (TWOFISH_OUTPUT_WHITEN + TWOFISH_BLOCK_SIZE / 32), /* use 2 * (# rounds) */
	TWOFISH_TOTAL_SUBKEYS = (TWOFISH_ROUND_SUBKEYS + 2 * TWOFISH_MAX_ROUNDS),
};

/* The structure for key information */
typedef struct
{
	BYTE direction;					/* Key used for encrypting or decrypting? */

	int  keyLen;					/* Length of the key */
	char keyMaterial[TWOFISH_MAX_KEY_SIZE + 4];/* Raw key data in ASCII */

	/* Twofish-specific parameters: */
	DWORD keySig;					/* set to VALID_SIG by makeKey() */
	int	  numRounds;				/* number of rounds in cipher */
	DWORD key32[TWOFISH_MAX_KEY_BITS / 32];	/* actual key bits, in dwords */
	DWORD sboxKeys[TWOFISH_MAX_KEY_BITS / 64];/* key bits used for S-boxes */
	DWORD subKeys[TWOFISH_TOTAL_SUBKEYS];	/* round subkeys, input/output whitening bits */
	twofish_fullSbox sBox8x32;				/* fully expanded S-box */
} twofish_keyInstance;



typedef struct
{
	BYTE  mode;                         /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
	BYTE  IV[TWOFISH_MAX_IV_SIZE];      /* CFB1 iv bytes  (CBC uses iv32) */

	/* Twofish-specific parameters: */
	DWORD cipherSig;                    /* set to VALID_SIG by cipherInit() */
	DWORD iv32[TWOFISH_BLOCK_SIZE / 32];  /* CBC IV bytes arranged as dwords */
} twofish_cipherInstance;


/* Function protoypes */
int twofish_makeKey(twofish_keyInstance* key, BYTE direction, int keyLen, const char* keyMaterial);

int twofish_cipherInit(twofish_cipherInstance* cipher, BYTE mode, const char* IV);

int twofish_blockEncrypt(twofish_cipherInstance* cipher, twofish_keyInstance* key, const BYTE* input,
	int inputLen, BYTE* outBuffer);

int twofish_blockDecrypt(twofish_cipherInstance* cipher, twofish_keyInstance* key, const BYTE* input,
	int inputLen, BYTE* outBuffer);

int twofish_reKey(twofish_keyInstance* key);	/* do key schedule using modified key.keyDwords */

#endif // #ifndef CA_CRYPTMGR_TWOFISH_IMPL__H__
