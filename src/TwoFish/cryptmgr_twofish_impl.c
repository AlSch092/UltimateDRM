#include "../../include/TwoFish/cryptmgr_twofish_impl.h"

/***************************************************************************
PLATFORM.C	-- Platform-specific defines for TWOFISH code

Submitters:
Bruce Schneier, Counterpane Systems
Doug Whiting,	Hi/fn
John Kelsey,	Counterpane Systems
Chris Hall,		Counterpane Systems
David Wagner,	UC Berkeley

Code Author:		Doug Whiting,	Hi/fn

Version  1.00		April 1998

Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.

Notes:
*	Tab size is set to 4 characters in this file

***************************************************************************/

/* use intrinsic rotate if possible */
#define	ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define	ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#if (0) && defined(__BORLANDC__) && (__BORLANDC__ >= 0x462)
#error "!!!This does not work for some reason!!!"
#include	<stdlib.h>					/* get prototype for _lrotl() , _lrotr() */
#pragma inline __lrotl__
#pragma inline __lrotr__
#undef	ROL								/* get rid of inefficient definitions */
#undef	ROR
#define	ROL(x,n)	__lrotl__(x,n)		/* use compiler intrinsic rotations */
#define	ROR(x,n)	__lrotr__(x,n)
#endif

#ifdef _MSC_VER
#include	<stdlib.h>					/* get prototypes for rotation functions */
#undef	ROL
#undef	ROR
#pragma intrinsic(_lrotl,_lrotr)		/* use intrinsic compiler rotations */
#define	ROL(x,n)	_lrotl(x,n)			
#define	ROR(x,n)	_lrotr(x,n)
#endif

#ifndef _M_IX86
#ifdef	__BORLANDC__
#define	_M_IX86					300		/* make sure this is defined for Intel CPUs */
#endif
#endif

#ifdef _M_IX86
#define		LittleEndian		1		/* e.g., 1 for Pentium, 0 for 68K */
#define		ALIGN32				0		/* need dword alignment? (no for Pentium) */
#else	/* non-Intel platforms */
#define		LittleEndian		0		/* (assume big endian */
#define		ALIGN32				1		/* (assume need alignment for non-Intel) */
#endif

#if LittleEndian
#define		Bswap(x)			(x)		/* NOP for little-endian machines */
#define		ADDR_XOR			0		/* NOP for little-endian machines */
#else
#define		Bswap(x)			((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
#define		ADDR_XOR			3		/* convert byte address in dword */
#endif

/*	Macros for extracting bytes from dwords (correct for endianness) */
#define	_b(x,N)	(((BYTE *)&x)[((N) & 3) ^ ADDR_XOR]) /* pick bytes out of a dword */

#define		b0(x)			_b(x,0)		/* extract LSB of DWORD */
#define		b1(x)			_b(x,1)
#define		b2(x)			_b(x,2)
#define		b3(x)			_b(x,3)		/* extract MSB of DWORD */












/* aes.h */
/* AES Cipher header file for ANSI C Submissions
Lawrence E. Bassham III
Computer Security Division
National Institute of Standards and Technology

This sample is to assist implementers developing to the
Cryptographic API Profile for AES Candidate Algorithm Submissions.
Please consult this document as a cross-reference.

ANY CHANGES, WHERE APPROPRIATE, TO INFORMATION PROVIDED IN THIS FILE
MUST BE DOCUMENTED. CHANGES ARE ONLY APPROPRIATE WHERE SPECIFIED WITH
THE STRING "CHANGE POSSIBLE". FUNCTION CALLS AND THEIR PARAMETERS
CANNOT BE CHANGED. STRUCTURES CAN BE ALTERED TO ALLOW IMPLEMENTERS TO
INCLUDE IMPLEMENTATION SPECIFIC INFORMATION.
*/

/* Includes:
Standard include files
*/

#include	<stdio.h>

/*	Defines:
Add any additional defines you need
*/

#define 	DIR_ENCRYPT 	0 		/* Are we encrpyting? */
#define 	DIR_DECRYPT 	1 		/* Are we decrpyting? */
#define 	MODE_ECB 		1 		/* Are we ciphering in ECB mode? */
#define 	MODE_CBC 		2 		/* Are we ciphering in CBC mode? */
#define 	MODE_CFB1 		3 		/* Are we ciphering in 1-bit CFB mode? */

#define 	TRUE 			1
#define 	FALSE 			0

#define 	BAD_KEY_DIR 		-1	/* Key direction is invalid (unknown value) */
#define 	BAD_KEY_MAT 		-2	/* Key material not of correct length */
#define 	BAD_KEY_INSTANCE 	-3	/* Key passed is not valid */
#define 	BAD_CIPHER_MODE 	-4 	/* Params struct passed to cipherInit invalid */
#define 	BAD_CIPHER_STATE 	-5 	/* Cipher in wrong state (e.g., not initialized) */

/* CHANGE POSSIBLE: inclusion of algorithm specific defines */
/* TWOFISH specific definitions */
#define		MAX_KEY_SIZE		64	/* # of ASCII chars needed to represent a key */
#define		MAX_IV_SIZE			16	/* # of bytes needed to represent an IV */
#define		BAD_INPUT_LEN		-6	/* inputLen not a multiple of block size */
#define		BAD_PARAMS			-7	/* invalid parameters */
#define		BAD_IV_MAT			-8	/* invalid IV text */
#define		BAD_ENDIAN			-9	/* incorrect endianness define */
#define		BAD_ALIGN32			-10	/* incorrect 32-bit alignment */

#define		BLOCK_SIZE			128	/* number of bits per block */
#define		MAX_ROUNDS			 16	/* max # rounds (for allocating subkey array) */
#define		ROUNDS_128			 16	/* default number of rounds for 128-bit keys*/
#define		ROUNDS_192			 16	/* default number of rounds for 192-bit keys*/
#define		ROUNDS_256			 16	/* default number of rounds for 256-bit keys*/
#define		MAX_KEY_BITS		256	/* max number of bits of key */
#define		MIN_KEY_BITS		128	/* min number of bits of key (zero pad) */
#define		VALID_SIG	 0x48534946	/* initialization signature ('FISH') */
#define		MCT_OUTER			400	/* MCT outer loop */
#define		MCT_INNER		  10000	/* MCT inner loop */
#define		REENTRANT			  1	/* nonzero forces reentrant code (slightly slower) */

#define		INPUT_WHITEN		0	/* subkey array indices */
#define		OUTPUT_WHITEN		( INPUT_WHITEN + BLOCK_SIZE/32)
#define		ROUND_SUBKEYS		(OUTPUT_WHITEN + BLOCK_SIZE/32)	/* use 2 * (# rounds) */
#define		TOTAL_SUBKEYS		(ROUND_SUBKEYS + 2*MAX_ROUNDS)





#if BLOCK_SIZE == 128			/* optimize block copies */
#define		Copy1(d,s,N)	((DWORD *)(d))[N] = ((DWORD *)(s))[N]
#define		BlockCopy(d,s)	{ Copy1(d,s,0);Copy1(d,s,1);Copy1(d,s,2);Copy1(d,s,3); }
#else
#define		BlockCopy(d,s)	{ memcpy(d,s,BLOCK_SIZE/8); }
#endif






/***************************************************************************
TABLE.H	-- Tables, macros, constants for Twofish S-boxes and MDS matrix

Submitters:
Bruce Schneier, Counterpane Systems
Doug Whiting,	Hi/fn
John Kelsey,	Counterpane Systems
Chris Hall,		Counterpane Systems
David Wagner,	UC Berkeley

Code Author:		Doug Whiting,	Hi/fn

Version  1.00		April 1998

Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.

Notes:
*	Tab size is set to 4 characters in this file
*	These definitions should be used in optimized and unoptimized
versions to insure consistency.

***************************************************************************/

/* for computing subkeys */
#define	SK_STEP			0x02020202u
#define	SK_BUMP			0x01010101u
#define	SK_ROTL			9

/* Reed-Solomon code parameters: (12,8) reversible code
g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
where a = primitive root of field generator 0x14D */
#define	RS_GF_FDBK		0x14D		/* field generator */
#define	RS_rem(x)		\
	{ BYTE  b  =   x >> 24;													 \
	  DWORD g2 = ((b << 1) ^ ((b & 0x80) ? RS_GF_FDBK : 0 )) & 0xFF;		 \
	  DWORD g3 = ((b >> 1) & 0x7F) ^ ((b & 1) ? RS_GF_FDBK >> 1 : 0 ) ^ g2 ; \
	  x = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;				 \
	}

/*	Macros for the MDS matrix
*	The MDS matrix is (using primitive polynomial 169):
*      01  EF  5B  5B
*      5B  EF  EF  01
*      EF  5B  01  EF
*      EF  01  EF  5B
*----------------------------------------------------------------
* More statistical properties of this matrix (from MDS.EXE output):
*
* Min Hamming weight (one byte difference) =  8. Max=26.  Total =  1020.
* Prob[8]:      7    23    42    20    52    95    88    94   121   128    91
*             102    76    41    24     8     4     1     3     0     0     0
* Runs[8]:      2     4     5     6     7     8     9    11
* MSBs[8]:      1     4    15     8    18    38    40    43
* HW= 8: 05040705 0A080E0A 14101C14 28203828 50407050 01499101 A080E0A0
* HW= 9: 04050707 080A0E0E 10141C1C 20283838 40507070 80A0E0E0 C6432020 07070504
*        0E0E0A08 1C1C1410 38382820 70705040 E0E0A080 202043C6 05070407 0A0E080E
*        141C101C 28382038 50704070 A0E080E0 4320C620 02924B02 089A4508
* Min Hamming weight (two byte difference) =  3. Max=28.  Total = 390150.
* Prob[3]:      7    18    55   149   270   914  2185  5761 11363 20719 32079
*           43492 51612 53851 52098 42015 31117 20854 11538  6223  2492  1033
* MDS OK, ROR:   6+  7+  8+  9+ 10+ 11+ 12+ 13+ 14+ 15+ 16+
*               17+ 18+ 19+ 20+ 21+ 22+ 23+ 24+ 25+ 26+
*/
#define	MDS_GF_FDBK		0x169	/* primitive polynomial for GF(256)*/
#define	LFSR1(x) ( ((x) >> 1)  ^ (((x) & 0x01) ?   MDS_GF_FDBK/2 : 0))
#define	LFSR2(x) ( ((x) >> 2)  ^ (((x) & 0x02) ?   MDS_GF_FDBK/2 : 0)  \
							   ^ (((x) & 0x01) ?   MDS_GF_FDBK/4 : 0))

#define	Mx_1(x) ((DWORD)  (x))		/* force result to dword so << will work */
#define	Mx_X(x) ((DWORD) ((x) ^            LFSR2(x)))	/* 5B */
#define	Mx_Y(x) ((DWORD) ((x) ^ LFSR1(x) ^ LFSR2(x)))	/* EF */

#define	M00		Mul_1
#define	M01		Mul_Y
#define	M02		Mul_X
#define	M03		Mul_X

#define	M10		Mul_X
#define	M11		Mul_Y
#define	M12		Mul_Y
#define	M13		Mul_1

#define	M20		Mul_Y
#define	M21		Mul_X
#define	M22		Mul_1
#define	M23		Mul_Y

#define	M30		Mul_Y
#define	M31		Mul_1
#define	M32		Mul_Y
#define	M33		Mul_X

#define	Mul_1	Mx_1
#define	Mul_X	Mx_X
#define	Mul_Y	Mx_Y

/*	Define the fixed p0/p1 permutations used in keyed S-box lookup.
By changing the following constant definitions for P_ij, the S-boxes will
automatically get changed in all the Twofish source code. Note that P_i0 is
the "outermost" 8x8 permutation applied.  See the f32() function to see
how these constants are to be  used.
*/
#define	P_00	1					/* "outermost" permutation */
#define	P_01	0
#define	P_02	0
#define	P_03	(P_01^1)			/* "extend" to larger key sizes */
#define	P_04	1

#define	P_10	0
#define	P_11	0
#define	P_12	1
#define	P_13	(P_11^1)
#define	P_14	0

#define	P_20	1
#define	P_21	1
#define	P_22	0
#define	P_23	(P_21^1)
#define	P_24	0

#define	P_30	0
#define	P_31	1
#define	P_32	1
#define	P_33	(P_31^1)
#define	P_34	1

#define	p8(N)	P8x8[P_##N]			/* some syntax shorthand */

/* fixed 8x8 permutation S-boxes */

/***********************************************************************
*  07:07:14  05/30/98  [4x4]  TestCnt=256. keySize=128. CRC=4BD14D9E.
* maxKeyed:  dpMax = 18. lpMax =100. fixPt =  8. skXor =  0. skDup =  6.
* log2(dpMax[ 6..18])=   --- 15.42  1.33  0.89  4.05  7.98 12.05
* log2(lpMax[ 7..12])=  9.32  1.01  1.16  4.23  8.02 12.45
* log2(fixPt[ 0.. 8])=  1.44  1.44  2.44  4.06  6.01  8.21 11.07 14.09 17.00
* log2(skXor[ 0.. 0])
* log2(skDup[ 0.. 6])=   ---  2.37  0.44  3.94  8.36 13.04 17.99
***********************************************************************/
static const BYTE P8x8[2][256] =
{
	/*  p0:   */
	/*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   1  1  1  0.         */
	/* 817D6F320B59ECA4.ECB81235F4A6709D.BA5E6D90C8F32471.D7F4126E9B3085CA. */
	/* Karnaugh maps:
	*  0111 0001 0011 1010. 0001 1001 1100 1111. 1001 1110 0011 1110. 1101 0101 1111 1001.
	*  0101 1111 1100 0100. 1011 0101 0010 0000. 0101 1000 1100 0101. 1000 0111 0011 0010.
	*  0000 1001 1110 1101. 1011 1000 1010 0011. 0011 1001 0101 0000. 0100 0010 0101 1011.
	*  0111 0100 0001 0110. 1000 1011 1110 1001. 0011 0011 1001 1101. 1101 0101 0000 1100.
	*/
	0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
	0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
	0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
	0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
	0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
	0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
	0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
	0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
	0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
	0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
	0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
	0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
	0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
	0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
	0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
	0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
	0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
	0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
	0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
	0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
	0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
	0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
	0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
	0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
	0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
	0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
	0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
	0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
	0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
	0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
	0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
	0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
	/*  p1:   */
	/*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   2  0  0  1.         */
	/* 28BDF76E31940AC5.1E2B4C376DA5F908.4C75169A0ED82B3F.B951C3DE647F208A. */
	/* Karnaugh maps:
	*  0011 1001 0010 0111. 1010 0111 0100 0110. 0011 0001 1111 0100. 1111 1000 0001 1100.
	*  1100 1111 1111 1010. 0011 0011 1110 0100. 1001 0110 0100 0011. 0101 0110 1011 1011.
	*  0010 0100 0011 0101. 1100 1000 1000 1110. 0111 1111 0010 0110. 0000 1010 0000 0011.
	*  1101 1000 0010 0001. 0110 1001 1110 0101. 0001 0100 0101 0111. 0011 1011 1111 0010.
	*/
	0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
	0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
	0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
	0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
	0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
	0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
	0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
	0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
	0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
	0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
	0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
	0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
	0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
	0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
	0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
	0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
	0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
	0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
	0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
	0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
	0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
	0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
	0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
	0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
	0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
	0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
	0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
	0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
	0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
	0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
	0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
	0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
};








/***************************************************************************
TWOFISH.C	-- C API calls for TWOFISH AES submission

Submitters:
Bruce Schneier, Counterpane Systems
Doug Whiting,	Hi/fn
John Kelsey,	Counterpane Systems
Chris Hall,		Counterpane Systems
David Wagner,	UC Berkeley

Code Author:		Doug Whiting,	Hi/fn

Version  1.00		April 1998

Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.

Notes:
*	Pedagogical version (non-optimized)
*	Tab size is set to 4 characters in this file

***************************************************************************/



/*
+*****************************************************************************
*			Constants/Macros/Tables
-****************************************************************************/

#define		VALIDATE_PARMS	1		/* nonzero --> check all parameters */
#define		FEISTEL			0		/* nonzero --> use Feistel version (slow) */





#define	P0_USED		0x01
#define	P1_USED		0x02
#define	B0_USED		0x04
#define	B1_USED		0x08
#define	B2_USED		0x10
#define	B3_USED		0x20
#define	ALL_USED	0x3F

/* number of rounds for various key sizes: 128, 192, 256 */
static const int	numRounds[4] = { 0,ROUNDS_128,ROUNDS_192,ROUNDS_256 };







/*
+*****************************************************************************
*
* Function Name:	ParseHexDword
*
* Function:			Parse ASCII hex nibbles and fill in key/iv dwords
*
* Arguments:		bit			=	# bits to read
*					srcTxt		=	ASCII source
*					d			=	ptr to dwords to fill in
*					dstTxt		=	where to make a copy of ASCII source
*									(NULL ok)
*
* Return:			Zero if no error.  Nonzero --> invalid hex or length
*
* Notes:  Note that the parameter d is a DWORD array, not a byte array.
*	This routine is coded to work both for little-endian and big-endian
*	architectures.  The character stream is interpreted as a LITTLE-ENDIAN
*	byte stream, since that is how the Pentium works, but the conversion
*	happens automatically below.
*
-****************************************************************************/
static int ParseHexDword(int bits, const char *srcTxt, DWORD *d, char *dstTxt)
{
	int i;
	DWORD b;
	char c;
#if ALIGN32
	char alignDummy[3];	/* keep dword alignment */
#endif

	union	/* make sure LittleEndian is defined correctly */
	{
		BYTE  b[4];
		DWORD d[1];
	} v;
	v.d[0] = 1;
	if (v.b[0 ^ ADDR_XOR] != 1)	/* sanity check on compile-time switch */
		return BAD_ENDIAN;

#if VALIDATE_PARMS
#if ALIGN32
	if (((int)d) & 3)
		return BAD_ALIGN32;
#endif
#endif

	for (i = 0; i * 32<bits; i++)
		d[i] = 0;					/* first, zero the field */

	for (i = 0; i * 4<bits; i++)		/* parse one nibble at a time */
	{						/* case out the hexadecimal characters */
		c = srcTxt[i];
		if (dstTxt) dstTxt[i] = c;
		if ((c >= '0') && (c <= '9'))
			b = c - '0';
		else if ((c >= 'a') && (c <= 'f'))
			b = c - 'a' + 10;
		else if ((c >= 'A') && (c <= 'F'))
			b = c - 'A' + 10;
		else
			return BAD_KEY_MAT;	/* invalid hex character */
								/* works for big and little endian! */
		d[i / 8] |= b << (4 * ((i ^ 1) & 7));
	}

	return 0;					/* no error */
}


/*
+*****************************************************************************
*
* Function Name:	f32
*
* Function:			Run four bytes through keyed S-boxes and apply MDS matrix
*
* Arguments:		x			=	input to f function
*					k32			=	pointer to key dwords
*					keyLen		=	total key length (k32 --> keyLey/2 bits)
*
* Return:			The output of the keyed permutation applied to x.
*
* Notes:
*	This function is a keyed 32-bit permutation.  It is the major building
*	block for the Twofish round function, including the four keyed 8x8
*	permutations and the 4x4 MDS matrix multiply.  This function is used
*	both for generating round subkeys and within the round function on the
*	block being encrypted.
*
*	This version is fairly slow and pedagogical, although a smartcard would
*	probably perform the operation exactly this way in firmware.   For
*	ultimate performance, the entire operation can be completed with four
*	lookups into four 256x32-bit tables, with three dword xors.
*
*	The MDS matrix is defined in TABLE.H.  To multiply by Mij, just use the
*	macro Mij(x).
*
-****************************************************************************/
static DWORD f32(DWORD x, const DWORD *k32, int keyLen)
{
	BYTE  b[4];

	/* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
	/* Note that each byte goes through a different combination of S-boxes.*/

	*((DWORD *)b) = Bswap(x);	/* make b[0] = LSB, b[3] = MSB */
	switch (((keyLen + 63) / 64) & 3)
	{
	case 0:		/* 256 bits of key */
		b[0] = p8(04)[b[0]] ^ b0(k32[3]);
		b[1] = p8(14)[b[1]] ^ b1(k32[3]);
		b[2] = p8(24)[b[2]] ^ b2(k32[3]);
		b[3] = p8(34)[b[3]] ^ b3(k32[3]);
		/* fall thru, having pre-processed b[0]..b[3] with k32[3] */
	case 3:		/* 192 bits of key */
		b[0] = p8(03)[b[0]] ^ b0(k32[2]);
		b[1] = p8(13)[b[1]] ^ b1(k32[2]);
		b[2] = p8(23)[b[2]] ^ b2(k32[2]);
		b[3] = p8(33)[b[3]] ^ b3(k32[2]);
		/* fall thru, having pre-processed b[0]..b[3] with k32[2] */
	case 2:		/* 128 bits of key */
		b[0] = p8(00)[p8(01)[p8(02)[b[0]] ^ b0(k32[1])] ^ b0(k32[0])];
		b[1] = p8(10)[p8(11)[p8(12)[b[1]] ^ b1(k32[1])] ^ b1(k32[0])];
		b[2] = p8(20)[p8(21)[p8(22)[b[2]] ^ b2(k32[1])] ^ b2(k32[0])];
		b[3] = p8(30)[p8(31)[p8(32)[b[3]] ^ b3(k32[1])] ^ b3(k32[0])];
	}

	/* Now perform the MDS matrix multiply inline. */
	return	((M00(b[0]) ^ M01(b[1]) ^ M02(b[2]) ^ M03(b[3]))) ^
		((M10(b[0]) ^ M11(b[1]) ^ M12(b[2]) ^ M13(b[3])) << 8) ^
		((M20(b[0]) ^ M21(b[1]) ^ M22(b[2]) ^ M23(b[3])) << 16) ^
		((M30(b[0]) ^ M31(b[1]) ^ M32(b[2]) ^ M33(b[3])) << 24);
}

/*
+*****************************************************************************
*
* Function Name:	RS_MDS_Encode
*
* Function:			Use (12,8) Reed-Solomon code over GF(256) to produce
*					a key S-box dword from two key material dwords.
*
* Arguments:		k0	=	1st dword
*					k1	=	2nd dword
*
* Return:			Remainder polynomial generated using RS code
*
* Notes:
*	Since this computation is done only once per reKey per 64 bits of key,
*	the performance impact of this routine is imperceptible. The RS code
*	chosen has "simple" coefficients to allow smartcard/hardware implementation
*	without lookup tables.
*
-****************************************************************************/
static DWORD RS_MDS_Encode(DWORD k0, DWORD k1)
{
	int i, j;
	DWORD r;

	for (i = r = 0; i<2; i++)
	{
		r ^= (i) ? k0 : k1;			/* merge in 32 more key bits */
		for (j = 0; j<4; j++)			/* shift one byte at a time */
			RS_rem(r);
	}
	return r;
}

/*
+*****************************************************************************
*
* Function Name:	reKey
*
* Function:			Initialize the Twofish key schedule from key32
*
* Arguments:		key			=	ptr to keyInstance to be initialized
*
* Return:			TRUE on success
*
* Notes:
*	Here we precompute all the round subkeys, although that is not actually
*	required.  For example, on a smartcard, the round subkeys can
*	be generated on-the-fly	using f32()
*
-****************************************************************************/
int twofish_reKey(twofish_keyInstance *key)
{
	int		i, k64Cnt;
	int		keyLen = key->keyLen;
	int		subkeyCnt = ROUND_SUBKEYS + 2 * key->numRounds;
	DWORD	A, B;
	DWORD	k32e[MAX_KEY_BITS / 64], k32o[MAX_KEY_BITS / 64]; /* even/odd key dwords */

#if VALIDATE_PARMS
#if ALIGN32
	if ((((int)key) & 3) || (((int)key->key32) & 3))
		return BAD_ALIGN32;
#endif
	if ((key->keyLen % 64) || (key->keyLen < MIN_KEY_BITS))
		return BAD_KEY_INSTANCE;
	if (subkeyCnt > TOTAL_SUBKEYS)
		return BAD_KEY_INSTANCE;
#endif

	k64Cnt = (keyLen + 63) / 64;		/* round up to next multiple of 64 bits */
	for (i = 0; i<k64Cnt; i++)
	{						/* split into even/odd key dwords */
		k32e[i] = key->key32[2 * i];
		k32o[i] = key->key32[2 * i + 1];
		/* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
		key->sboxKeys[k64Cnt - 1 - i] = RS_MDS_Encode(k32e[i], k32o[i]); /* reverse order */
	}

	for (i = 0; i<subkeyCnt / 2; i++)					/* compute round subkeys for PHT */
	{
		A = f32(i*SK_STEP, k32e, keyLen);	/* A uses even key dwords */
		B = f32(i*SK_STEP + SK_BUMP, k32o, keyLen);	/* B uses odd  key dwords */
		B = ROL(B, 8);
		key->subKeys[2 * i] = A + B;			/* combine with a PHT */
		key->subKeys[2 * i + 1] = ROL(A + 2 * B, SK_ROTL);
	}

	return TRUE;
}
/*
+*****************************************************************************
*
* Function Name:	makeKey
*
* Function:			Initialize the Twofish key schedule
*
* Arguments:		key			=	ptr to keyInstance to be initialized
*					direction	=	DIR_ENCRYPT or DIR_DECRYPT
*					keyLen		=	# bits of key text at *keyMaterial
*					keyMaterial	=	ptr to hex ASCII chars representing key bits
*
* Return:			TRUE on success
*					else error code (e.g., BAD_KEY_DIR)
*
* Notes:
*	This parses the key bits from keyMaterial.  No crypto stuff happens here.
*	The function reKey() is called to actually build the key schedule after
*	the keyMaterial has been parsed.
*
-****************************************************************************/
int twofish_makeKey(twofish_keyInstance *key, BYTE direction, int keyLen, const char *keyMaterial)
{
	int i;

#if VALIDATE_PARMS				/* first, sanity check on parameters */
	if (key == NULL)
		return BAD_KEY_INSTANCE;/* must have a keyInstance to initialize */
	if ((direction != DIR_ENCRYPT) && (direction != DIR_DECRYPT))
		return BAD_KEY_DIR;		/* must have valid direction */
	if ((keyLen > MAX_KEY_BITS) || (keyLen < 8))
		return BAD_KEY_MAT;		/* length must be valid */
	if (keyMaterial == NULL)
		return BAD_KEY_MAT;		/* must have some data to work with */
	key->keySig = VALID_SIG;	/* show that we are initialized */
#if ALIGN32
	if ((((int)key) & 3) || (((int)key->key32) & 3))
		return BAD_ALIGN32;
#endif
#endif

	key->direction = direction;	/* set our cipher direction */
	key->keyLen = (keyLen + 63) & ~63;		/* round up to multiple of 64 */
	key->numRounds = numRounds[(keyLen - 1) / 64];
	for (i = 0; i<MAX_KEY_BITS / 32; i++)	/* zero unused bits */
		key->key32[i] = 0;

	if (ParseHexDword(keyLen, keyMaterial, key->key32, key->keyMaterial))
		return BAD_KEY_MAT;

	key->keyMaterial[MAX_KEY_SIZE] = 0;	/* terminate ASCII string */

	return twofish_reKey(key);			/* generate round subkeys */
}


/*
+*****************************************************************************
*
* Function Name:	cipherInit
*
* Function:			Initialize the Twofish cipher in a given mode
*
* Arguments:		cipher		=	ptr to cipherInstance to be initialized
*					mode		=	MODE_ECB, MODE_CBC, or MODE_CFB1
*					IV			=	ptr to hex ASCII test representing IV bytes
*
* Return:			TRUE on success
*					else error code (e.g., BAD_CIPHER_MODE)
*
-****************************************************************************/
int twofish_cipherInit(twofish_cipherInstance *cipher, BYTE mode, const char *IV)
{
	int i;
#if VALIDATE_PARMS				/* first, sanity check on parameters */
	if (cipher == NULL)
		return BAD_PARAMS;		/* must have a cipherInstance to initialize */
	if ((mode != MODE_ECB) && (mode != MODE_CBC) && (mode != MODE_CFB1))
		return BAD_CIPHER_MODE;	/* must have valid cipher mode */
	if ((mode != MODE_ECB) && (IV == NULL))
		return BAD_PARAMS;		/* must have IV for CBC and CFB modes */
	cipher->cipherSig = VALID_SIG;
#if ALIGN32
	if ((((int)cipher) & 3) || (((int)cipher->IV) & 3) || (((int)cipher->iv32) & 3))
		return BAD_ALIGN32;
#endif
#endif

	if (mode != MODE_ECB)		/* parse the IV */
	{
		if (ParseHexDword(BLOCK_SIZE, IV, cipher->iv32, NULL))
			return BAD_IV_MAT;
		for (i = 0; i<BLOCK_SIZE / 32; i++)	/* make byte-oriented copy for CFB1 */
			((DWORD *)cipher->IV)[i] = Bswap(cipher->iv32[i]);
	}

	cipher->mode = mode;

	return TRUE;
}

/*
+*****************************************************************************
*
* Function Name:	blockEncrypt
*
* Function:			Encrypt block(s) of data using Twofish
*
* Arguments:		cipher		=	ptr to already initialized cipherInstance
*					key			=	ptr to already initialized keyInstance
*					input		=	ptr to data blocks to be encrypted
*					inputLen	=	# bits to encrypt (multiple of blockSize)
*					outBuffer	=	ptr to where to put encrypted blocks
*
* Return:			# bits ciphered (>= 0)
*					else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*		 If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*		 an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block
*		 sizes can be supported.
*
-****************************************************************************/
int twofish_blockEncrypt(twofish_cipherInstance *cipher, twofish_keyInstance *key, const BYTE *input,
	int inputLen, BYTE *outBuffer)
{
	int   i, n, r;					/* loop variables */
	DWORD x[BLOCK_SIZE / 32];			/* block being encrypted */
	DWORD t0, t1, tmp;				/* temp variables */
	int	  rounds = key->numRounds;	/* number of rounds */
	BYTE  bit, ctBit, carry;			/* temps for CFB */
#if ALIGN32
	BYTE alignDummy;				/* keep 32-bit variable alignment on stack */
#endif

#if VALIDATE_PARMS
	if ((cipher == NULL) || (cipher->cipherSig != VALID_SIG))
		return BAD_CIPHER_STATE;
	if ((key == NULL) || (key->keySig != VALID_SIG))
		return BAD_KEY_INSTANCE;
	if ((rounds < 2) || (rounds > MAX_ROUNDS) || (rounds & 1))
		return BAD_KEY_INSTANCE;
	if ((cipher->mode != MODE_CFB1) && (inputLen % BLOCK_SIZE))
		return BAD_INPUT_LEN;
#if ALIGN32
	if ((((int)cipher) & 3) || (((int)key) & 3) ||
		(((int)input) & 3) || (((int)outBuffer) & 3))
		return BAD_ALIGN32;
#endif
#endif

	if (cipher->mode == MODE_CFB1)
	{	/* use recursion here to handle CFB, one block at a time */
		cipher->mode = MODE_ECB;	/* do encryption in ECB */
		for (n = 0; n<inputLen; n++)
		{
			twofish_blockEncrypt(cipher, key, cipher->IV, BLOCK_SIZE, (BYTE *)x);
			bit = 0x80 >> (n & 7);/* which bit position in byte */
			ctBit = (input[n / 8] & bit) ^ ((((BYTE *)x)[0] & 0x80) >> (n & 7));
			outBuffer[n / 8] = (outBuffer[n / 8] & ~bit) | ctBit;
			carry = ctBit >> (7 - (n & 7));
			for (i = BLOCK_SIZE / 8 - 1; i >= 0; i--)
			{
				bit = cipher->IV[i] >> 7;	/* save next "carry" from shift */
				cipher->IV[i] = (cipher->IV[i] << 1) ^ carry;
				carry = bit;
			}
		}
		cipher->mode = MODE_CFB1;	/* restore mode for next time */
		return inputLen;
	}

	/* here for ECB, CBC modes */
	for (n = 0; n<inputLen; n += BLOCK_SIZE, input += BLOCK_SIZE / 8, outBuffer += BLOCK_SIZE / 8)
	{
		for (i = 0; i<BLOCK_SIZE / 32; i++)	/* copy in the block, add whitening */
		{
			x[i] = Bswap(((DWORD *)input)[i]) ^ key->subKeys[INPUT_WHITEN + i];
			if (cipher->mode == MODE_CBC)
				x[i] ^= cipher->iv32[i];
		}

		for (r = 0; r<rounds; r++)			/* main Twofish encryption loop */
		{
#if FEISTEL
			t0 = f32(ROR(x[0], (r + 1) / 2), key->sboxKeys, key->keyLen);
			t1 = f32(ROL(x[1], 8 + (r + 1) / 2), key->sboxKeys, key->keyLen);
			/* PHT, round keys */
			x[2] ^= ROL(t0 + t1 + key->subKeys[ROUND_SUBKEYS + 2 * r], r / 2);
			x[3] ^= ROR(t0 + 2 * t1 + key->subKeys[ROUND_SUBKEYS + 2 * r + 1], (r + 2) / 2);
#else
			t0 = f32(x[0], key->sboxKeys, key->keyLen);
			t1 = f32(ROL(x[1], 8), key->sboxKeys, key->keyLen);

			x[3] = ROL(x[3], 1);
			x[2] ^= t0 + t1 + key->subKeys[ROUND_SUBKEYS + 2 * r]; /* PHT, round keys */
			x[3] ^= t0 + 2 * t1 + key->subKeys[ROUND_SUBKEYS + 2 * r + 1];
			x[2] = ROR(x[2], 1);
#endif
			if (r < rounds - 1)						/* swap for next round */
			{
				tmp = x[0]; x[0] = x[2]; x[2] = tmp;
				tmp = x[1]; x[1] = x[3]; x[3] = tmp;
			}
		}
#if FEISTEL
		x[0] = ROR(x[0], 8);                     /* "final permutation" */
		x[1] = ROL(x[1], 8);
		x[2] = ROR(x[2], 8);
		x[3] = ROL(x[3], 8);
#endif
		for (i = 0; i<BLOCK_SIZE / 32; i++)	/* copy out, with whitening */
		{
			((DWORD *)outBuffer)[i] = Bswap(x[i] ^ key->subKeys[OUTPUT_WHITEN + i]);
			if (cipher->mode == MODE_CBC)
				cipher->iv32[i] = Bswap(((DWORD *)outBuffer)[i]);
		}
	}

	return inputLen;
}

/*
+*****************************************************************************
*
* Function Name:	blockDecrypt
*
* Function:			Decrypt block(s) of data using Twofish
*
* Arguments:		cipher		=	ptr to already initialized cipherInstance
*					key			=	ptr to already initialized keyInstance
*					input		=	ptr to data blocks to be decrypted
*					inputLen	=	# bits to encrypt (multiple of blockSize)
*					outBuffer	=	ptr to where to put decrypted blocks
*
* Return:			# bits ciphered (>= 0)
*					else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*		 If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*		 an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block
*		 sizes can be supported.
*
-****************************************************************************/
int twofish_blockDecrypt(twofish_cipherInstance *cipher, twofish_keyInstance *key, const BYTE *input,
	int inputLen, BYTE *outBuffer)
{
	int   i, n, r;					/* loop counters */
	DWORD x[BLOCK_SIZE / 32];			/* block being encrypted */
	DWORD t0, t1;					/* temp variables */
	int	  rounds = key->numRounds;	/* number of rounds */
	BYTE  bit, ctBit, carry;			/* temps for CFB */
#if ALIGN32
	BYTE alignDummy;				/* keep 32-bit variable alignment on stack */
#endif

#if VALIDATE_PARMS
	if ((cipher == NULL) || (cipher->cipherSig != VALID_SIG))
		return BAD_CIPHER_STATE;
	if ((key == NULL) || (key->keySig != VALID_SIG))
		return BAD_KEY_INSTANCE;
	if ((rounds < 2) || (rounds > MAX_ROUNDS) || (rounds & 1))
		return BAD_KEY_INSTANCE;
	if ((cipher->mode != MODE_CFB1) && (inputLen % BLOCK_SIZE))
		return BAD_INPUT_LEN;
#if ALIGN32
	if ((((int)cipher) & 3) || (((int)key) & 3) ||
		(((int)input) & 3) || (((int)outBuffer) & 3))
		return BAD_ALIGN32;
#endif
#endif

	if (cipher->mode == MODE_CFB1)
	{	/* use blockEncrypt here to handle CFB, one block at a time */
		cipher->mode = MODE_ECB;	/* do encryption in ECB */
		for (n = 0; n<inputLen; n++)
		{
			twofish_blockEncrypt(cipher, key, cipher->IV, BLOCK_SIZE, (BYTE *)x);
			bit = 0x80 >> (n & 7);
			ctBit = input[n / 8] & bit;
			outBuffer[n / 8] = (outBuffer[n / 8] & ~bit) |
				(ctBit ^ ((((BYTE *)x)[0] & 0x80) >> (n & 7)));
			carry = ctBit >> (7 - (n & 7));
			for (i = BLOCK_SIZE / 8 - 1; i >= 0; i--)
			{
				bit = cipher->IV[i] >> 7;	/* save next "carry" from shift */
				cipher->IV[i] = (cipher->IV[i] << 1) ^ carry;
				carry = bit;
			}
		}
		cipher->mode = MODE_CFB1;	/* restore mode for next time */
		return inputLen;
	}

	/* here for ECB, CBC modes */
	for (n = 0; n<inputLen; n += BLOCK_SIZE, input += BLOCK_SIZE / 8, outBuffer += BLOCK_SIZE / 8)
	{
		for (i = 0; i<BLOCK_SIZE / 32; i++)	/* copy in the block, add whitening */
			x[i] = Bswap(((DWORD *)input)[i]) ^ key->subKeys[OUTPUT_WHITEN + i];

		for (r = rounds - 1; r >= 0; r--)			/* main Twofish decryption loop */
		{
			t0 = f32(x[0], key->sboxKeys, key->keyLen);
			t1 = f32(ROL(x[1], 8), key->sboxKeys, key->keyLen);

			x[2] = ROL(x[2], 1);
			x[2] ^= t0 + t1 + key->subKeys[ROUND_SUBKEYS + 2 * r]; /* PHT, round keys */
			x[3] ^= t0 + 2 * t1 + key->subKeys[ROUND_SUBKEYS + 2 * r + 1];
			x[3] = ROR(x[3], 1);

			if (r)									/* unswap, except for last round */
			{
				t0 = x[0]; x[0] = x[2]; x[2] = t0;
				t1 = x[1]; x[1] = x[3]; x[3] = t1;
			}
		}

		for (i = 0; i<BLOCK_SIZE / 32; i++)	/* copy out, with whitening */
		{
			x[i] ^= key->subKeys[INPUT_WHITEN + i];
			if (cipher->mode == MODE_CBC)
			{
				x[i] ^= cipher->iv32[i];
				cipher->iv32[i] = Bswap(((DWORD *)input)[i]);
			}
			((DWORD *)outBuffer)[i] = Bswap(x[i]);
		}
	}

	return inputLen;
}


