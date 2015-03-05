/*
 * desutils.c - DES Utilities Functions for DES Test Program
 * These are the des utility functions from Section V of Schneier's
 * classic tome, "Applied Cryptography, Second Edition: Protocols,
 * Algorithms, and Source Code in C" (C) ~1996 Bruce Schneier
 *
 * All other parts:
 * (C) 2015 KB4OID Labs, A Division of Kodetroll Heavy Industries
 * Author: Kodetroll
 * Date: January 2015
 */

#include <stdio.h>
#include "desutils.h"

/* Validation sets:
 *
 * Single-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
 *
 **********************************************************************/


void deskey(unsigned char *key, short edf)	/* Thanks to James Gillogly & Phil Karn! */
{
	register int i, j, l, m, n, o;
	unsigned char pc1m[56], pcr[56];
	unsigned long kn[32];

	for ( j = 0; j < 56; j++ )
	{
		l = pc1[j];
		m = l & 07;
		pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
	}

	for( i = 0; i < 16; i++ )
	{
		if( edf == DE1 ) m = (15 - i) << 1;
		else m = i << 1;
		n = m + 1;
		kn[m] = kn[n] = 0L;
		for( j = 0; j < 28; j++ )
		{
			l = j + totrot[i];
			if( l < 28 ) pcr[j] = pc1m[l];
			else pcr[j] = pc1m[l - 28];
		}
		for( j = 28; j < 56; j++ )
		{
		    l = j + totrot[i];
		    if( l < 56 ) pcr[j] = pc1m[l];
		    else pcr[j] = pc1m[l - 28];
	    	}
		for( j = 0; j < 24; j++ )
		{
			if( pcr[pc2[j]] ) kn[m] |= bigbyte[j];
			if( pcr[pc2[j+24]] ) kn[n] |= bigbyte[j];
		}
	}

	cookey(kn);
	return;
}

static void cookey(register unsigned long *raw1)
{
	register unsigned long *cook, *raw0;
	unsigned long dough[32];
	register int i,j,k,o;

	cook = dough;
	for( i = 0; i < 16; i++, raw1++ )
	{
		raw0 = raw1++;
		*cook	 = (*raw0 & 0x00fc0000L) << 6;
		*cook	|= (*raw0 & 0x00000fc0L) << 10;
		*cook	|= (*raw1 & 0x00fc0000L) >> 10;
		*cook++	|= (*raw1 & 0x00000fc0L) >> 6;
		*cook	 = (*raw0 & 0x0003f000L) << 12;
		*cook	|= (*raw0 & 0x0000003fL) << 16;
		*cook	|= (*raw1 & 0x0003f000L) >> 4;
		*cook++	|= (*raw1 & 0x0000003fL);
	}
/*	o = 0;
	for(i=0;i<32;i++) {
		j = dough[i]/0x10000;
		k = dough[i] & 0xFFFF;
		printf("i: %d, 0x%2.2x%4.4x\n",i,j,k);
		if (o == 7) {
			o = pause();
			o = 0;
		}

		o++;
	}
*/
	usekey(dough);
	return;
}

void cpkey(register unsigned long *into)
{
	register unsigned long *from, *endp;

	from = KnL, endp = &KnL[32];
	while( from < endp ) *into++ = *from++;
	return;
}

void usekey(register unsigned long *from)
{
	register unsigned long *to, *endp;

	to = KnL, endp = &KnL[32];
	while( to < endp ) *to++ = *from++;
	return;
}

void des(unsigned char *inblock, unsigned char *outblock)
{
	unsigned long work[2];

	scrunch(inblock, work);
	desfunc(work, KnL);
	unscrun(work, outblock);
	return;
}

static void scrunch(register unsigned char *outof, register unsigned long *into)
{
	*into 	 = (*outof++ & 0xffL) << 24;
	*into 	|= (*outof++ & 0xffL) << 16;
	*into 	|= (*outof++ & 0xffL) << 8;
	*into++ |= (*outof++ & 0xffL);
	*into 	 = (*outof++ & 0xffL) << 24;
	*into 	|= (*outof++ & 0xffL) << 16;
	*into 	|= (*outof++ & 0xffL) << 8;
	*into	|= (*outof   & 0xffL);
	return;
}

static void unscrun(register unsigned long *outof, register unsigned char *into)
{
	*into++ = (*outof >> 24) & 0xffL;
	*into++ = (*outof >> 16) & 0xffL;
	*into++ = (*outof >>  8) & 0xffL;
	*into++ =  *outof++	 & 0xffL;
	*into++ = (*outof >> 24) & 0xffL;
	*into++ = (*outof >> 16) & 0xffL;
	*into++ = (*outof >>  8) & 0xffL;
	*into   =  *outof	 & 0xffL;
	return;
}

static void desfunc(register unsigned long *block, register unsigned long *keys)
{
	register unsigned long fval, work, right, leftt;
	register int round;

	leftt = block[0];
	right = block[1];
	work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
	right ^= work;
	leftt ^= (work << 4);
	work = ((leftt >> 16) ^ right) & 0x0000ffffL;
	right ^= work;
	leftt ^= (work << 16);
	work = ((right >> 2) ^ leftt) & 0x33333333L;
	leftt ^= work;
	right ^= (work << 2);
	work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
	leftt ^= work;
	right ^= (work << 8);
	right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
	work = (leftt ^ right) & 0xaaaaaaaaL;
	leftt ^= work;
	right ^= work;
	leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;

	for( round = 0; round < 8; round++ )
	{
		work  = (right << 28) | (right >> 4);
		work ^= *keys++;
		fval  = SP7[ work		 & 0x3fL];
		fval |= SP5[(work >>  8) & 0x3fL];
		fval |= SP3[(work >> 16) & 0x3fL];
		fval |= SP1[(work >> 24) & 0x3fL];
		work  = right ^ *keys++;
		fval |= SP8[ work		 & 0x3fL];
		fval |= SP6[(work >>  8) & 0x3fL];
		fval |= SP4[(work >> 16) & 0x3fL];
		fval |= SP2[(work >> 24) & 0x3fL];
		leftt ^= fval;
		work  = (leftt << 28) | (leftt >> 4);
		work ^= *keys++;
		fval  = SP7[ work		 & 0x3fL];
		fval |= SP5[(work >>  8) & 0x3fL];
		fval |= SP3[(work >> 16) & 0x3fL];
		fval |= SP1[(work >> 24) & 0x3fL];
		work  = leftt ^ *keys++;
		fval |= SP8[ work		 & 0x3fL];
		fval |= SP6[(work >>  8) & 0x3fL];
		fval |= SP4[(work >> 16) & 0x3fL];
		fval |= SP2[(work >> 24) & 0x3fL];
		right ^= fval;
	}

	right = (right << 31) | (right >> 1);
	work = (leftt ^ right) & 0xaaaaaaaaL;
	leftt ^= work;
	right ^= work;
	leftt = (leftt << 31) | (leftt >> 1);
	work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
	right ^= work;
	leftt ^= (work << 8);
	work = ((leftt >> 2) ^ right) & 0x33333333L;
	right ^= work;
	leftt ^= (work << 2);
	work = ((right >> 16) ^ leftt) & 0x0000ffffL;
	leftt ^= work;
	right ^= (work << 16);
	work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
	leftt ^= work;
	right ^= (work << 4);
	*block++ = right;
	*block = leftt;
	return;
}


void des_key(des_ctx *dc, unsigned char *key)
{
	deskey(key,EN0);
	cpkey(dc->ek);
	deskey(key,DE1);
	cpkey(dc->dk);
}

/* Encrypt several blocks in ECB. Caller is responsible for
   short blocks */

void des_enc(des_ctx *dc, unsigned char *data, int blocks)
{
	unsigned long work[2];
	int i;
	unsigned char *cp;

	cp = data;
	for(i=0;i<blocks;i++)
	{
		scrunch(cp,work);
		desfunc(work,dc->ek);
		unscrun(work,cp);
		cp+=8;
	}
}

void des_dec(des_ctx *dc, unsigned char *data, int blocks)
{
	unsigned long work[2];
	int i;
	unsigned char *cp;

	cp = data;
	for(i=0;i<blocks;i++)
	{
		scrunch(cp,work);
		desfunc(work,dc->dk);
		unscrun(work,cp);
		cp+=8;
	}
}

int pause(void)
{
	int i;

	i = getchar();

	return (i);
}

/* This function will pack an ASCII HEX string into a hex
 * array (which is really a cblock)
 */
void pack_key(unsigned char * key, unsigned char * deskey)
{
   	unsigned int hexint1 = 0;
   	unsigned int hexint2 = 0;
   	unsigned int j = 0;
   	unsigned int c = 0;
   	int i;
	unsigned char *tmpkey;

	tmpkey = deskey;

   	/* Pack ASCII KEY string into hex array */
   	j = 0;
   	for(i=0; i<HEXBLOCK_SIZE; i+=2) {
		hexint1 = hex2int(key[i]);
		hexint2 = hex2int(key[i+1]);
		c = ((hexint1 * 16 ) + hexint2) & 0xFF;
		//printf("[i: %x 1: 0x%02x 2: 0x%02x c: 0x%02x]\n",i,hexint1,hexint2,c);
		tmpkey[j] = c;
	        j++;
   	}


}

/* This function will convert a single digit ASCII character
 * (typed as int) representing a hex string digit into the
 * integer value it represents. E.g. 'F' returns (int)15
 */
int hex2int(int num)
{
	int n = 0;

	//printf("num: %d\n",num);
	switch (num) {

		case '0':	// 48
			n = 0;
			break;

		case '1':	// 49
			n = 1;
			break;

		case '2':	// 50
			n = 2;
			break;

		case '3':	// 51
			n = 3;
			break;

		case '4':	// 52
			n = 4;
			break;

		case '5':	// 53
			n = 5;
			break;

		case '6':	// 54
			n = 6;
			break;

		case '7':	// 55
			n = 7;
			break;

		case '8':	// 56
			n = 8;
			break;

		case '9':	// 57
			n = 9;
			break;

		case 'A':	// 65
			n = 10;
			break;

		case 'B':	// 66
			n = 11;
			break;

		case 'C':	// 67
			n = 12;
			break;

		case 'D':	// 68
			n = 13;
			break;

		case 'E':	// 69
			n = 14;
			break;

		case 'F':	// 70
			n = 15;
			break;

		case 'a':	// 97
			n = 10;
			break;

		case 'b':	// 98
			n = 11;
			break;

		case 'c':	// 99
			n = 12;
			break;

		case 'd':	// 100
			n = 13;
			break;

		case 'e':	// 101
			n = 14;
			break;

		case 'f':	// 102
			n = 15;
			break;
	}

	return (n);
}

/* This method will take the provided des_cblock value
 * and print it to std out as ASCII HEX digits, with
 * the proivded name as a label.
 */
//void
//show_block(char * name, des_cblock * block)
//{
//	char hexblock[17];
//
//	memset(hexblock,0x00,sizeof(hexblock));
//	unpack_key(hexblock,block);
//	printf("%s: '%s'\n",name,hexblock);
//}
