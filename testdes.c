/*
 * testdes.c - DES Test Program for Linux PC
 *
 * This program uses the older Applied Cryptography example program to generate a SDES and TDES
 * functionality. These are arranged in a series if actions to 'proof' the capability of
 * crypto on a platform. This particular version should require no extraneous libs, it is
 * self-contained. I would not base any modern code on this but it can be used to prove
 * that des crypt can run on a platform.
 *
 * This program is organized as a series of tests, but can also be used to easily encrypt single
 * blocks of data. See usage for details.
 *
 * Parts attributable to Applied Cryptography remain the property of the original owners.
 * Used here, with permission, (I believe).
 * All the other parts, (good or bad) are:
 * (C) 2015 KB4OID Labs, A Division of Kodetroll Heavy Industries
 *
 * Author: Kodetroll (KB4OID)
 *
 */

/* Validation sets: (From the original)
 *
 * Single-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "testdes.h"
#include "desutils.h"

#define HEXKEY_SIZE HEXBLOCK_SIZE+1					// Enough room for 16 hex digits and \0
#define HEXKEY_TSIZE (HEXBLOCK_SIZE * 2) + 1		// Enough room for 32 hex digits and \0

static int tests = 0;		// Controls whether standard test block is done (1 = Yes)
static int verbose = 0;		// Controls whether verbose reporting occurs (1 = Yes)
static int debug = 0;		// When set to 1, debugging output occurs
static int quiet = 0;		// When set to 1, suppresses all extraneous output
static int mode = 0;		// Controls DES mode, 0 = SDES, 1 = TDES
static int action = 0;		// Determins what action occurs, 0 = decrypt, 1 = encrypt

// Set some enums for actions
enum Actions {
	ACT_DEC,	// Action Decrypt
	ACT_ENC		// Action Encrypt
};

// Set some enums for modes
enum Modes {
	MODE_SDES,	// Mode Single DES
	MODE_TDES	// Mode Triple DES
};

/* This function returns the hex key size
 * for the specified DES mode. Useful for
 * checking that a key is large enough for
 * the desired mode.
 */
int getKeySize(int tmode)
{
	switch(tmode)
	{
		case MODE_SDES:
			return(16);
		case MODE_TDES:
			return(32);
		default:
			return(-1);

	}

	return(-1);
}

/* Function to show the contents of a binary BLOCK
 * to the screen with a label. Useful for debugging
 * crypt  activities
 */
void show_key(char * name, unsigned char * key)
{
	int i;
	/* Show key1 to user */
	if (name != "")
		printf("%s ",name);
	for(i=0;i<CBLOCK_SIZE;i++)
		printf("%02X",key[i]);
	printf("\n");

//	printf("%s: ",name);
//	for(i=0;i<8;i++)
//		printf("%02x ",((unsigned int)key[i])&0x00ff);
//	printf("\n");

}

/* Function to accomplish a standardized set of tests of SDES
 * functionality. Given a known set of keys (111111111111111)
 * & (3333333333333333) and a known start vector (0000000000000000)
 * this function will return a series of results that can verify
 * that des functions are working. Was originally the core function
 * of this program.
 */
void do_sdes_tests(unsigned char * hexdata, unsigned char * hexkey)
{
	des_ctx dc;
	unsigned char *cp;
	unsigned char block[CBLOCK_SIZE];
	unsigned char key1[CBLOCK_SIZE];
	unsigned char key2[CBLOCK_SIZE];
	unsigned char hexkey1[HEXKEY_SIZE];
	unsigned char hexkey2[HEXKEY_SIZE];
	int start;

	// The provided hexkey needs to be a double length (TDES) key
	if (strlen(hexkey) != getKeySize(MODE_TDES))
	{
		printf("hexkey size not correct for mode!\n");
		return;
	}

	// Split the left half of the key into hexkey1
	start = 0;
	memset(hexkey1,0x00,sizeof(hexkey1));
	strncpy(hexkey1,&hexkey[start],HEXBLOCK_SIZE);

	// Split the right half of the key into hexkey2
	start = HEXBLOCK_SIZE;
	memset(hexkey2,0x00,sizeof(hexkey2));
	strncpy(hexkey2,&hexkey[start],HEXBLOCK_SIZE);

	if (debug)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey",hexkey);
		printf("%s: '%s'\n","hexkey1",hexkey1);
		printf("%s: '%s'\n","hexkey2",hexkey2);
	}

	/* Pack Hexkey1 into key1 */
	pack_key(hexkey1,key1);

	/* Show key1 to user */
	if (debug)
		show_key("Key1:",key1);

	/* Pack Hexkey2 into key2 */
	pack_key(hexkey2,key2);

 	/* Show key2 to user */
	if (debug)
	 	show_key("Key2:",key2);

	/* Pack hexdata into data block */
	pack_key(hexdata,block);

	/* Show data to user */
	if (debug)
		show_key("Data:",block);

	/* Initialize CP to point to our data block */
	cp = block;

	/* Setup key structure */
	des_key(&dc,key1);

	/* Do first action, DES Encrypt Data with Key */
	des_enc(&dc,cp,1);

	/* Show results */
	show_key("SDES Enc(key1) = ",cp);

	/* Do action, DES Decrypt previous result with Key */
	des_dec(&dc,cp,1);

	/* Show results */
	show_key("SDES Dec(key1) = ",cp);

	/* Do action, DES Decrypt previous result with Key */
	des_dec(&dc,cp,1);

	/* Show results */
	show_key("SDES Dec(key1) = ",cp);

	/* SDES with Key2 */

	/* Restore X by Packing hexdata into data */
	pack_key(hexdata,block);

	/* Show data to user */
	show_key("Data:",block);

	/* Initialize CP */
	cp = block;

	/* Setup key structure */
	des_key(&dc,key2);

	/* Do first action, DES Encrypt Data with Key */
	des_enc(&dc,cp,1);

	/* Show results */
	show_key("SDES Enc(key2) = ",cp);

	/* Do action, DES Decrypt previous result with Key */
	des_dec(&dc,cp,1);

	/* Show results */
	show_key("SDES Dec(key2) = ",cp);

	/* Do action, DES Decrypt previous result with Key */
	des_dec(&dc,cp,1);

	/* Show results */
	show_key("SDES Dec(key2) = ",cp);

}

/* Function to accomplish a standardized set of tests of TDES
 * functionality. Given a known set of keys (111111111111111)
 * & (3333333333333333) and a known start vector (0000000000000000)
 * this function will return a series of results that can verify
 * that des functions are working. Was originally the core function
 * of this program.
 */
 void do_tdes_tests(unsigned char * hexdata,unsigned char * hexkey)
{
	des_ctx dc;
	unsigned char *cp;
	unsigned char block[CBLOCK_SIZE];
	unsigned char key1[CBLOCK_SIZE];
	unsigned char key2[CBLOCK_SIZE];
	unsigned char hexkey1[HEXKEY_SIZE];
	unsigned char hexkey2[HEXKEY_SIZE];
	int start;

	if (strlen(hexkey) != getKeySize(MODE_TDES))
	{
		printf("hexkey size not correct for mode!\n");
		return;
	}

	start = 0;
	memset(hexkey1,0x00,sizeof(hexkey1));
	strncpy(hexkey1,&hexkey[start],HEXBLOCK_SIZE);

	start = HEXBLOCK_SIZE;
	memset(hexkey2,0x00,sizeof(hexkey2));
	strncpy(hexkey2,&hexkey[start],HEXBLOCK_SIZE);

	if (debug)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey",hexkey);
		printf("%s: '%s'\n","hexkey1",hexkey1);
		printf("%s: '%s'\n","hexkey2",hexkey2);
	}

	/* Pack Hexkey into key */
	pack_key(hexkey1,key1);

	/* Show key1 to user */
	if (debug)
		show_key("Key1:",key1);

	/* Pack Hexkey into key */
	pack_key(hexkey2,key2);

 	/* Show key2 to user */
	if (debug)
	 	show_key("Key2:",key2);

	/* Pack hexdata into data */
	pack_key(hexdata,block);

	/* Show data to user */
	if (debug)
		show_key("Data:",block);

	/* Initialize CP */
	cp = block;

	/* Setup key structure for key1 */
	des_key(&dc,key1);

	/* Do first action, DES Encrypt Data with Key1 */
	des_enc(&dc,cp,1);

	/* Setup key structure for key2 */
	des_key(&dc,key2);

	/* Do second action, DES Decrypt previous result with Key2 */
	des_dec(&dc,cp,1);

	/* Setup key structure for key1 again */
	des_key(&dc,key1);

	/* Do third and last action, DES Encrypt Data with Key1 */
	des_enc(&dc,cp,1);

	/* Show results */
	if (quiet == 1)
		show_key("TDES Enc(Key1,Key2) = ",cp);
	else
		show_key("",cp);
}

/* Function to accomplish an SDES Decrypt on a block of data
 * Data and key are provided as 16 digit ASCII hex strings.
 */
void do_sdes_dec(unsigned char * hexdata, unsigned char * hexkey)
{
	des_ctx dc;
	unsigned char *cp;
	unsigned char x[CBLOCK_SIZE];
	unsigned char key[CBLOCK_SIZE];

	if (strlen(hexkey) != getKeySize(mode))
	{
		printf("hexkey size not correct for mode!\n");
		return;
	}

	if (debug)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey",hexkey);
	}

	/* Pack Hexkey into key */
	pack_key(hexkey,key);

	/* Show key1 to user */
	if (debug)
		show_key("Key:",key);

	/* Pack hexdata into data */
	pack_key(hexdata,x);

	/* Show data to user */
	if (debug)
		show_key("Data:",x);

	/* Initialize CP */
	cp = x;

	/* Setup key structure */
	des_key(&dc,key);

	/* Do first action, DES Encrypt Data with Key */
	des_dec(&dc,cp,1);

	/* Show results */
	if (quiet == 1)
		show_key("SDES Dec(key) = ",cp);
	else
		show_key("",cp);

}

/* Function to accomplish an SDES Encrypt on a block of data
 * Data and key are provided as 16 digit ASCII hex strings.
 */
void do_sdes_enc(unsigned char * hexdata, unsigned char * hexkey)
{
	des_ctx dc;
	unsigned char *cp;
	unsigned char x[CBLOCK_SIZE];
	unsigned char key[CBLOCK_SIZE];

	if (strlen(hexkey) != getKeySize(mode))
	{
		printf("hexkey size not correct for mode!\n");
		return;
	}

	if (debug)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey",hexkey);
	}

	/* Pack Hexkey into key */
	pack_key(hexkey,key);

	/* Show key1 to user */
	if (debug)
		show_key("Key:",key);

	/* Pack hexdata into data */
	pack_key(hexdata,x);

	/* Show data to user */
	if (debug)
		show_key("Data:",x);

	/* Initialize CP */
	cp = x;

	/* Setup key structure */
	des_key(&dc,key);

	/* Do first action, DES Encrypt Data with Key */
	des_enc(&dc,cp,1);

	/* Show results */
	if (quiet == 1)
		show_key("SDES Enc(key) = ",cp);
	else
		show_key("",cp);

}

/* Function to accomplish a TDES Decrypt on a block of data
 * Data is provided as 16 digit ASCII hex string, key as a
 * 32 digit ASCII hex string.
 */
void do_tdes_dec(unsigned char * hexdata, unsigned char * hexkey)
{
	des_ctx dc;
	unsigned char *cp;
	unsigned char x[CBLOCK_SIZE];
	unsigned char key1[CBLOCK_SIZE];
	unsigned char key2[CBLOCK_SIZE];
	unsigned char hexkey1[HEXKEY_SIZE];
	unsigned char hexkey2[HEXKEY_SIZE];
	int start;

	if (strlen(hexkey) != getKeySize(mode))
	{
		printf("hexkey size not correct for mode!\n");
		return;
	}

	start = 0;
	memset(hexkey1,0x00,sizeof(hexkey1));
	strncpy(hexkey1,&hexkey[start],HEXBLOCK_SIZE);

	start = HEXBLOCK_SIZE;
	memset(hexkey2,0x00,sizeof(hexkey2));
	strncpy(hexkey2,&hexkey[start],HEXBLOCK_SIZE);

	if (debug)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey",hexkey);
		printf("%s: '%s'\n","hexkey1",hexkey1);
		printf("%s: '%s'\n","hexkey2",hexkey2);
	}

	/* Pack Hexkey into key */
	pack_key(hexkey1,key1);

	/* Show key1 to user */
	if (debug)
		show_key("Key1:",key1);

	/* Pack Hexkey into key */
	pack_key(hexkey2,key2);

 	/* Show key2 to user */
	if (debug)
		show_key("Key2:",key2);

	/* Restore X by Packing hexdata into data */
	pack_key(hexdata,x);

	/* Show data to user */
	if (debug)
		show_key("Data:",x);

	/* Initialize CP */
	cp = x;

	/* Setup key structure for key1 */
	des_key(&dc,key1);

	/* Do first action, DES Encrypt Data with Key1 */
	des_dec(&dc,cp,1);

	/* Setup key structure for key2 */
	des_key(&dc,key2);

	/* Do second action, DES Decrypt previous result with Key2 */
	des_enc(&dc,cp,1);

	/* Setup key structure for key1 again */
	des_key(&dc,key1);

	/* Do third and last action, DES Encrypt Data with Key1 */
	des_dec(&dc,cp,1);

	/* Show results */
	if (quiet == 1)
		show_key("TDES Dec(Key1,Key2) = ",cp);
	else
		show_key("",cp);

}

/* Function to accomplish a TDES Encrypt on a block of data
 * Data is provided as 16 digit ASCII hex string, key as a
 * 32 digit ASCII hex string.
 */
void do_tdes_enc(unsigned char * hexdata, unsigned char * hexkey)
{
	des_ctx dc;
	unsigned char *cp;
	unsigned char x[CBLOCK_SIZE];
	unsigned char key1[CBLOCK_SIZE];
	unsigned char key2[CBLOCK_SIZE];
	unsigned char hexkey1[HEXKEY_SIZE];
	unsigned char hexkey2[HEXKEY_SIZE];
	int start;

	if (strlen(hexkey) != getKeySize(mode))
	{
		printf("hexkey size not correct for mode!\n");
		return;
	}

	start = 0;
	memset(hexkey1,0x00,sizeof(hexkey1));
	strncpy(hexkey1,&hexkey[start],HEXBLOCK_SIZE);

	start = HEXBLOCK_SIZE;
	memset(hexkey2,0x00,sizeof(hexkey2));
	strncpy(hexkey2,&hexkey[start],HEXBLOCK_SIZE);

	if (debug)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey",hexkey);
		printf("%s: '%s'\n","hexkey1",hexkey1);
		printf("%s: '%s'\n","hexkey2",hexkey2);
	}

	/* Pack Hexkey into key */
	pack_key(hexkey1,key1);

	/* Show key1 to user */
	if (debug)
		show_key("Key1:",key1);

	/* Pack Hexkey into key */
	pack_key(hexkey2,key2);

	/* Show key2 to user */
	if (debug)
		show_key("Key2:",key2);

	/* Restore X by Packing hexdata into data */
	pack_key(hexdata,x);

	/* Show Data to user */
	if (debug)
		show_key("Data:",x);

	/* Initialize CP */
	cp = x;

	/* Setup key structure for key1 */
	des_key(&dc,key1);

	/* Do first action, DES Encrypt Data with Key1 */
	des_enc(&dc,cp,1);

	/* Setup key structure for key2 */
	des_key(&dc,key2);

	/* Do second action, DES Decrypt previous result with Key2 */
	des_dec(&dc,cp,1);

	/* Setup key structure for key1 again */
	des_key(&dc,key1);

	/* Do third and last action, DES Encrypt Data with Key1 */
	des_enc(&dc,cp,1);

	/* Show results */
	if (quiet == 1)
		show_key("TDES Enc(Key1,Key2) = ",cp);
	else
		show_key("",cp);

}

/* This function will print the program header
 */
void header(void)
{
	printf("TESTDES - DES Test Utility\n");
	copyright();
}

/* This function will print the program version
 */
void version(void)
{
	printf("Version: %d.%d\n",VER_MAJOR,VER_MINOR);
}

/* This function will print the program usage (help)
 */
void usage(char * name)
{
	header();
	version();
	printf("Usage:\n");
	printf("%s <options>\n",name);
	printf("Where:\n");
	printf("	--verbose          Turns ON VERBOSE reporting.\n");
	printf("	--brief            Turns OFF VERBOSE reporting.\n");
	printf("	--quiet            Turns OFF VERBOSE reporting. (default)\n");
	printf("	--debug            Turns ON debugging.\n");
	printf("	--nodebug          Turns OFF debugging. (default)\n");
	printf("	--enc              Enables ENCRYPT action.\n");
	printf("	--dec              Enables DECRYPT action. (default)\n");
	printf("	--tests            Enables test mode.\n");
	printf("	--notests          Disables test mode. (default)\n");
	printf("	--tdes             Sets Triple DES mode.\n");
	printf("	--sdes             Sets Single DES mode. (default)\n");
	printf("	-h --help          Prints this help and exits.\n");
	printf("	-v --version       Prints version and exits.\n");
	printf("	-k --key <KEY>     Specifies Key to be used.\n");
	printf("	-d --data <DATA>   Specifies Data Block.\n");
	printf("	-b --block <DATA>  Specifies Data Block.\n");
	printf("	-m --mode {0|1}    Sets DES Mode, 0 - SDES, 1 - TDES.\n");
	printf("	-a --action {0|1}  Sets Crypt Action, 0 - DECRYPT, 1 - ENCRYPT.\n");
	printf("\n");
}

void copyright(void)
{
	printf("Parts attributable to Applied Cryptography remain the property of the original owners.\n");
	printf("Used here, with permission, (I believe).\n");
	printf("All the other parts, (good or bad) are:\n");
	printf("(C) 2015 KB4OID Labs, A Division of Kodetroll Heavy Industries\n");
	printf("\n");
}

int main(int argc, char * argv[]) {
	int i;
	int start = 0;
	int gotkey = 0;
	int gotblock = 0;
	unsigned char hexkey1[HEXKEY_SIZE];
	unsigned char hexkey2[HEXKEY_SIZE];
	unsigned char hexdata[HEXKEY_SIZE];
	unsigned char hexkey[33];

	if (verbose)
		header();

	memset(hexkey,0x00,sizeof(hexkey));
	strcpy(hexkey,"11111111111111113333333333333333");

	memset(hexkey1,0x00,sizeof(hexkey1));
	strcpy(hexkey1,"1111111111111111");
	if (debug)
		printf("%s: '%s'\n","hexkey1",hexkey1);

	memset(hexkey2,0x00,sizeof(hexkey2));
	strcpy(hexkey2,"3333333333333333");
	if (debug)
		printf("%s: '%s'\n","hexkey2",hexkey2);

	memset(hexdata,0x00,sizeof(hexdata));
	strcpy(hexdata,"0000000000000000");

	int c;

	while (1)
	{
		static struct option long_options[] =
		{
			/* These options set a flag. */
			{"verbose",   no_argument,     &verbose, 1},
			{"brief",     no_argument,     &verbose, 0},
			{"quiet",     no_argument,       &quiet, 0},
			{"debug",     no_argument,       &debug, 1},
			{"nodebug",   no_argument,       &debug, 0},
			{"enc",       no_argument,      &action, 1},
			{"dec",       no_argument,      &action, 0},
			{"tests",     no_argument,       &tests, 1},
			{"notests",   no_argument,       &tests, 0},
			{"tdes",      no_argument,        &mode, 1},
			{"sdes",      no_argument,        &mode, 0},
			/* These options don’t set a flag.
			   We distinguish them by their indices. */
			{"help",      no_argument,           0, 'h'},
			{"version",   no_argument,           0, 'v'},
			{"key",      required_argument,      0, 'k'},
			{"data",     required_argument,      0, 'd'},
			{"block",    required_argument,      0, 'b'},
			{"mode",     required_argument,      0, 'm'},
			{"action",   required_argument,      0, 'a'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "hvk:d:b:m:a:",
				   long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
		break;

		switch (c)
		{
			case 0:
				/* If this option set a flag, do nothing else now. */
				if (long_options[option_index].flag != 0)
					break;
				printf ("option %s", long_options[option_index].name);
				if (optarg)
					printf (" with arg %s", optarg);
				printf ("\n");
				break;

			case 'h':	// help
				if (debug)
					printf("option '-h' or '--help'\n");
				usage(argv[0]);
				exit(0);
				break;

			case 'v':	// version
				if (debug)
					printf("option '-v' or '--version'\n");
				version();
				exit(0);
				break;


			case 'k':
				if (debug)
					printf("option '-k' -or- '--key' with value: '%s'\n",optarg);
				strcpy(hexkey,optarg);
				gotkey = 1;
				break;

			case 'd':
			case 'b':
				if (debug)
					printf("option '-d','-b','--data', or '--block' with value: '%s'\n",optarg);
				strcpy(hexdata,optarg);
				gotblock = 1;
				break;

			case 'm':
				if (debug)
					printf("option '-m' -or- '--mode' with value: '%s'\n",optarg);
				mode = atoi(optarg);
				if (verbose)
					if (mode == MODE_SDES)
						printf("Mode set to 'Single DES'!\n");
					else
						printf("Mode set to 'Triple DES'!\n");
				break;

			case 'a':
				if (debug)
					printf("option '-a' -or- '--action' with value: '%s'\n",optarg);
				action = atoi(optarg);
				if (verbose)
					if (action == ACT_DEC)
						printf("Action set to 'Decrypt'!\n");
					else
						printf("Action set to 'Encrypt'!\n");
				break;

			case '?':
				/* getopt_long already printed an error message. */
				break;

			default:
				abort ();
		}
	}

	/* Instead of reporting ‘--verbose’
	and ‘--brief’ as they are encountered,
	we report the final status resulting from them. */
	if (verbose)
		printf("verbose flag is set!\n");

	if (debug)
		printf("debug flag is set!\n");

	if (verbose)
		if (mode == MODE_SDES)
			printf("Mode: 'Single DES'!\n");
		else
			printf("Mode: 'Triple DES'!\n");

	if (verbose)
		if (action == ACT_DEC)
			printf("Action: 'Decrypt'!\n");
		else
			printf("Action: 'Encrypt'!\n");

	/* Print any remaining command line arguments (not options). */
	if (optind < argc)
	{
		printf ("non-option ARGV-elements: ");
		while (optind < argc)
		{
			printf ("%s ", argv[optind]);
			//strcpy(hexkey,argv[optind]);
			optind++;
		}
		putchar ('\n');
	}

	if (debug)
		printf("HEXBLOCK_SIZE: %d\n",HEXBLOCK_SIZE);

	if (debug)
	{
		printf("sizeof(hexkey): %d\n",sizeof(hexkey));
		printf("sizeof(hexkey1): %d\n",sizeof(hexkey1));
		printf("sizeof(hexkey2): %d\n",sizeof(hexkey2));
	}


	if (debug)
		printf("argc: %d\n",argc);
//	if (gotkey != 1)
//	{
//		if (argc > 1)
//		{
//			strcpy(hexkey,argv[1]);
//			if (debug)
//				printf("%s: '%s'\n","hexkey",hexkey);
//		}
//	}

	if (tests)
	{
		if (verbose)
		{
			printf("%s: '%s'\n","hexdata",hexdata);
			printf("%s: '%s'\n","hexkey",hexkey);
		}

		/* do SDES Tests*/
		do_sdes_tests(hexdata,hexkey);

		/* SDES Done, now do TDES Tests */
		do_tdes_tests(hexdata,hexkey);

		exit(0);
	}

	if (verbose)
	{
		printf("%s: '%s'\n","hexdata",hexdata);
		printf("%s: '%s'\n","hexkey1",hexkey1);
		printf("%s: '%s'\n","hexkey2",hexkey2);
	}

	if (mode == MODE_SDES)
	{
		if (action == ACT_ENC)
			do_sdes_enc(hexdata,hexkey);
		else
			do_sdes_dec(hexdata,hexkey);
	} else {
		if (action == ACT_ENC)
			do_tdes_enc(hexdata,hexkey);
		else
			do_tdes_dec(hexdata,hexkey);
	}

	exit(0);
}

