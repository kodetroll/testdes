/*
 * testdes.h - A definition and header file for the testdes program
 *
 * (C) 2015 KB4OID Labs, A Division of Kodetroll Heavy Industries
 * Author: Kodetroll
 * Date: January 2015
 *
 */

#ifndef __TESTDES_H__
#define __TESTDES_H__

#define VER_MAJOR 1
#define VER_MINOR 1

// Global Prototypes

int getKeySize(int tmode);
void show_key(char * name, unsigned char * key);

void do_sdes_tests(unsigned char * hexdata, unsigned char * hexkey);
void do_tdes_tests(unsigned char * hexdata, unsigned char * hexkey);

void do_sdes_dec(unsigned char * hexdata, unsigned char * hexkey);
void do_sdes_enc(unsigned char * hexdata, unsigned char * hexkey);
void do_tdes_dec(unsigned char * hexdata, unsigned char * hexkey);
void do_tdes_enc(unsigned char * hexdata, unsigned char * hexkey);
void header(void);
void version(void);
void usage(char * name);
void copyright(void);

#endif	// __TESTDES_H__
