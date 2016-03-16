/*
 *
 * The pam_pivcard license version 1.0 This file is part of pam_pivcard,
 * the PIV (compatible) smartcard authentication module.
 * (C) 2015 Andreas Steinmetz, ast@domdv.de
 *
 * pam_pivcard is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 or (at your option) any later
 * version.
 *
 * pam_pivcard is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pam_pivcard; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * As a special exception, if you compile this file and link it with
 * other works to produce a work based on this file, this file does not
 * by itself cause the resulting work to be covered by the GNU General
 * Public License. However the source code for this file must still be
 * made available in accordance with section (3) of the GNU General Public
 * License v2.
 *
 * This exception does not invalidate any other reasons why a work based
 * on this file might be covered by the GNU General Public License.
 *
 */

#define GETPASS		0
#define SETPASS		1

#define OK		0
#define ENGFAIL		-1
#define FILEFAIL	-2
#define CRYPTOFAIL	-3
#define NOCARD		-4
#define NOUSER		-5

#define PINSIZE		16
#define PASSSIZE	88
#define DIRSIZE		128
#define CONFSIZE	128
#define USERSIZE	128
#define HASHSIZE	32
#define RANDSIZE	8

#define MAXFILES	9

#define DFTFILE		"01:01"

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

typedef struct
{
	char cmdres;
	char nopin;
	char precheck;
	char nopass;
	char mode0;
	char openscconf[CONFSIZE];
	char cfgfile[CONFSIZE];
	char passfile[DIRSIZE];
	char engine[DIRSIZE];
	char pkcs11[DIRSIZE];
	char pin[PINSIZE];
	char keyfile[MAXFILES][PINSIZE];
	char pass[PASSSIZE];
} MESSAGE;

typedef struct
{
	int port;
	int nopin;
	char user[USERSIZE];
	char pin[PINSIZE];
	char key[CONFSIZE];
	char host[CONFSIZE];
	char dev[CONFSIZE];
	char lock[CONFSIZE];
} FWDREQUEST;

typedef struct
{
	int result;
} FWDREPLY;

typedef struct
{
	unsigned char sha256[HASHSIZE];
	unsigned char random[RANDSIZE];
	char user[USERSIZE];
	char pin[PINSIZE];
	unsigned char flags;
} REQUEST;

typedef struct
{
	unsigned char sha256[HASHSIZE];
	unsigned char random[RANDSIZE];
	unsigned char result;
} REPLY;
