/*
 *
 * The pam_pivcard license version 1.0 This file is part of pam_pivcard,
 * the PIV (compatible) smartcard authentication module.
 * (C) 2015, 2016 Andreas Steinmetz, ast@domdv.de
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

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <shadow.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include "common.h"

#undef DEBUG

#define FAIL(a,b)	do { r=a; goto b; } while(0)

typedef struct
{
	unsigned char dgst[HASHSIZE];
	unsigned char random[RANDSIZE];
	unsigned char data[PASSSIZE];
} DATA;

static struct
{
	char *name;
	char *value;
} pkcs11[]=
{
	{"ID","pkcs11"},
	{"LIST_ADD","1"},
	{"LOAD",NULL},
#ifdef DEBUG
	{"VERBOSE",NULL},
#endif
	{NULL,NULL}
};

static int engbits;

static int load_engine(void **ctx,MESSAGE *msg)
{
	int i;
	ENGINE **e=(ENGINE **)ctx;

	ENGINE_load_dynamic();

	if(!(*e=ENGINE_by_id("dynamic")))goto err1;

	if(!ENGINE_ctrl_cmd_string(*e,"SO_PATH",msg->engine,0))goto err2;
	for(i=0;pkcs11[i].name;i++)
		if(!ENGINE_ctrl_cmd_string(*e,pkcs11[i].name,pkcs11[i].value,0))
			goto err2;
	if(!ENGINE_ctrl_cmd_string(*e,"MODULE_PATH",msg->pkcs11,0))goto err2;
	if(msg->nopin)if(!ENGINE_ctrl_cmd_string(*e,"NOLOGIN","1",0))goto err2;
	if(!ENGINE_ctrl_cmd_string(*e,"PIN",msg->nopin?"":msg->pin,0))goto err2;
	if(!ENGINE_init(*e))
	{
err2:		ENGINE_free(*e);
err1:		ENGINE_cleanup();
		return ENGFAIL;
	}

	ENGINE_free(*e);

	ENGINE_set_default(*e,ENGINE_METHOD_ALL&~ENGINE_METHOD_RAND);

	return OK;
}

static void unload_engine(void *ctx)
{
	ENGINE *e=(ENGINE *)ctx;

	ENGINE_finish(e);
	ENGINE_cleanup();
}

static void suspend_engine(void *ctx,int *mem)
{
	ENGINE *e=(ENGINE *)ctx;

	*mem=0;

	if(ENGINE_get_default_RSA())
	{
		*mem|=0x01;
		ENGINE_unregister_RSA(e);
	}

	if(ENGINE_get_default_DSA())
	{
		*mem|=0x02;
		ENGINE_unregister_DSA(e);
	}

	if(ENGINE_get_default_ECDH())
	{
		*mem|=0x04;
		ENGINE_unregister_ECDH(e);
	}

	if(ENGINE_get_default_ECDSA())
	{
		*mem|=0x08;
		ENGINE_unregister_ECDSA(e);
	}

	if(ENGINE_get_default_DH())
	{
		*mem|=0x10;
		ENGINE_unregister_DH(e);
	}

	if(ENGINE_get_default_RAND())
	{
		*mem|=0x20;
		ENGINE_unregister_RAND(e);
	}
}

static void resume_engine(void *ctx,int mem)
{
	ENGINE *e=(ENGINE *)ctx;

	if(mem&0x01)ENGINE_register_RSA(e);
	if(mem&0x02)ENGINE_register_DSA(e);
	if(mem&0x04)ENGINE_register_ECDH(e);
	if(mem&0x08)ENGINE_register_ECDSA(e);
	if(mem&0x10)ENGINE_register_DH(e);
	if(mem&0x20)ENGINE_register_RAND(e);
}

static void sha256(unsigned char *in,int ilen,unsigned char *out)
{
	EVP_MD_CTX md;

	EVP_MD_CTX_init(&md);
	EVP_DigestInit_ex(&md,EVP_sha256(),NULL);
	EVP_DigestUpdate(&md,in,ilen);
	EVP_DigestFinal_ex(&md,out,NULL);
	EVP_MD_CTX_cleanup(&md);
}

static int sign(void *ctx,char *file,void *in,int ilen,void *out,int *olen)
{
	int r=NOCARD;
	size_t slen=*olen;
	ENGINE *e=(ENGINE *)ctx;
	EVP_PKEY *key;
	EVP_MD_CTX *mdc;

	resume_engine(e,engbits);

	if(!(key=ENGINE_load_private_key(e,file,NULL,NULL)))goto err1;

	r=CRYPTOFAIL;
	if(!(mdc=EVP_MD_CTX_create()))goto err2;
	if(EVP_DigestInit_ex(mdc,EVP_sha256(),NULL)!=1)goto err3;
	if(EVP_DigestSignInit(mdc,NULL,EVP_sha256(),NULL,key)!=1)goto err3;
	if(EVP_DigestSignUpdate(mdc,in,ilen)!=1)goto err3;
	if(EVP_DigestSignFinal(mdc,out,&slen)!=1)goto err3;
	*olen=slen;
	r=OK;

err3:	EVP_MD_CTX_destroy(mdc);
err2:	EVP_PKEY_free(key);
err1:	suspend_engine(e,&engbits);
	return r;
}

static int verify(char *file,void *in,int ilen,void *sig,int slen)
{
	int r=FILEFAIL;
	BIO *cert;
	X509 *x509;
	EVP_PKEY *key;
	EVP_MD_CTX *mdc;

	if(!(cert=BIO_new(BIO_s_file())))goto err1;
	if(BIO_read_filename(cert,file)<=0)goto err2;

	r=CRYPTOFAIL;
	if(!(x509=PEM_read_bio_X509_AUX(cert,NULL,NULL,NULL)))goto err2;
	if(!(key=X509_get_pubkey(x509)))goto err3;
	if(!(mdc=EVP_MD_CTX_create()))goto err4;
	if(EVP_DigestInit_ex(mdc,EVP_sha256(),NULL)!=1)goto err5;
	if(EVP_DigestVerifyInit(mdc,NULL,EVP_sha256(),NULL,key)!=1)goto err5;
	if(EVP_DigestVerifyUpdate(mdc,in,ilen)!=1)goto err5;
	if(EVP_DigestVerifyFinal(mdc,sig,slen)!=1)goto err5;
	r=OK;

err5:	EVP_MD_CTX_destroy(mdc);
err4:	EVP_PKEY_free(key);
err3:	X509_free(x509);
err2:	BIO_free(cert);
err1:	return r;
}

static int certfingerprint(char *file,void *out)
{
	int r=FILEFAIL;
	int len;
	BIO *cert;
	X509 *x509;
	EVP_PKEY *key;
	RSA *rsa=NULL;
	EC_KEY *ec=NULL;
	unsigned char bfr[2048];
	unsigned char *p=bfr;

	if(!(cert=BIO_new(BIO_s_file())))goto err1;
	if(BIO_read_filename(cert,file)<=0)goto err2;

	r=CRYPTOFAIL;
	if(!(x509=PEM_read_bio_X509_AUX(cert,NULL,NULL,NULL)))goto err2;
	if(!(key=X509_get_pubkey(x509)))goto err3;

	switch(EVP_PKEY_type(key->type))
	{
	case EVP_PKEY_RSA:
		if(!(rsa=EVP_PKEY_get1_RSA(key)))goto err4;
		if((len=i2d_RSA_PUBKEY(rsa,NULL))>sizeof(bfr))goto err5;
		if(i2d_RSA_PUBKEY(rsa,&p)!=len)goto err5;
		break;

	case EVP_PKEY_EC:
		if(!(ec=EVP_PKEY_get1_EC_KEY(key)))goto err4;
		if((len=i2d_EC_PUBKEY(ec,NULL))>sizeof(bfr))goto err5;
		if(i2d_EC_PUBKEY(ec,&p)!=len)goto err5;
		break;

	default:goto err4;
	}

	if(out)sha256(bfr,len,out);
	r=OK;

err5:	if(rsa)RSA_free(rsa);
	if(ec)EC_KEY_free(ec);
err4:	EVP_PKEY_free(key);
err3:	X509_free(x509);
err2:	BIO_free(cert);
err1:	return r;
}

static int hascard(void *ctx,char *file)
{
	int r=NOCARD;
	ENGINE *e=(ENGINE *)ctx;
	EVP_PKEY *key;

	resume_engine(e,engbits);

	if(!(key=ENGINE_load_public_key(e,file,NULL,NULL)))goto err1;
	EVP_PKEY_free(key);
	r=OK;

err1:	suspend_engine(e,&engbits);
	return r;
}
static int cardfingerprint(void *ctx,char *file,void *out)
{
	int r=NOCARD;
	int len;
	EVP_PKEY *key;
	RSA *rsa=NULL;
	EC_KEY *ec=NULL;
	ENGINE *e=(ENGINE *)ctx;
	unsigned char bfr[2048];
	unsigned char *p=bfr;

	resume_engine(e,engbits);

	if(!(key=ENGINE_load_public_key(e,file,NULL,NULL)))goto err1;

	r=CRYPTOFAIL;

	switch(EVP_PKEY_type(key->type))
	{
	case EVP_PKEY_RSA:
		if(!(rsa=EVP_PKEY_get1_RSA(key)))goto err2;
		if((len=i2d_RSA_PUBKEY(rsa,NULL))>sizeof(bfr))goto err3;
		if(i2d_RSA_PUBKEY(rsa,&p)!=len)goto err3;
		break;

	case EVP_PKEY_EC:
		if(!(ec=EVP_PKEY_get1_EC_KEY(key)))goto err2;
		if((len=i2d_EC_PUBKEY(ec,NULL))>sizeof(bfr))goto err3;
		if(i2d_EC_PUBKEY(ec,&p)!=len)goto err3;
		break;

	default:goto err2;
	}

	if(out)sha256(bfr,len,out);
	r=OK;

err3:	if(rsa)RSA_free(rsa);
	if(ec)EC_KEY_free(ec);
	memclear(bfr,0,sizeof(bfr));
err2:	EVP_PKEY_free(key);
err1:	suspend_engine(e,&engbits);
	return r;
}

static int encrypt(void *ctx,char *name,char *file,void *in,int ilen,void *out)
{
	int len;
	int rem;
	int r=NOUSER;
	struct spwd *sp;
	EVP_CIPHER_CTX etx;
	unsigned char bfr[512];
	unsigned char key[32];
	unsigned char iv[32];

	if(!(sp=getspnam(name)))goto err1;

	len=sizeof(bfr);
	if((r=sign(ctx,file,sp->sp_pwdp,strlen(sp->sp_pwdp),bfr,&len)))
		goto err2;

	r=CRYPTOFAIL;
	EVP_CIPHER_CTX_init(&etx);
	EVP_BytesToKey(EVP_aes_256_cfb(),EVP_sha256(),NULL,bfr,len,1,key,iv);
	EVP_EncryptInit_ex(&etx,EVP_aes_256_cfb(),NULL,key,iv);
	len=ilen;
	if(!EVP_EncryptUpdate(&etx,out,&len,in,ilen))goto err3;
	rem=ilen-len;
	if(!EVP_EncryptFinal_ex(&etx,out+len,&rem))goto err3;
	r=OK;

err3:	EVP_CIPHER_CTX_cleanup(&etx);
	memclear(key,0,sizeof(key));
	memclear(iv,0,sizeof(iv));
err2:	memclear(bfr,0,sizeof(bfr));
	memclear(sp->sp_pwdp,0,strlen(sp->sp_pwdp));
err1:	return r;
}

static int decrypt(void *ctx,char *name,char *file,void *in,int ilen,void *out)
{
	int len;
	int rem;
	int r=NOUSER;
	struct spwd *sp;
	EVP_CIPHER_CTX etx;
	unsigned char bfr[512];
	unsigned char key[32];
	unsigned char iv[32];

	if(!(sp=getspnam(name)))goto err1;

	len=sizeof(bfr);
	if((r=sign(ctx,file,sp->sp_pwdp,strlen(sp->sp_pwdp),bfr,&len)))
		goto err2;

	r=CRYPTOFAIL;
	EVP_CIPHER_CTX_init(&etx);
	EVP_BytesToKey(EVP_aes_256_cfb(),EVP_sha256(),NULL,bfr,len,1,key,iv);
	EVP_DecryptInit_ex(&etx,EVP_aes_256_cfb(),NULL,key,iv);
	len=ilen;
	if(!EVP_DecryptUpdate(&etx,out,&len,in,ilen))goto err3;
	rem=ilen-len;
	if(!EVP_DecryptFinal_ex(&etx,out+len,&rem))goto err3;
	r=OK;

err3:	EVP_CIPHER_CTX_cleanup(&etx);
	memclear(key,0,sizeof(key));
	memclear(iv,0,sizeof(iv));
err2:	memclear(bfr,0,sizeof(bfr));
	memclear(sp->sp_pwdp,0,strlen(sp->sp_pwdp));
err1:	return r;
}

static int validate(void *ctx,char *user,char *cfgfile,char *cardfile,int pre,
	int chresp,int *mode)
{
	int fd;
	int len;
	int r;
	int flag=0;
	int val;
	FILE *fp;
	char *u;
	char *m;
	char *c;
	char *f;
	char *mem;
	char line[512];
	char data[512];
	unsigned char cardfp[HASHSIZE];
	unsigned char certfp[HASHSIZE];

	if(!(fp=fopen(cfgfile,"re")))return FILEFAIL;

	while(fgets(line,sizeof(line),fp))
	{
		u=strtok_r(line,":\r\n",&mem);
		m=strtok_r(NULL,":\r\n",&mem);
		c=strtok_r(NULL,":\r\n",&mem);
		f=strtok_r(NULL,":\r\n",&mem);
		if(c&&!f&&*c=='/')f=c;
		if(!u||!m||!c||!f||!*u||!*f)continue;
		if(strcmp(u,user))continue;

		switch((val=atoi(m)))
		{
		case 1:
		case 2:	if(chresp)continue;
			break;
		case 3:	if(chresp)continue;
			fclose(fp);
			if(pre)
			{
				if((r=cardfingerprint(ctx,cardfile,NULL)))
					return r;
			}
			else if((r=hascard(ctx,cardfile)))return r;

			goto out;
		}

		if(certfingerprint(f,certfp))continue;

		if(!flag++)if((r=cardfingerprint(ctx,cardfile,cardfp)))
		{
			fclose(fp);
			return r;
		}

		if(memcmp(certfp,cardfp,HASHSIZE))continue;

		fclose(fp);

		if(val==2)goto out;

		if((fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)
			return FILEFAIL;
		len=read(fd,certfp,HASHSIZE);
		close(fd);
		if(len!=HASHSIZE)return FILEFAIL;

		len=sizeof(data);
		if((r=sign(ctx,cardfile,certfp,HASHSIZE,data,&len)))
			return r;
		if((r=verify(f,(char *)certfp,HASHSIZE,data,len)))return r;

out:		if(mode)*mode=(val?1:0);
		return OK;
	}

	fclose(fp);
	return NOUSER;
}

static void killer(int unused)
{
	kill(getpid(),SIGKILL);
}

int main(int argc,char *argv[])
{
	int r=ENGFAIL;
	int fd=0;
	int efd;
	int elen;
	int i;
	int m=1;
	char *name;
	void *ctx;
	DATA din;
	DATA dout;
	MESSAGE msg;

	if(geteuid()||setuid(0)||setgid(0)||getenv("LD_PRELOAD")||
		getenv("LD_LIBRARY_PATH"))goto out;
	if(ptrace(PTRACE_TRACEME,0,1,0))goto out;
	if(mlockall(MCL_CURRENT|MCL_FUTURE))goto out;
	if(prctl(PR_SET_DUMPABLE,0))goto out;

	signal(SIGALRM,killer);
	alarm(10);

	if(argc==2)fd=atoi(argv[1]);

#ifndef DEBUG
	for(i=0;i<3;i++)if(fd!=i)
	{
		close(i);
		open("/dev/null",i?O_WRONLY:O_RDONLY);
	}
#endif

	if((i=read(fd,&msg,sizeof(msg)))!=sizeof(msg))goto out;
	if(!msg.keyfile[0]||msg.passfile[0]!='/')goto out;
	if(msg.cfgfile[0]&&msg.cfgfile[0]!='/')goto out;
	if(msg.mode0&&!msg.cfgfile[0])goto out;
	if(msg.openscconf[0])putenv(msg.openscconf);
	i=-1;

	switch(msg.cmdres)
	{
	case GETPASS:
		if((r=load_engine(&ctx,&msg)))goto gerr1;
		suspend_engine(ctx,&engbits);

		name=strrchr(msg.passfile,'/')+1;

		if(msg.cfgfile[0])
		{
			for(r=NOCARD,i=0;r==NOCARD&&i<MAXFILES;i++)
				if(*msg.keyfile[i])r=validate(ctx,name,
					msg.cfgfile,msg.keyfile[i],0,
					msg.mode0,&m);
			if(r)goto gerr2;
			if(!m)
			{
				memset(msg.pass,0,sizeof(msg.pass));
				goto done;
			}
		}

		if((efd=open(msg.passfile,O_RDONLY|O_CLOEXEC))==-1)
			FAIL(FILEFAIL,gerr2);

		if(flock(efd,LOCK_EX))
		{
			close(efd);
			FAIL(FILEFAIL,gerr2);
		}

		elen=read(efd,&din,sizeof(din));

		flock(efd,LOCK_UN);
		close(efd);

		if(elen!=sizeof(din))FAIL(FILEFAIL,gerr2);

		if(i!=-1)r=decrypt(ctx,name,msg.keyfile[--i],&din,sizeof(din),
			&dout);
		else for(r=NOCARD,i=0;r==NOCARD&&i<MAXFILES;i++)
		    if(*msg.keyfile[i])
			r=decrypt(ctx,name,msg.keyfile[i],&din,sizeof(din),
				&dout);
		if(r)goto gerr2;

		sha256(dout.random,sizeof(dout)-sizeof(dout.dgst),din.dgst);
		if(memcmp(din.dgst,dout.dgst,sizeof(din.dgst)))
		{
			r=CRYPTOFAIL;
			goto gerr2;
		}

		memcpy(msg.pass,dout.data,sizeof(msg.pass));
done:		r=OK;

gerr2:		unload_engine(ctx);
gerr1:		memset(&msg,0,sizeof(msg));
		memcpy(msg.pass,dout.data,sizeof(msg.pass));
		msg.cmdres=r;
		msg.nopass=m?0:1;
		memclear(&din,0,sizeof(din));
		memclear(&dout,0,sizeof(dout));
		break;

	case SETPASS:
		if((r=load_engine(&ctx,&msg)))goto serr1;

		name=strrchr(msg.passfile,'/')+1;

		if(msg.cfgfile[0])
		{
			for(r=NOCARD,i=0;r==NOCARD&&i<MAXFILES;i++)
				if(*msg.keyfile[i])r=validate(ctx,name,
					msg.cfgfile,msg.keyfile[i],
					msg.precheck,msg.mode0,&m);
			if(r||!m||msg.precheck)goto serr2;
		}
		else if(msg.precheck)
		{
			for(r=NOCARD,i=0;r==NOCARD&&i<MAXFILES;i++)
				r=cardfingerprint(ctx,name,NULL);
			goto serr2;
		}

		if((efd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)
			FAIL(FILEFAIL,serr2);
		elen=read(efd,din.random,sizeof(din.random));
		close(efd);
		if(elen!=sizeof(din.random))FAIL(FILEFAIL,serr2);

		memcpy(din.data,msg.pass,sizeof(msg.pass));
		sha256(din.random,sizeof(din)-sizeof(din.dgst),din.dgst);

		if(i!=-1)r=encrypt(ctx,name,msg.keyfile[--i],&din,sizeof(din),
			&dout);
		else for(r=NOCARD,i=0;r==NOCARD&&i<MAXFILES;i++)
		    if(*msg.keyfile[i])
			r=encrypt(ctx,name,msg.keyfile[i],&din,sizeof(din),
				&dout);
		if(r)goto serr2;

		if((efd=open(msg.passfile,O_WRONLY|O_CREAT|O_CLOEXEC,0600))
			==-1)FAIL(FILEFAIL,serr2);

		if(flock(efd,LOCK_EX)||ftruncate(efd,sizeof(dout))||
			write(efd,&dout,sizeof(dout))!=sizeof(dout)||
			fdatasync(efd))r=FILEFAIL;
		else r=OK;

		flock(efd,LOCK_UN);
		close(efd);

serr2:		unload_engine(ctx);
serr1:		memclear(&din,0,sizeof(din));
		memclear(&dout,0,sizeof(dout));
		memset(&msg,0,sizeof(msg));
		msg.cmdres=r;
		msg.nopass=m?0:1;
		break;

	default:goto out;
	}

	i=write(fd,&msg,sizeof(msg));
	r=OK;

out:	memclear(&msg,0,sizeof(msg));
	close(fd);
	return r;
}
