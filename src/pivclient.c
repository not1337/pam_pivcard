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

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <openssl/pem.h>
#include "common.h"

static void usage(void) __attribute__((noreturn));

static void *getkey(char *file)
{
	BIO *bio;
	EVP_PKEY *key;
	RSA *rsa=NULL;

	if(!(bio=BIO_new(BIO_s_file())))goto err1;
	if(BIO_read_filename(bio,file)<=0)goto err2;
	if(!(key=PEM_read_bio_PUBKEY(bio,NULL,NULL,NULL)))goto err2;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	if(!EVP_PKEY_get0_RSA(key))goto err3;
#else
	if(EVP_PKEY_type(key->type)!=EVP_PKEY_RSA)goto err3;
#endif
	rsa=EVP_PKEY_get1_RSA(key);
err3:	EVP_PKEY_free(key);
err2:   BIO_free(bio);
err1:   return rsa;
}

static void freekey(void *key)
{
	RSA *rsa=(RSA *)key;

	if(rsa)RSA_free(rsa);
}

static int keysize(void *key)
{
	RSA *rsa=(RSA *)key;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	const BIGNUM *n;

	if(rsa)
	{
		RSA_get0_key(rsa,&n,NULL,NULL);
		if(n)return RSA_size(rsa);
	}
#else
	if(rsa)if(rsa->n)return RSA_size(rsa);
#endif
	return 0;
}

static int rsaenc(void *key,void *in,int ilen,void **out,int *olen)
{
	RSA *rsa=(RSA *)key;

	if(!(*olen=keysize(key))||*olen<ilen)return -1;
	if(!(*out=malloc(*olen)))return -1;
	if((*olen=RSA_public_encrypt(ilen,in,*out,rsa,RSA_PKCS1_PADDING))<=0)
	{
		memclear(*out,0,keysize(key));
		free(*out);
		return -1;
	}
	return 0;
}

static int rsadec(void *key,void *in,int ilen,void **out,int *olen)
{
	RSA *rsa=(RSA *)key;

	if(!(*olen=keysize(key))||*olen<ilen)return -1;
	if(!(*out=malloc(*olen)))return -1;
	if((*olen=RSA_public_decrypt(ilen,in,*out,rsa,RSA_PKCS1_PADDING))<=0)
	{
		memclear(*out,0,keysize(key));
		free(*out);
		return -1;
	}
	return 0;
}

static void sha256(unsigned char *in,int ilen,unsigned char *out)
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	EVP_MD_CTX *md;

	md=EVP_MD_CTX_new();
	EVP_DigestInit_ex(md,EVP_sha256(),NULL);
	EVP_DigestUpdate(md,in,ilen);
	EVP_DigestFinal_ex(md,out,NULL);
	EVP_MD_CTX_free(md);
#else
	EVP_MD_CTX md;

	EVP_MD_CTX_init(&md);
	EVP_DigestInit_ex(&md,EVP_sha256(),NULL);
	EVP_DigestUpdate(&md,in,ilen);
	EVP_DigestFinal_ex(&md,out,NULL);
	EVP_MD_CTX_cleanup(&md);
#endif
}

static int authorize(int s,char *user,char *pin,char *pubkey)
{
	int r=-1;
	int l;
	int n;
	int i;
	int j;
	REQUEST req;
	unsigned char *ptr=(unsigned char *)&req;
	REPLY *ans;
	void *key;
	void *enc;
	unsigned char cmp[RANDSIZE];

	if((i=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)goto err1;
	l=read(i,req.random,RANDSIZE);
	close(i);
	if(l!=RANDSIZE)goto err1;
	memcpy(cmp,req.random,RANDSIZE);

	if(!(key=getkey(pubkey)))goto err1;

	strncpy(req.user,user,USERSIZE);
	if(pin)
	{
		strncpy(req.pin,pin,PINSIZE);
		req.flags=0x00;
	}
	else req.flags=0x80;

	sha256(ptr+HASHSIZE,sizeof(REQUEST)-HASHSIZE,ptr);

	for(i=HASHSIZE,j=0;i<sizeof(REQUEST);i++)
	{
		ptr[i]^=ptr[j];
		if(++j==HASHSIZE)j=0;
	}

	if(rsaenc(key,ptr,sizeof(REQUEST),&enc,&l))goto err2;

	if(write(s,enc,l)!=l)goto err3;
	if(read(s,enc,l)!=l)goto err3;

	if(rsadec(key,enc,l,(void **)&ans,&n))goto err3;
	if(n!=sizeof(REPLY))goto err4;
	ptr=(unsigned char *)ans;

	for(i=HASHSIZE,j=0;i<sizeof(REPLY);i++)
	{
		ptr[i]^=ptr[j];
		if(++j==HASHSIZE)j=0;
	}

	sha256(ptr+HASHSIZE,sizeof(REPLY)-HASHSIZE,req.sha256);
	if(memcmp(req.sha256,ans->sha256,HASHSIZE))goto err4;

	if(memcmp(ans->random,cmp,RANDSIZE))goto err4;

	r=ans->result;

err4:	memclear(ans,0,n);
	free(ans);
err3:	memclear(enc,0,l);
	free(enc);
err2:	freekey(key);
	memclear(&req,0,sizeof(REQUEST));
err1:	return r;
}

static int netclient(const char *host,int port,char *interface)
{
	int s;
	int i;
	struct hostent *h;
	struct hostent hh;
	union
	{
		struct sockaddr_in6 a6;
		struct sockaddr_in a4;
	} addr;
	struct sockaddr *a=(struct sockaddr *)&addr;
	char bfr[2048];

	memset(&addr,0,sizeof(addr));

	if(inet_pton(AF_INET6,host,&addr.a6.sin6_addr)==1)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
	}
	else if(inet_pton(AF_INET,host,&addr.a4.sin_addr)==1)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
	}
	else if(!gethostbyname2_r(host,AF_INET6,&hh,bfr,sizeof(bfr),&h,&s)&&h)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
		memcpy(&addr.a6.sin6_addr,h->h_addr,16);
	}
	else if(!gethostbyname2_r(host,AF_INET,&hh,bfr,sizeof(bfr),&h,&s)&&h)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
		memcpy(&addr.a4.sin_addr,h->h_addr,4);
	}
	else return -1;

	if((s=socket(a->sa_family,SOCK_STREAM|SOCK_CLOEXEC,0))==-1)return -1;

	if(interface)
	{
		if(a->sa_family==AF_INET)goto fail;
		if(!(addr.a6.sin6_scope_id=if_nametoindex(interface)))goto fail;
		i=1;
		if(setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&i,sizeof(i)))
			goto fail;
	}

	i=1;
	if(setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&i,sizeof(i)))goto fail;

	if(connect(s,a,sizeof(addr)))
	{
fail:		close(s);
		return -1;
	}

	return s;
}

static int rmtclient(const char *device,const char *lock,int *lockfd)
{       
	int l;
	int s; 
	int i;
	struct termios tt;
	
	if((l=open(lock,O_RDWR|O_CREAT|O_CLOEXEC,0600))==-1)goto err1;
	if(lockf(l,F_LOCK,0))goto err2;
	if((s=open(device,O_RDWR|O_CLOEXEC))==-1)goto err2;
	if(tcgetattr(s,&tt)<0)goto err3;
	tt.c_cflag=CS8|CREAD;
	tt.c_iflag=IGNBRK|IGNPAR;
	tt.c_oflag=0;
	tt.c_lflag=0;
	for(i=0;i<NCCS;i++)tt.c_cc[i]=0;
	tt.c_cc[VMIN]=1;
	tt.c_cc[VTIME]=0;
	cfsetispeed(&tt,B115200);
	cfsetospeed(&tt,B115200);
	if(tcsetattr(s,TCSAFLUSH,&tt)<0)
	{
err3:		close(s);
err2:		close(l);
err1:		return -1;
	}
	tcflush(s,TCIOFLUSH);
	*lockfd=l;
	return s;
}

static int unxclient(const char *sock)
{
	int c;
	struct stat stb;
	struct sockaddr_un a;

	if(stat(sock,&stb))return -1;
	if(!S_ISSOCK(stb.st_mode))return -1;
	if(access(sock,R_OK|W_OK))return -1;
	if(strlen(sock)>=sizeof(a.sun_path))return -1;

	if((c=socket(PF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0))==-1)return -1;
	memset(&a,0,sizeof(a));
	a.sun_family=AF_UNIX;
	strcpy(a.sun_path,sock);

	if(connect(c,(struct sockaddr *)(&a),sizeof(a)))
	{
		close(c);
		return -1;
	}

	return c;
}

static void usage(void)
{   
    fprintf(stderr,"Usage:\n"
    "pivclient -D <device> -L <lockfile> -u <name> <options>\n"
    "pivclient -H <host> -P <port> -u <name> <options>\n"
    "pivclient [-s <socket>] -n <name> <options>\n"
    "pivclient -h\n"
    "\n"
    "Serial Line Options:\n"
    "-D  serial device (no default)\n"
    "-L  lock file (no default)\n"
    "\n"
    "TCP Options:\n"
    "-H  remote host name (no default)\n"
    "-P  remote host port (no default)\n"
    "-i  IPv6 link local interface (no default)\n"
    "\n"
    "Unix Domain Socket Options:\n"
    "-s  socket name (default: /var/run/pivd.sock)\n"
    "\n"
    "Common Options:\n"
    "-u  authentication name (no default)\n"
    "-p  smartcard PIN or '-' to read from standard input (no default)\n"
    "-k  RSA public key file (default: /etc/pam_pivcard/piv.pub)\n"
    "-h  this help text\n");
    exit(1);
}

int main(int argc,char *argv[])
{
	int i;
	int r=1;
	int s=-1;
	int l=-1;
	int port=0;
	char *sock="/var/run/pivd.sock";
	char *key="/etc/pam_pivcard/piv.pub";
	char *user=NULL;
	char *pin=NULL;
	char *host=NULL;
	char *ifc=NULL;
	char *device=NULL;
	char *lock=NULL;
	char bfr[128];

	while((i=getopt(argc,argv,"u:p:k:s:H:P:D:L:i:h"))!=-1)switch(i)
	{
	case 'u':
		user=optarg;
		break;
	case 'p':
		if(!strcmp(optarg,"-"))
		{
			if(!fgets(bfr,sizeof(bfr),stdin))usage();
			pin=bfr;
		}
		else pin=optarg;
		break;
	case 'k':
		key=optarg;
		break;
	case 's':
		sock=optarg;
		break;
	case 'H':
		host=optarg;
		break;
	case 'P':
		port=atoi(optarg);
		break;
	case 'D':
		device=optarg;
		break;
	case 'L':
		lock=optarg;
		break;
	case 'i':
		ifc=optarg;
		break;
	case 'h':
	default:usage();
	}

	if(!user||!*user||strlen(user)>=USERSIZE)usage();

	if(pin)
	{
		for(i=0;pin[i];i++)if(pin[i]<'0'||pin[i]>'9')usage();
		if(!i||i>=PINSIZE)usage();
	}

	if(host)
	{
		if(!*host||port<1||port>65535)usage();
	}
	else if(port)usage();

	if((device&&!lock)||(!device&&lock))usage();
	if(device&&(!*device||!*lock))usage();

	if(device&&host)usage();

	if(device)
	{
		if((s=rmtclient(device,lock,&l))==-1)goto out;
	}
	else if(host)
	{
		if((s=netclient(host,port,ifc))==-1)goto out;
	}
	else if((s=unxclient(sock))==-1)goto out;

	if(!authorize(s,user,pin,key))r=0;

out:	if(s!=-1)close(s);
	if(l!=-1)
	{
		s=lockf(l,F_ULOCK,0);
		close(l);
	}
	if(pin)memclear(pin,0,strlen(pin));
	return r;
}
