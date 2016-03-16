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

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "common.h"

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

static int usage(void) __attribute__((noreturn));

static pthread_mutex_t mtx=PTHREAD_MUTEX_INITIALIZER;
static char *path="/var/run/pivd.sock";
static char *pidfile="/var/run/pivd.pid";
static char *keyfile="/etc/pam_pivcard/pivd.key";
static void *key=NULL;
static char *helper=DFTHELPER;
static char *pkcs11=DFTPKCS11;
static char *engine=DFTENGINE;
static char *prefix="";
static char *cfgfile=NULL;
static char *opensc=NULL;
static char cardfile[MAXFILES][PINSIZE];
static int keylen=0;
static int nopin=0;

static void *getkey(char *file)
{
	BIO *bio;
	EVP_PKEY *key;
	RSA *rsa=NULL;

	if(!(bio=BIO_new(BIO_s_file())))goto err1;
	if(BIO_read_filename(bio,file)<=0)goto err2;
	if(!(key=PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL)))goto err2;
	if(EVP_PKEY_type(key->type)!=EVP_PKEY_RSA)goto err3;
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

	if(rsa)if(rsa->n)return RSA_size(rsa);
	return 0;
}

static int rsaenc(void *key,void *in,int ilen,void **out,int *olen)
{
	RSA *rsa=(RSA *)key;

	if(!(*olen=keysize(key))||*olen<ilen)return -1;
	if(!(*out=malloc(*olen)))return -1;
	if((*olen=RSA_private_encrypt(ilen,in,*out,rsa,RSA_PKCS1_PADDING))<=0)
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
	if((*olen=RSA_private_decrypt(ilen,in,*out,rsa,RSA_PKCS1_PADDING))<=0)
	{
		memclear(*out,0,keysize(key));
		free(*out);
		return -1;
	}
	return 0;
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

static void handler(int unused)
{
	unlink(path);
	freekey(key);
	if(pidfile)unlink(pidfile);
	exit(1);
}

static int mkunix(char *path)
{
	int s;
	mode_t mask;
	struct sockaddr_un a;
	struct stat stb;

	if(!path||strlen(path)>=sizeof(a.sun_path))
	{
		fprintf(stderr,"illegal socket path.\n");
		return -1;
	}

	if((s=socket(PF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0))==-1)
	{
		perror("socket");
		return -1;
	}

	memset(&a,0,sizeof(a));
	a.sun_family=AF_UNIX;
	strcpy(a.sun_path,path);

	if(!lstat(path,&stb))
	{
		if(!S_ISSOCK(stb.st_mode))
		{
			fprintf(stderr,"%s is not a socket\n",path);
			close(s);
			return -1;
		}
		if(unlink(path))
		{
			perror("unlink");
			close(s);
			return -1;
		}
	}

	mask=umask(077);

	if(bind(s,(struct sockaddr *)(&a),sizeof(a)))
	{
		perror("bind");
		umask(mask);
		close(s);
		return -1;
	}

	umask(mask);

	if(listen(s,255))
	{
		perror("listen");
		unlink(path);
		close(s);
		return -1;
	}

	return s;
}

static int mknet(int port)
{       
	int s;
	int x; 
	struct sockaddr_in6 a;
	
	memset(&a,0,sizeof(a));
	a.sin6_family=AF_INET6;
	a.sin6_port=htons(port);
	
	if((s=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0))==-1)
		return -1;
	
	x=1;
	if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&x,sizeof(x)))
	{       
		close(s);
		return -1;
	}
	
	x=0;
	if(setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&x,sizeof(x)))
	{       
		close(s);
		return -1;
	}
	
	if(bind(s,(struct sockaddr *)(&a),sizeof(a)))
	{       
		close(s);
		return -1;
	}
	
	if(listen(s,255))
	{       
		close(s);
		return -1;
	}
	
	return s;
}

static int starthelper(const char *helper)
{
	pid_t pid;
	int s[2];
	char bfr[16];
	struct stat stb;

	if(stat(helper,&stb)||!S_ISREG(stb.st_mode))return -1;

	if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,s))return -1;
	sprintf(bfr,"%d",s[1]);

	switch((pid=fork()))
	{
	case 0: close(s[0]);
		unsetenv("LD_PRELOAD");
		unsetenv("LD_LIBRARY_PATH");
		switch(fork())
		{
		case 0: fcntl(s[1],F_SETFD,fcntl(s[1],F_GETFD)&~FD_CLOEXEC);
			execl(helper,helper,bfr,NULL);
		case -1:exit(1);
		default:exit(0);
		}

	default:close(s[1]);
		waitpid(pid,NULL,0);
		return s[0];

	case -1:close(s[0]);
		close(s[1]);
		return -1;
	}
}

static int run(char *user,char *pin,char *cfgfile,char *opensc,MESSAGE *msg)
{
	int r=-1;
	int fd;
	struct pollfd p;

	memset(msg,0,sizeof(MESSAGE));
	msg->cmdres=GETPASS;
	if(opensc)
	{
		strcpy(msg->openscconf,"OPENSC_CONF=");
		strcat(msg->openscconf,opensc);
	}
	strcpy(msg->passfile,"/");
	strcat(msg->passfile,prefix);
	strcat(msg->passfile,user);
	strcpy(msg->engine,engine);
	strcpy(msg->pkcs11,pkcs11);
	strcpy(msg->cfgfile,cfgfile);
	memcpy(msg->keyfile,cardfile,sizeof(cardfile));
	if(pin)strcpy(msg->pin,pin);
	msg->nopin=pin?0:1;
	msg->mode0=1;

	if((fd=starthelper(helper))==-1)goto err1;
	if(write(fd,msg,sizeof(MESSAGE))!=sizeof(MESSAGE))goto err2;
	p.events=POLLIN;
	p.fd=fd;
	if(poll(&p,1,10000)!=1||!(p.revents&POLLIN))goto err2;
	if(read(fd,msg,sizeof(MESSAGE))!=sizeof(MESSAGE))goto err2;
	r=0;
err2:   close(fd);
err1:   if(r)memclear(msg,0,sizeof(MESSAGE));
	return r;
}

static int reader(int s,unsigned char *bfr)
{
	int i;
	int l;
	struct pollfd p;

	p.fd=s;
	p.events=POLLIN;

repeat:	while(1)
	{
		switch(poll(&p,1,-1))
		{
		case -1:if(errno==EAGAIN)continue;
		case 0: return -1;
		case 1: break;
		}
		if(p.revents&(POLLERR|POLLHUP))return -1;
		if(!(p.revents&POLLIN))continue;
		break;
	}

	for(i=0;i<keylen;)
	{
		switch(poll(&p,1,1000))
		{
		case -1:if(errno==EAGAIN)continue;
		case 0: goto repeat;
		default:break;
		}
		if(p.revents&(POLLERR|POLLHUP))return -1;
		if(!(p.revents&POLLIN))continue;
		if((l=read(s,bfr+i,keylen-i))<=0)return -1;
		i+=l;
	}

	return 0;
}

static void *worker(void *data)
{
	int s=(int)((long)data);
	int len;
	int i;
	int j;
	union
	{
		REQUEST *req;
		REPLY *ans;
		unsigned char *ptr;
	} u;
	void *enc;
	unsigned char bfr[2048];
	MESSAGE msg;

	if(sizeof(bfr)>=keylen)while(1)
	{
		if(reader(s,bfr))break;

		pthread_mutex_lock(&mtx);
		if(rsadec(key,bfr,keylen,(void **)&u,&len))goto err1;
		if(len!=sizeof(REQUEST))goto err2;
		for(i=HASHSIZE,j=0;i<sizeof(REQUEST);i++)
		{
			u.ptr[i]^=u.ptr[j];
			if(++j==HASHSIZE)j=0;
		}
		sha256(u.ptr+HASHSIZE,sizeof(REQUEST)-HASHSIZE,bfr);
		if(memcmp(u.ptr,bfr,HASHSIZE))goto err2;
		for(i=0;i<USERSIZE&&u.req->user[i];i++);
		if(!i||i==USERSIZE)goto err2;
		if(strlen(prefix)+i+1>=DIRSIZE)goto err2;
		if(!(u.req->flags&0x80))
		{
			if(nopin)goto err2;
			for(i=0;i<PINSIZE&&u.req->pin[i];i++)
				if(u.req->pin[i]<'0'||u.req->pin[i]>'9')
					goto err2;
			if(!i||i==PINSIZE)goto err2;
		}
		pthread_mutex_unlock(&mtx);

		if(run(u.req->user,(u.req->flags&0x80)?NULL:u.req->pin,cfgfile,
			opensc,&msg))u.ans->result=1;
		else
		{
			u.ans->result=(msg.cmdres==OK?0:1);
			memclear(&msg,0,sizeof(MESSAGE));
		}

		pthread_mutex_lock(&mtx);
		sha256(u.ptr+HASHSIZE,sizeof(REPLY)-HASHSIZE,u.ptr);
		for(i=HASHSIZE,j=0;i<sizeof(REPLY);i++)
		{
			u.ptr[i]^=u.ptr[j];
			if(++j==HASHSIZE)j=0;
		}

		if(rsaenc(key,u.ans,sizeof(REPLY),&enc,&len))goto err2;
		i=write(s,enc,len);
		memclear(enc,0,len);
		free(enc);

err2:		memclear(u.req,0,sizeof(REQUEST));
		free(u.req);
err1:		pthread_mutex_unlock(&mtx);
		memclear(bfr,0,sizeof(bfr));
	}

	close(s);
	pthread_exit(NULL);
}

static int usage(void)  
{       
	fprintf(stderr,"Usage: pivd [<options>]\n" );
	fprintf(stderr,"Options:\n");
	fprintf(stderr,"-p <pidfile> (default: /var/run/pivd.pid)\n");
	fprintf(stderr,"-s <socket>  (default: /var/run/pivd.sock)\n");
	fprintf(stderr,"-k <key>     (default: /etc/pam_pivcard/pivd.key)\n");
	fprintf(stderr,"-[n] <slot>  key slot (01-04) for reader [n] (1-9)\n");
	fprintf(stderr,"-H <path>    helper (" DFTHELPER ")\n");
	fprintf(stderr,"-c <path>    helper configuration file\n");
	fprintf(stderr,"-E <path>    OpenSSL engine (" DFTENGINE ")\n");
	fprintf(stderr,"-P <path>    OpenSC PKCS11 library (" DFTPKCS11 ")\n");
	fprintf(stderr,"-o <path>    optional OpenSC private configuration\n");
	fprintf(stderr,"-L <port>    optional listening port (1-65535)\n");
	fprintf(stderr,"-X <prefix>  optional user prefix\n");
	fprintf(stderr,"-N           disallow PINs\n");
	fprintf(stderr,"-f           stay in foreground\n");
	fprintf(stderr,"-h           this help text\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int f=0;
	int p=0;
	int n=-1;
	FILE *fp;
	struct pollfd pp[2];
	pthread_t hh;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);

	strcpy(cardfile[0],DFTFILE);

	while((c=getopt(argc,argv,
		"k:p:s:fh1:2:3:4:5:6:7:8:9:c:o:H:E:P:L:X:N"))!=-1)switch(c)
	{
	case 'p':
		pidfile=optarg;
		break;
	case 's':
		path=optarg;
		break;
	case 'f':
		f=1;
		break;
	case 'k':
		keyfile=optarg;
		break;
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		snprintf(cardfile[c-'1'],PINSIZE,"0%c:%s",c,optarg);
		break;
	case 'c':
		cfgfile=optarg;
		break;
	case 'o':
		opensc=optarg;
		break;
	case 'H':
		helper=optarg;
		break;
	case 'E':
		engine=optarg;
		break;
	case 'P':
		pkcs11=optarg;
		break;
	case 'L':
		p=atoi(optarg);
		break;
	case 'X':
		prefix=optarg;
		break;
	case 'N':
		nopin=1;
		break;
	case 'h':
	default:usage();
	}

	if(!cfgfile||strlen(cfgfile)>=CONFSIZE||*cfgfile!='/')return 1;
	if(opensc)if(strlen(opensc)>=CONFSIZE-12||*opensc!='/')return 1;
	if(strlen(engine)>=DIRSIZE||strlen(pkcs11)>=DIRSIZE)return 1;
	if(*helper!='/')return 1;

	if(p)if((n=mknet(p))==-1)return 1;
	if((c=mkunix(path))==-1)return 1;

	signal(SIGINT,handler);
	signal(SIGHUP,handler);
	signal(SIGQUIT,handler);
	signal(SIGTERM,handler);
	signal(SIGPIPE,SIG_IGN);

	if(!(key=getkey(keyfile)))return 1;
	if(!(keylen=keysize(key))||keylen<sizeof(REQUEST))
	{
		freekey(key);
		return 1;
	}

	if(!f)
	{
		if(daemon(0,0))
		{
			perror("daemon");
			return 1;
		}
		if((fp=fopen(pidfile,"we")))
		{
			fprintf(fp,"%d\n",getpid());
			fclose(fp);
		}
	}
	else pidfile=NULL;

	pp[0].fd=c;
	pp[0].events=POLLIN;
	pp[1].fd=n;
	pp[1].events=POLLIN;
	pp[1].revents=0;
	n=(n==-1?1:2);

	while(1)
	{
		if(poll(pp,n,-1)<1)continue;
		if(pp[0].revents&POLLIN)
			if((f=accept4(pp[0].fd,NULL,NULL,SOCK_CLOEXEC))!=-1)
		{
			if(pthread_create(&hh,&attr,worker,(void *)((long)f)))
				close(f);
		}

		if(pp[1].revents&POLLIN)
			if((f=accept4(pp[1].fd,NULL,NULL,SOCK_CLOEXEC))!=-1)
		{
			c=1;
			if(setsockopt(f,IPPROTO_TCP,TCP_NODELAY,&c,sizeof(c)))
			{
				close(f);
				continue;
			}
			if(pthread_create(&hh,&attr,worker,(void *)((long)f)))
				close(f);
		}
	}

	return 0;
}
