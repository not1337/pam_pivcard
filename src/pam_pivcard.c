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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "common.h"

typedef struct
{
	int passvalid;
	int nopass;
	char pin[PINSIZE];
	char pass[PASSSIZE];
	char user[USERSIZE];
} MEM;

typedef struct
{
	char *item;
	int len;
	int index;
	int size;
} PARAM;

#define TRYFIRST	0
#define USEFIRST	1
#define NOPIN		2
#define NODEVOK		3
#define DOFAIL		4
#define OPENSC		5
#define HELPER		6
#define PASSDIR		7
#define ENGINE		8
#define PKCS11		9
#define CFGFILE		10
#define KEYFILE1	11
#define KEYFILE2	12
#define KEYFILE3	13
#define KEYFILE4	14
#define KEYFILE5	15
#define KEYFILE6	16
#define KEYFILE7	17
#define KEYFILE8	18
#define KEYFILE9	19
#define TOTALPARAMS	20

static PARAM config[TOTALPARAMS]=
{
	{"try_first_pass",0,TRYFIRST,0},
	{"use_first_pass",0,USEFIRST,0},
	{"nopin",0,NOPIN,0},
	{"nodevok",0,NODEVOK,0},
	{"dofail",0,DOFAIL,0},
	{"opensc_config=",14,OPENSC,CONFSIZE-12},
	{"helper=",7,HELPER,0},
	{"passfiledir=",12,PASSDIR,PASSSIZE},
	{"engine=",7,ENGINE,DIRSIZE},
	{"pkcs11=",7,PKCS11,DIRSIZE},
	{"userfile=",9,CFGFILE,CONFSIZE},
	{"keyfile=",8,KEYFILE1,PINSIZE},
	{"keyfile2=",9,KEYFILE2,PINSIZE},
	{"keyfile3=",9,KEYFILE3,PINSIZE},
	{"keyfile4=",9,KEYFILE4,PINSIZE},
	{"keyfile5=",9,KEYFILE5,PINSIZE},
	{"keyfile6=",9,KEYFILE6,PINSIZE},
	{"keyfile7=",9,KEYFILE7,PINSIZE},
	{"keyfile8=",9,KEYFILE8,PINSIZE},
	{"keyfile9=",9,KEYFILE9,PINSIZE},
};

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
		case 0:	fcntl(s[1],F_SETFD,fcntl(s[1],F_GETFD)&~FD_CLOEXEC);
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

static int preprocess(pam_handle_t *pamh,const char **user,const char **pass,
	int try_first_pass,int use_first_pass,int nopin)
{
	int r;
	struct pam_conv *cnv;
	struct pam_message msg;
	struct pam_message *mptr=&msg;
	struct pam_response *rsp=NULL;

	if((r=pam_get_user(pamh,user,NULL))!=PAM_SUCCESS)return r;

	if(nopin)return PAM_SUCCESS;

	if(try_first_pass||use_first_pass)
	{
		if((r=pam_get_item(pamh,PAM_AUTHTOK,(const void **)pass))!=
			PAM_SUCCESS)return r;

		if(use_first_pass&&!*pass)return PAM_AUTH_ERR;
	}

	if(!*pass)
	{
		if((r=pam_get_item(pamh,PAM_CONV,(const void **)&cnv))!=
			PAM_SUCCESS)return r;

		msg.msg_style=PAM_PROMPT_ECHO_OFF;
		msg.msg="Enter PIN: ";

		if((r=cnv->conv(1,(const struct pam_message **)&mptr,&rsp,
			cnv->appdata_ptr))!=PAM_SUCCESS)return r;

		if(!(*pass=rsp->resp))return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

static int notify(pam_handle_t *pamh,int flags,char *msg,int type)
{
	int r;
	struct pam_conv *cnv;
	struct pam_message pmsg;
	struct pam_message *mptr=&pmsg;
	struct pam_response *rsp=NULL;

	if(flags&PAM_SILENT)return PAM_SUCCESS;

	if((r=pam_get_item(pamh,PAM_CONV,(const void **)&cnv))!=PAM_SUCCESS)
		return r;

	pmsg.msg_style=type;
	pmsg.msg=msg;

	return cnv->conv(1,(const struct pam_message **)&mptr,
		&rsp,cnv->appdata_ptr);
}

static void clear(pam_handle_t *pamh,void *data,int error_status)
{
	MEM *mem=data;

	if(mem)
	{
		memclear(mem,0,sizeof(MEM));
		free(mem);
	}
}

static int parse(int argc,const char **argv,char **params)
{
	int i;
	int j;

	memset(params,0,TOTALPARAMS*sizeof(char *));

	for(j=0;j<argc;j++)
	{
		for(i=0;i<TOTALPARAMS;i++)if(!config[i].len)
		{
			if(!strcmp(argv[j],config[i].item))
			{
				params[i]=(char *)argv[j];
				break;
			}
		}
		else if(!strncmp(argv[j],config[i].item,config[i].len))
		{
			params[i]=(char *)argv[j]+config[i].len;
			break;
		}
	}

	if(!params[HELPER])params[HELPER]=DFTHELPER;
	if(!params[PASSDIR])params[PASSDIR]=DFTDIR;
	if(!params[KEYFILE1])params[KEYFILE1]=DFTFILE;
	if(!params[ENGINE])params[ENGINE]=DFTENGINE;
	if(!params[PKCS11])params[PKCS11]=DFTPKCS11;

	for(i=0;i<TOTALPARAMS;i++)if(params[i]&&config[i].size)
		if(strlen(params[i])>=config[i].size)return -1;

	return 0;
}

static int run(int cmd,int flag,char **params,const char *user,const char *pin,
	const char *pass,MESSAGE *msg)
{
	int r=-1;
	int fd;
	struct pollfd p;

	memset(msg,0,sizeof(MESSAGE));
	msg->cmdres=cmd;
	if(params[OPENSC])
	{
		strcpy(msg->openscconf,"OPENSC_CONF=");
		strcat(msg->openscconf,params[OPENSC]);
	}
	strcpy(msg->passfile,params[PASSDIR]);
	if(user)
	{
		strcat(msg->passfile,"/");
		strcat(msg->passfile,user);
	}
	strcpy(msg->engine,params[ENGINE]);
	strcpy(msg->pkcs11,params[PKCS11]);
	if(params[CFGFILE])strcpy(msg->cfgfile,params[CFGFILE]);
	for(fd=0;fd<MAXFILES;fd++)strcpy(msg->keyfile[fd],params[KEYFILE1+fd]);
	if(pin)strcpy(msg->pin,params[NOPIN]?"":pin);
	if(pass)strcpy(msg->pass,pass);
	msg->nopin=params[NOPIN]?1:0;
	msg->precheck=flag;

	if((fd=starthelper(params[HELPER]))==-1)goto err1;
	if(write(fd,msg,sizeof(MESSAGE))!=sizeof(MESSAGE))goto err2;
	p.events=POLLIN;
	p.fd=fd;
	if(poll(&p,1,10000)!=1||!(p.revents&POLLIN))goto err2;
	if(read(fd,msg,sizeof(MESSAGE))!=sizeof(MESSAGE))goto err2;
	r=0;
err2:	close(fd);
err1:	if(r)memclear(msg,0,sizeof(MESSAGE));
	return r;
}

static int pinchk(const char *pin)
{
	int i;

	if(pin)
	{
		for(i=0;pin[i];i++)if(pin[i]<'0'||pin[i]>'9')
			return PAM_AUTH_ERR;
		if(i>=PINSIZE)return PAM_AUTH_ERR;
	}
	return PAM_SUCCESS;
}

static int puchk(const char *user,char **params)
{
	if(*params[PASSDIR]!='/')return PAM_SERVICE_ERR;
	if(strlen(params[PASSDIR])+strlen(user)+1>=DIRSIZE)return PAM_AUTH_ERR;
	if(!*user||!strcmp(user,".")||!strcmp(user,"..")||strchr(user,'/')||
		strlen(user)>=USERSIZE)return PAM_AUTHINFO_UNAVAIL;
	return PAM_SUCCESS;
}

static int ignore(pam_handle_t *pamh,int flags,char **params,MESSAGE *msg,
	char *txt)
{
	int r=PAM_SUCCESS;

	switch(msg->cmdres)
	{
	case NOCARD:
		if(params[NODEVOK])break;
	case ENGFAIL:
	case FILEFAIL:
	case CRYPTOFAIL:
		r=PAM_PERM_DENIED;
	case NOUSER:
		break;
	}

	if(msg->cmdres&&r==PAM_SUCCESS)notify(pamh,flags,txt,PAM_TEXT_INFO);

	memclear(msg,0,sizeof(MESSAGE));
	return r;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	int r;
	const char *user=NULL;
	const char *pass=NULL;
	char *params[TOTALPARAMS];
	MESSAGE msg;

	if(parse(argc,argv,params))return PAM_SERVICE_ERR;

	if((r=preprocess(pamh,&user,&pass,params[TRYFIRST]?1:0,
		params[USEFIRST]?1:0,params[NOPIN]?1:0)!=PAM_SUCCESS))goto err1;

	if((r=pinchk(pass))!=PAM_SUCCESS)goto err1;
	if((r=puchk(user,params))!=PAM_SUCCESS)goto err1;

	if(run(GETPASS,0,params,user,pass,NULL,&msg))
	{
		r=PAM_AUTHINFO_UNAVAIL;
		goto err1;
	}
	if(msg.cmdres!=OK)r=PAM_AUTH_ERR;
	else if(msg.nopass)r=PAM_SUCCESS;
	else
	{
		r=PAM_IGNORE;
		pam_set_item(pamh,PAM_AUTHTOK,(const void **)(&msg.pass));
	}

	memclear(&msg,0,sizeof(msg));
err1:	if(r!=PAM_SUCCESS&&!params[DOFAIL])r=PAM_IGNORE;
	return r;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	int r;
	int nopass=0;
	const char *user=NULL;
	const char *pass=NULL;
	const char *newpass=NULL;
	char *params[TOTALPARAMS];
	MEM *mem;
	MESSAGE msg;

	if(parse(argc,argv,params))return PAM_SERVICE_ERR;

	if(flags&PAM_PRELIM_CHECK)
	{
		if((r=pam_get_item(pamh,PAM_AUTHTOK,(const void **)&newpass))!=
			PAM_SUCCESS)if(r!=PAM_PERM_DENIED)return r;

		if(newpass&&strlen(newpass)>=sizeof(msg.pass))
			return PAM_AUTH_ERR;

		if((r=preprocess(pamh,&user,&pass,0,0,params[NOPIN]?1:0))!=
			PAM_SUCCESS)return r;

		if(pinchk(pass)!=PAM_SUCCESS)return PAM_CRED_INSUFFICIENT;
		if((r=puchk(user,params))!=PAM_SUCCESS)return r;

		if(run(SETPASS,1,params,user,pass,NULL,&msg))
			return PAM_AUTHINFO_UNAVAIL;
		nopass=msg.nopass;

		if(msg.cmdres!=OK)
		{
			if((r=ignore(pamh,flags,params,&msg,"Warning: token "
				"not available"))!=PAM_SUCCESS)return r;
		}
		else memclear(&msg,0,sizeof(msg));

		if(!(mem=malloc(sizeof(MEM))))return PAM_BUF_ERR;

		strcpy(mem->pin,params[NOPIN]?"":pass);
		strcpy(mem->user,user);
		if(newpass)
		{
			strcpy(mem->pass,newpass);
			mem->passvalid=1;
		}
		else mem->passvalid=0;
		mem->nopass=nopass;

		if((r=pam_set_data(pamh,"pam_pivcard",mem,clear))!=PAM_SUCCESS)
		{
			memclear(mem,0,sizeof(MEM));
			free(mem);
			return r;
		}

		return PAM_SUCCESS;
	}

	if(!(flags&PAM_UPDATE_AUTHTOK))return PAM_SERVICE_ERR;

	if((r=pam_get_data(pamh,"pam_pivcard",(const void **)&mem))!=
		PAM_SUCCESS)
	{
		if(r!=PAM_NO_MODULE_DATA)return r;

		if((r=pam_get_item(pamh,PAM_AUTHTOK,(const void **)newpass))!=
			PAM_SUCCESS)return r;

		if(!newpass||strlen(newpass)>=sizeof(msg.pass))
			return PAM_AUTH_ERR;

		if((r=preprocess(pamh,&user,&pass,0,0,params[NOPIN]?1:0))!=
			PAM_SUCCESS)return r;

		if(pinchk(pass)!=PAM_SUCCESS)return PAM_CRED_INSUFFICIENT;
	}
	else if(mem->nopass)return PAM_SUCCESS;
	else if(!mem->passvalid)
	{
		if((r=pam_get_item(pamh,PAM_AUTHTOK,(const void **)&newpass))!=
			PAM_SUCCESS||!newpass)return r;

		if(strlen(newpass)>=sizeof(msg.pass))return PAM_AUTH_ERR;
		strcpy(mem->pass,newpass);
	}

	if(run(SETPASS,0,params,mem?mem->user:user,
		params[NOPIN]?"":mem?mem->pin:pass,mem?mem->pass:newpass,&msg))
		return PAM_AUTHINFO_UNAVAIL;

	if(msg.cmdres!=OK)
	{
		if((r=ignore(pamh,flags,params,&msg,"Warning: token password "
			"not updated"))!=PAM_SUCCESS)return r;
	}
	else memclear(&msg,0,sizeof(msg));

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

struct pam_module _pam_neototp_modstruct=
{
	"pam_pivcard",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif
