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

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "common.h"

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

static int run(const char *user,const char *pin,const char *key,const char *dev,
	const char *lock,const char *helper)
{
	int r=PAM_AUTHINFO_UNAVAIL;
	int fd;
	struct pollfd p;
	FWDREQUEST req;
	FWDREPLY ans;

	memset(&req,0,sizeof(FWDREQUEST));
	strncpy(req.user,user,USERSIZE);
	if(pin)strncpy(req.pin,pin,PINSIZE);
	else req.nopin=1;
	strncpy(req.key,key,CONFSIZE-1);
	strncpy(req.dev,dev,CONFSIZE-1);
	strncpy(req.lock,lock,CONFSIZE-1);

	if((fd=starthelper(helper))==-1)goto err1;
	if(write(fd,&req,sizeof(FWDREQUEST))!=sizeof(FWDREQUEST))goto err2;
	p.events=POLLIN;
	p.fd=fd;
	if(poll(&p,1,10000)!=1||!(p.revents&POLLIN))goto err2;
	if(read(fd,&ans,sizeof(FWDREPLY))!=sizeof(FWDREPLY))goto err2;

	if(!ans.result)r=PAM_SUCCESS;
	else r=PAM_AUTH_ERR;

err2:   close(fd);
err1:   memclear(&req,0,sizeof(FWDREQUEST));
	memclear(&ans,0,sizeof(FWDREPLY));
	return r;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	int i;
	int r=PAM_SERVICE_ERR;
	int nopin=0;
	int dofail=0;
	int try_first_pass=0;
	int use_first_pass=0;
	const char *user=NULL;
	const char *pass=NULL;
	const char *key="/etc/pam_pivcard/piv.pub";
	const char *helper=DFTHELPER;
	const char *dev=NULL;
	const char *lock=NULL;
	struct pam_conv *cnv;
	struct pam_message msg;
	struct pam_message *mptr=&msg;
	struct pam_response *rsp=NULL;

	for(i=0;i<argc;i++)if(!strcmp(argv[i],"try_first_pass"))
		try_first_pass=1;
	else if(!strcmp(argv[i],"use_first_pass"))use_first_pass=1;
	else if(!strcmp(argv[i],"nopin"))nopin=1;
	else if(!strcmp(argv[i],"dofail"))dofail=1;
	else if(!strncmp(argv[i],"device=",7))dev=&argv[i][7];
	else if(!strncmp(argv[i],"lock=",5))lock=&argv[i][5];
	else if(!strncmp(argv[i],"helper=",7))helper=&argv[i][7];
	else if(!strncmp(argv[i],"key=",4))key=&argv[i][4];

	if(!dev||!lock)goto out;

	if((r=pam_get_user(pamh,&user,NULL))!=PAM_SUCCESS)goto out;

	if(!nopin)if(try_first_pass||use_first_pass)
	{
		if((r=pam_get_item(pamh,PAM_AUTHTOK,(const void **)&pass))!=
			PAM_SUCCESS)goto out;

		if(use_first_pass&&!*pass)
		{
			r=PAM_AUTH_ERR;
			goto out;
		}
	}

	if(!nopin&&!pass)
	{
		if((r=pam_get_item(pamh,PAM_CONV,(const void **)&cnv))!=
			PAM_SUCCESS)goto out;

		msg.msg_style=PAM_PROMPT_ECHO_OFF;
		msg.msg="Enter PIN: ";

		if((r=cnv->conv(1,(const struct pam_message **)&mptr,&rsp,
			cnv->appdata_ptr))!=PAM_SUCCESS)goto out;

		if(!(pass=rsp->resp))
		{
			r=PAM_AUTH_ERR;
			goto out;
		}
	}

	r=run(user,pass,key,dev,lock,helper);

out:	if(r!=PAM_SUCCESS&&!dofail)r=PAM_IGNORE;
	return r;
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

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,
	const char **argv)
{
	return PAM_PERM_DENIED;
}

#ifdef PAM_STATIC

struct pam_module _pam_rmttotp_modstruct=
{
	"pam_pivrmt",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif
