sbin_PROGRAMS = pivd pivclient

libexec_PROGRAMS = pivhelper pivforwarder

man_MANS = pam_pivcard.8 pam_pivrmt.8 pam_pivnet.8 pivd.1 pivclient.1

noinst_HEADERS = common.h

pivhelper_CFLAGS = -Wall -O3
pivhelper_LDADD = -lcrypto

pivforwarder_CFLAGS = -Wall -O3
pivforwarder_LDADD = -lcrypto

pivclient_CFLAGS = -Wall -O3
pivclient_LDADD = -lcrypto

pivd_CFLAGS = -Wall -O3 -D'DFTHELPER="$(libexecdir)/pivhelper"' -D'DFTENGINE="$(exec_prefix)$(libdir)/engines/engine_pkcs11.so"' -D'DFTPKCS11="$(exec_prefix)$(libdir)/opensc-pkcs11.so"'
pivd_LDADD = -lcrypto -lpthread

securelib_LTLIBRARIES = pam_pivcard.la pam_pivrmt.la pam_pivnet.la
securelibdir = $(libdir)/security

pam_pivcard_la_CFLAGS = -Wall -O3 -fPIC -D'DFTHELPER="$(libexecdir)/pivhelper"' -D'DFTDIR="$(sysconfdir)/pam_pivcard/data"' -D'DFTENGINE="$(exec_prefix)$(libdir)/engines/engine_pkcs11.so"' -D'DFTPKCS11="$(exec_prefix)$(libdir)/opensc-pkcs11.so"'
pam_pivcard_la_LDFLAGS = -shared -rdynamic -no-undefined -avoid-version -module -Wl,-x -Wl,-S
pam_pivcard_la_LIBADD = -lpam

pam_pivrmt_la_CFLAGS = -Wall -O3 -fPIC -D'DFTHELPER="$(libexecdir)/pivforwarder"'
pam_pivrmt_la_LDFLAGS = -shared -rdynamic -no-undefined -avoid-version -module -Wl,-x -Wl,-S
pam_pivrmt_la_LIBADD = -lpam

pam_pivnet_la_CFLAGS = -Wall -O3 -fPIC -D'DFTHELPER="$(libexecdir)/pivforwarder"'
pam_pivnet_la_LDFLAGS = -shared -rdynamic -no-undefined -avoid-version -module -Wl,-x -Wl,-S
pam_pivnet_la_LIBADD = -lpam

install-exec-hook:
	strip  $(libexecdir)/pivhelper
	strip  $(libexecdir)/pivforwarder
	strip  $(sbindir)/pivd

install-data-hook:
	rm -f $(securelibdir)/pam_pivcard.la
	rm -f $(securelibdir)/pam_pivrmt.la
	rm -f $(securelibdir)/pam_pivnet.la
	mkdir -p -m 0755 $(sysconfdir)/pam_pivcard/data
	[ ! -f /etc/pam_pivcard/pivd.key ] && ( umask 077 ; openssl genrsa -out /etc/pam_pivcard/pivd.key 2048 2> /dev/null ) || echo "Not replacing the exisiting RSA private key"
	[ ! -f /etc/pam_pivcard/piv.pub ] && ( umask 077 ; openssl rsa -in /etc/pam_pivcard/pivd.key -pubout -out /etc/pam_pivcard/piv.pub ) || echo "Not replacing the exisiting RSA public key"
