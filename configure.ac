AC_INIT([pam_pivcard], [1.0.0])
AC_CONFIG_SRCDIR([src/pam_pivcard.c])
AM_INIT_AUTOMAKE
LT_INIT
AM_CONFIG_HEADER(config.h)
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_LIB(crypto,ENGINE_init,,AC_MSG_ERROR([Cannot find libcrypto]))
AC_CHECK_LIB(pam,pam_get_user,,AC_MSG_ERROR([Cannot find libpam]))
AC_CHECK_HEADERS([security/pam_appl.h security/pam_modules.h openssl/engine.h openssl/evp.h openssl/pem.h])
AC_PREFIX_DEFAULT(/usr)
test "${prefix}" = "NONE" && prefix="/usr"
if test ${prefix} = '/usr'
then
	if test ${sysconfdir} = '${prefix}/etc'
	then
		sysconfdir="/etc"
	fi
	if test ${libdir} = '${exec_prefix}/lib'
	then
		case "`uname -m`" in
		    x86_64|ppc64|s390x|sparc64)
			libdir="/lib64" ;;
		    *)
			libdir="/lib" ;;
		esac
	fi
	if test ${includedir} = '${prefix}/include'
	then
		includedir="${prefix}/include/security"
	fi
	if test ${localstatedir} = '${prefix}/var'
	then
		localstatedir="/var"
	fi
fi
LIBS=
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
