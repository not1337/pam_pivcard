#!/bin/bash
#
# (C) 2015,2016 Andreas Steinmetz, ast@domdv.de
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
#
generate()
{
datim=`date +%s`
let datim=$datim-2592000
datim="`date --date=@$datim`"

if [ -f "$FBASE.key" -o -f "$FBASE.cert" -o -f "$FBASE.pub" ]
then
	echo "key already exists"
	return 1
fi
rm -f $FBASE.csr
umask 077
openssl genrsa -out $FBASE.key -aes256 -passout env:KEY 2048 || return 1
umask 022
TMPFILE=`mktemp`
cat << EOF > $TMPFILE
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
CN=$FQDN
EOF
openssl req -new -sha256 -config $TMPFILE -key $FBASE.key -passin env:KEY -out $FBASE.csr || { rm -f $TMPFILE ; return 1 ; }
rm -f $TMPFILE
datefudge "$datim" openssl x509 -sha256 -req -days 100000 -passin env:KEY -in $FBASE.csr -signkey $FBASE.key -out $FBASE.cert || return 1
env DISPLAY=:0 SSH_ASKPASS=$0 ssh-keygen -y -f $FBASE.key < /dev/null > $FBASE.pub || return 1
rm $FBASE.csr
return 0
}

key2piv()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
if [ "$MGMTKEY" != "" ]
then
	mgmt="--key=$MGMTKEY"
else
	mgmt=""
fi
if [ ! -f "$FBASE.key" -o ! -f "$FBASE.cert" ]
then
	echo "key doesn't exist"
	return 1
fi
openssl rsa -in $FBASE.key -passin env:KEY -passout pass: 2> /dev/null | yubico-piv-tool $mgmt -s $SLOT -a import-key -i - "$opt$dev" || return 1
yubico-piv-tool $mgmt -s $SLOT -a import-certificate -i $FBASE.cert "$opt$dev" || return 1
return 0
}

delfrompiv()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
if [ "$MGMTKEY" != "" ]
then
	mgmt="--key=$MGMTKEY"
else
	mgmt=""
fi
yubico-piv-tool $mgmt -s $SLOT -a delete-certificate "$opt$dev" || return 1
return 0
}

genuid()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
if [ "$MGMTKEY" != "" ]
then
	mgmt="--key=$MGMTKEY"
else
	mgmt=""
fi
yubico-piv-tool $mgmt -a set-chuid "$opt$dev" || return 1
return 0
}

setpin()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
yubico-piv-tool -P 123456 -N "$PIN" -a change-pin "$opt$dev" || return 1
return 0
}

clrpin()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
yubico-piv-tool -N 123456 -P "$PIN" -a change-pin "$opt$dev" || return 1
return 0
}

setpuk()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
yubico-piv-tool -P 12345678 -N $PUK -a change-puk "$opt$dev" || return 1
return 0
}

clrpuk()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
yubico-piv-tool -N 12345678 -P $PUK -a change-puk "$opt$dev" || return 1
return 0
}

dorst()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
yubico-piv-tool -a reset "$opt$dev" || return 1
return 0
}

unblock()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
yubico-piv-tool -N 123456 -P $PUK -a unblock-pin "$opt$dev" || return 1
return 0
}

setmgmt()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
if [ "$MGMTKEY" = "" ]
then
	echo "need new management key to continue"
	return 1
fi
yubico-piv-tool --key=010203040506070801020304050607080102030405060708 -n $MGMTKEY -a set-mgm-key "$opt$dev" || return 1
return 0
}

clrmgmt()
{
if [ "$SERIAL" != "" ]
then
	dev=`opensc-tool -l | grep 'Yubikey NEO .* (0*'"$SERIAL"')' | sed -e 's/).*/)/' -e 's/^[0-9]\+[ ]\+[^ ]\+[ ]\+//'`
	opt="--reader="
else
	dev=""
	opt=""
fi
if [ "$MGMTKEY" = "" ]
then
	echo "need current management key to continue"
	return 1
fi
yubico-piv-tool --key=$MGMTKEY -n 010203040506070801020304050607080102030405060708 -a set-mgm-key "$opt$dev" || return 1
return 0
}

usage()
{
cat - << EOF 1>&2
Usage:

pivscript.sh <command> [<command> ...]

Commands are:

generate	generate a new RSA key pair and a ssh usable public key
newkey		install a new management key (uses random key on request)
clrkey		reset management key to default (requires current key)
newuid		set new card holder unique identifier (CHUID)
remove		remove private and public key from card
install		install private and public key to card
setpin		change PIN from factory default to user defined value
clrpin		change PIN from user defined value to factory default
unblock		reset blocked PIN to factory default
setpuk		change PUK from factory default to user defined value
clrpuk		change PUK from user defined value to factory default
reset		reset PIV applet (needs PIN and PUK to be blocked)

Command Parameters (as required):

key base pathname	The base pathname of the key to be generated or used.
			<pathname>.key contains the private key
			<pathname>.cert contains the public key certificate
			<pathname>.pub contains the public key in ssh format
key passphrase		The passphrase for the <pathname>.key file
FQDN for certificate	An arbitrary string identifying the certificate
PIV key slot		PIV slot to use, see below
Yubikey serial number	optional, to select the proper Yubikey device
			(needs serial number to be USB visible)
Yubikey Management key	The new management key to use or the current key
			In case of 'newkey' (see above) if the new management
			key is not specified a random management key is
			generated, printed to screen and then installed.
			You need the management key for any management
			operation (install or delete key/certificate pairs,
			set a new CHUID)
PIN			New or current PIN for the PIV applet
PUK			New or current PUK for the PIV applet

Slot Information:

9a	Authentication (PIN checked on first use)
9c	Digital Signature (PIN always checked)
9d	Key Management (PIN checked on first use)
9e	Card Authentication (PIN never checked)

You can use the slots as you wish for your own purposes.

If you lose your management key do the following to restart from scratch:

1. Lock the PIN by retrying with the wrong PIN
2. Lock the PUK by retrying with the wrong PUK
3. Reset the PIV applet with the 'reset' command

Note that all key/certificate pairs as well as the CHUID are cleared by
this operation!

EOF
exit 1
}

export LANG=C

if [ "$SSH_ASKPASS" = "$0" ]
then
	cat - <<EOF
$KEY
EOF
	exit 0
fi

for i in yubico-piv-tool openssl datefudge ssh-keygen opensc-tool hexdump mktemp
do
	which $i > /dev/null 2>&1
	if [ $? != 0 ]
	then
		echo "$missing $i, cannot continue"
		exit 1
	fi
done

uid=0
gen=0
cpy=0
del=0
pinset=0
pinclr=0
mgmtset=0
mgmtclr=0
ublk=0
pukset=0
pukclr=0
rset=0

while [ "$1" != "" ]
do
	case "$1" in
	newuid)		uid=1
			;;
	generate)	gen=1
			;;
	install)	cpy=1
			;;
	remove)		del=1
			;;
	newkey)		mgmtset=1
			;;
	clrkey)		mgmtclr=1
			;;
	setpin)		pinset=1
			;;
	clrpin)		pinclr=1
			;;
	unblock)	ublk=1
			;;
	setpuk)		pukset=1
			;;
	clrpuk)		pukclr=1
			;;
	reset)		rset=1
			;;
	*)		usage
			;;
	esac
	shift
done

if [ $mgmtset = 1 -a $mgmtclr = 1 ]
then
	usage
fi

if [ $pinset = 1 -a $pinclr = 1 ]
then
	usage
fi

if [ $pukset = 1 -a $pukclr = 1 ]
then
	usage
fi

if [ $uid = 0 -a $gen = 0 -a $cpy = 0 -a $del = 0 -a $pinset = 0 -a $pinclr = 0 -a $mgmtset = 0 -a $mgmtclr = 0 -a $ublk = 0 -a $pukset = 0 -a $pukclr = 0 -a $rset = 0 ]
then
	usage
fi

if [ $gen = 1 -o $cpy = 1 ]
then
	echo -n "Enter key base pathname: "
	read FBASE
	stty -echo
	echo -n "Enter key passphrase: "
	read KEY
	echo ""
	echo -n "Repeat key passphrase: "
	read KEY2
	echo ""
	stty echo
	if [ "$FBASE" = "" ]
	then
		echo "missing key base pathname"
		exit 1
	fi
	if [ "$KEY" = "" ]
	then
		echo "Empty passphrase not allowed"
		exit 1
	fi
	if [ "$KEY" != "$KEY2" ]
	then
		echo "Passphrase mismatch"
		exit 1
	fi
	export FBASE KEY
fi

if [ $gen = 1 ]
then
	echo -n "Enter FQDN for certificate: "
	read FQDN
	export FQDN
fi

if [ $pinset = 1 -o $pinclr = 1 ]
then
	echo -n "Enter PIN: "
	read PIN
	export PIN
fi

if [ $ublk = 1 -o $pukset = 1 -o $pukclr = 1 ]
then
	echo -n "Enter PUK: "
	read PUK
	if [ "$PUK" = "" ]
	then
		echo "need PUK to continue"
		exit 1
	fi
	export PUK
fi

if [ $cpy = 1 -o $del = 1 ]
then
	echo -n "Enter PIV key slot (9a,9c,9d,9e): "
	read SLOT
	case "$SLOT" in
	9a|9c|9d|9e)	;;
	*)		echo "illegal slot"
			exit 1
			;;
	esac
	export SLOT
fi

if [ $uid = 1 -o $cpy = 1 -o $del = 1 -o $mgmtset = 1 -o $mgmtclr = 1 -o $pinset = 1 -o $pinclr = 1 ]
then
	echo -n "Enter Yubikey serial number (opt): "
	read SERIAL
	if [ "$SERIAL" != "" ]
	then
		export SERIAL
	else
		unset SERIAL
	fi
fi

if [ $uid = 1 -o $cpy = 1 -o $del = 1 -o $mgmtset = 1 -o $mgmtclr = 1 ]
then
	echo -n "Enter Yubikey Management key (opt): "
	read MGMTKEY
	if [ "$MGMTKEY" != "" ]
	then
		export MGMTKEY
	else
		unset MGMTKEY
	fi
fi

if [ $mgmtset = 1 -a "$MGMTKEY" = "" ]
then
	MGMTKEY=`dd if=/dev/urandom bs=1 count=24 status=none | hexdump -v -e '1/1 "%02x"'`
	echo "New management key: $MGMTKEY"
	export MGMTKEY
fi

if [ $gen = 1 ]
then
	generate || exit 1
fi

if [ $rset = 1 ]
then
	dorst || exit 1
fi

if [ $mgmtset = 1 ]
then
	setmgmt || exit 1
fi

if [ $mgmtclr = 1 ]
then
	clrmgmt || exit 1
	unset MGMTKEY
fi

if [ $pukset = 1 ]
then
	setpuk || exit 1
fi

if [ $pukclr = 1 ]
then
	clrpuk || exit 1
	export PUK=12345678
fi

if [ $ublk = 1 ]
then
	unblock || exit 1
fi

if [ $pinset = 1 ]
then
	setpin || exit 1
fi

if [ $pinclr = 1 ]
then
	clrpin || exit 1
	export PIN=123456
fi

if [ $del = 1 ]
then
	delfrompiv || exit 1
fi

if [ $uid = 1 ]
then
	genuid || exit 1
fi

if [ $cpy = 1 ]
then
	key2piv || exit 1
fi

echo "**** SUCCESS ****"
exit 0
