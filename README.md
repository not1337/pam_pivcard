#pam_pivcard
Easy to use PAM authentication for PIV smartcards.

A PAM modules that allows you to authenticate using a PIV (compatible)
smartcard containing RSA (and possibly EC) keys. Optionally your
plaintext password is stored encrypted and when the smartcard is
present the password is decrypted and inserted onto the PAM stack
for further processing. The latter is supposed to be used in cases
where subsequent PAM modules require a valid plaintext password, e.g.
for browser keystore unlock or subsequent automated remote logon.

pam_pivcard is a convenience module for cases where a complete certificate
infrastructure including certificate verification and revocation is overkill.
Only public/private RSA (or possibly EC) key encryption and decryption is used,
thus there is no validity or expiry date checking, either.

Note that though EC keys should be properly handled I refuse even to
test this due to the fact that PIV only supports the 'r' curves which were
generated with 'generous' NSA 'help' and thus the 'r' is supposed to be
short for 'recoverable'.

For password injection to work the first authentication module must be
pam_pivcard, e.g.:

auth		required	pam_pivcard.so nopin

Now if the PIV smartcard is present you just need to enter 'Return' and your
actual password will be read from a file and decrypted by the PIV smartcard
private key. If there is no PIV smartcard present just enter your password
manually as usual.

To have your PIV smartcard encrypted password changed when you change your
password use the following line as the last "required" password line
in your PAM configuration:

password	required	pam_pivcard.so nopin nodevok

The "nodevok" means that it is ok to change your password while the
PIV smartcard is not present. In that case, you need to change your password
again when your PIV smartcard is present again to be able to use the
smartcard feature again.

If you do not use "dofail" authentication will return PAM_IGNORE in
case of any authentication failure. This allows you to have e.g.
pam_unix save your day as you can enter your password manually then.

Be aware that for KDE you will need to modify /etc/pam.d/kde
(additionally /etc/pam.d/sddm for KDE5) and to have the KDE
screensaver work properly in the unlock case you will have to
modify kcheckpass to be setuid root. You must not, never ever, set
the pivhelper setuid root as the helper returns unencrypted passwords
for injection onto the PAM stack. If you do not follow this advice
any running process on the system will be able to retrieve your
login password while your PIV smartcard is available, especially if
you chose to use the nopin option.

Note: This PAM module requires OpenSSL with engine support and the
PKCS11 engine for OpenSSL to be installed. Furthermore PC/SC Lite,
the CCID driver for PC/SC Lite as well as OpenSC are required. Finally
a (preferably CCID compliant) smartcard reader and a PIV smartcard
or a PIV usb smartcard like the Yubikey NEO is required. Links:

http://www.openssl.org/
http://pcsclite.alioth.debian.org/
http://pcsclite.alioth.debian.org/ccid.html
https://github.com/OpenSC/OpenSC/wiki
https://github.com/OpenSC/engine_pkcs11
https://github.com/opensc/libp11/wiki
https://www.yubico.com/products/yubikey-hardware/yubikey-neo/
http://www.gemalto.com/products/prox_DU_SU/index.html

The patch for opensc which is contained in this distribution adds an
"allowed_readers" option to opensc that uses the same style as the
"ignored readers" options. I did submit the patch upstream.

The patch for engine_pkcs11 is required if you want to use the nologin
configuration option. This is very useful if you use the 9E slot of
your PIV smartcard for local logon. This slot doesn't require a pin entry
but unfortunately there is no way to tell engine_pkcs11 not to require
a pin for this slot except by using the supplied patch.

The included "pivscript.sh" shell script should simplify card management
for you. Run the script without parameters for usage information.

If you chose to use a configuration file it has to be formatted in
/etc/passwd style with the following fields (multiple entries for
the same user are possible):

<user>:<mode>:<comment>:<certificate>

<user>		the user name as stated in /etc/passwd

<mode>		the operation mode:
		0	no encrypted password stored, challenge
			response verification
		1	encrypted password stored, challenge
			response verification
		2	encrypted password stored, certificate
			must match smartcard
		3	encrypted password stored, certificate
			is ignored

<comment>	an arbitrary comment

<certificate>	The fully qualified pathname of the certificate
		containing the public key associated to the
		private key on the smartcard

Note that in mode 3 the smartcard presented is not matched
against the locally stored cert. Though this is a bit
more insecure it is faster and will probably suit single
user systems better.

The whole processing takes about 2 to 7 seconds depending on
the operation mode as well as the smartcard attachment mode
(contacless vs. contact vs. USB direct).

Be aware that except for mode 0 which is pure challenge response
in theory replay attacks are possible if somebody manages to
intercept the USB communication. As this anyway requires physical
access one can call that a calculated risk which is typically
acceptable for the majority of home systems.

The following diagram shows you how successful authentication is
achieved:

"authenticate" PAM stack is processed
          |
          v
pam_pivcard is called
          |
          v
configuration file is present -----no-----> smartcard is present
          |                                           |
         yes                                         yes
          |                                           |
          v                                           |
entry(ies) for user in file                           |
          |                                           |
         yes                                          |
          |                                           |
          v                                           |
smartcard is present                                  |
          |                                           |
         yes                                          |
          |                                           |
          v                                           |
match card to stored certificate                      |
          |                                           |
          ok                                          |
          |                                           |
          v                                           |
card challenge response                               |
          |                                           |
          ok                                          |
          |                                           |
          v                                           v
stored plaintext user password --- yes ---> card provides decryption key
          |                                           |
          no                                          ok
          |                                           |
          v                                           v
       success                              decrypt user plaintext password
                                                      |
                                                      ok
                                                      |
                                                      v
                                                   success

For analysis, the plaintext password of the user is stored on disk using
AES256/CFB. The AES encryption key is generated by the smartcard doing a
private key encrypt of a SHA256 hash. This hash is derived from the
password field of /etc/shadow.

Challenge response is based on a 32 byte random number from /dev/urandom
which is hashed using SHA256 and then the hash is encrypted by the smartcard
doing a private key encrypt. The encrypted result is the decrypted using the
on disk certificate containing the public key and the hash is then verified
against the original challenge.

Card verification is done using a SHA256 hash of the public key present
on disk and on smartcard. You can extract such a hash for RSA keys with
the following shell command (allows for searching for e.g. duplicate
public keys):

openssl x509 -in <certificate> -pubkey -noout | \
        openssl rsa -pubin -outform der 2> /dev/null | \
        openssl dgst -sha256 | cut -d' ' -f2

Using only private key encrypt on the PIV smartcard allows for the use of
slot 9E which is not PIN protected and which is available via NFC
(needs engine_pkcs11-x.y.z-override_login.patch to be applied).

If you chose to use a Yubikey NEO as your smartcard you can use the
pivscript.sh provided in the yubikey directory for easier Yubikey
management.

In case the helper process fails by hanging smartcard processing will
time out after 10 seconds, so just be patient.

Note that porting to e.g. GnuTLS is not possible as GnuTLS is missing
required low level interfaces as well as a method to bypass smartcard
login (no PIN).

Compiling for virtual guests:
=============================

The "src" directory includes a simple "Makefile.guest" which builds the stuff
suitable for virtual guests. No install included, this must then be done
manually.

Readers (NFC):
==============

Tested with Gemalto Prox-DU (IDBridge CL3000) and ACS ACR1281U-C1.

