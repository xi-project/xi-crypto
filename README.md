# Xi Crypto

A set of utility classes for common cryptographic needs in writing secure 
web services. This package is part of the Xi project.

## Encryption / Decryption

TODO: Add a user friendly AES-256 implementation with good documentation, as
      the way you do this with mcrypt, MCRYPT_RIJNDAEL_128 and a specific key
      size is not obvious.

## Password based key derivation functions

Key derivation functions are used to create encryption keys or hashes. Password
based versions can be used for password hashing, and with high iteration counts
make anyone brute-forcing passwords out of the hashes very unlikely due to
computational (and thus, financial) costs.

Estimated cost of hardware to crack a password in 1 year (2009):

Assumes
PBKDF2-HMAC-SHA256, c = 86000 / c = 4300000
bcrypt, cost = 11 / cost = 16
scrypt, N = 2^14, r = 8, p = 1 / N = 2^20, r = 8, p = 1
(Runtimes on a Core 2 laptop, costs on specially designed custom hardware)

        KDF             6 letters   8 letters   8 chars 10 chars    40-char text
        DES CRYPT       < $1        < $1        < $1    < $1        < $1
        MD5             < $1        < $1        < $1    $1.1k       $1
        MD5 CRYPT       < $1        < $1        $130    $1.1M       $1.4k
        PBKDF2 (100 ms) < $1        < $1        $18k    $160M       $200k
        bcrypt (95 ms)  < $1        $4          $130k   $1.2B       $1.5M
        scrypt (64 ms)  < $1        $150        $4.8M   $43B        $52M
        PBKDF2 (5.0 s)  < $1        $29         $920k   $8.3B       $10M
        bcrypt (3.0 s)  < $1        $130        $4.3M   $39B        $47M
        scrypt (3.8 s)  $900        $610k       $19B    $175T       $210B

The cost differences between PBKDF2, bcrypt and scrypt are explained by the
amount of memory required for the calculations and their scalability for
parallel calculation.

http://www.bsdcan.org/2009/schedule/attachments/86_scrypt_slides.pdf

TODO: Look into bcrypt/scrypt implementations for PHP.

### PBKDF2

A commonly used KDF for hashing passwords with moderate brute-force security.

As described in RFC 2898 ( http://www.ietf.org/rfc/rfc2898.txt ).

Requires the Hash extension (enabled by default on most installations).

For example,

        $salt = pack('L4', mt_rand(), mt_rand(), mt_rand(), mt_rand());
        $hash = bin2hex(Xi\Crypto\Password\KDF\PBKDF2::PBKDF2(
            'abc123]#-',
            $salt,
            1e5, // 100000
            64,
            'sha512'
        ));
