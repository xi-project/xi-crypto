<?php

namespace Xi\Crypto\Password\KDF;

use Xi\Crypto\Hash;

/**
 * Password based key derivation function PBKDF2.
 * 
 * As described in RFC 2898 ( http://www.ietf.org/rfc/rfc2898.txt ).
 * 
 * For satisfying password security, modern password based systems use key 
 * derivation functions, which satisfy the need to keep passwords
 * difficult to calculate with brute force, even with a known hash.
 * 
 * @author Petri Koivula <petri.koivula@iki.fi>
 */
class PBKDF2
{
    /** 
     * PBKDF2 Implementation.
     * 
     * If the salt is namespaced, it should still contain 8 octets of random
     * data.
     * 
     * Iteration count should be at least 1000, and as of 2011, used values are
     * often in the 10^4 to 10^6 region.
     * 
     * As described in RFC 2898 ( http://www.ietf.org/rfc/rfc2898.txt ).
     *
     * @param string $password
     * @param string $salt A minimum of 8 octets of random data.
     * @param string $iterationCount
     * @param string $keyLength Wanted key length in octets.
     * @param string $algorithm Hash algorithm.
     *
     * @return string Derived key, as a binary string.
     * 
     * @throws \InvalidArgumentException
     */
    public static function PBKDF2($password, $salt, $iterationCount, $keyLength, $algorithm = 'sha256')
    {
        Hash::assertValidHashAlgorithm($algorithm);
        self::assertValidSalt($salt);
        
        $hashLength = Hash::hashLength($algorithm);
        $keyBlockAmount = \ceil($keyLength / $hashLength);
        
        $derivedKey = '';
        
        for ($blockNumber = 1; $blockNumber <= $keyBlockAmount; $blockNumber += 1) {
            $iteratedBlock = \hash_hmac($algorithm, $salt . \pack('N', $blockNumber), $password, true);
            
            $blockIteration = $iteratedBlock;
            for ($iterationNumber = 1; $iterationNumber <= $iterationCount; $iterationNumber += 1) {
                $blockIteration = \hash_hmac($algorithm, $blockIteration, $password, true);
                
                $iteratedBlock ^= $blockIteration;
            }
            
            $derivedKey .= $iteratedBlock;
        }
        
        return \substr($derivedKey, 0, $keyLength);
    }
    
    /**
     * Checks that the given salt is a string and at least 8 octets (64 bits)
     * long as recommended in the RFC.
     * 
     * @param string $salt
     * 
     * @throws \InvalidArgumentException
     */
    public static function assertValidSalt($salt)
    {
        if (!\is_string($salt)) {
            throw new \InvalidArgumentException('The given salt is not a string.');
        }
        
        if (self::binaryLength($salt) < 8) {
            throw new \InvalidArgumentException('The given salt is not at least 8 octets (64 bits) long.');
        }
    }
    
    /**
     * String length in octets.
     * 
     * Plain \strlen() could be overridden with \mb_strlen().
     * 
     * @param string $string 
     */
    public static function binaryLength($string)
    {
        if (!\is_string($string)) {
            throw new \InvalidArgumentException('The given value is not a string.');
        }
        
        $hasMbstring = \extension_loaded('mbstring') ||@\dl(PHP_SHLIB_PREFIX.'mbstring.'.PHP_SHLIB_SUFFIX); 
        $hasMbShadow = (int) \ini_get('mbstring.func_overload'); 

        if ($hasMbstring && ($hasMbShadow & 2) ) { 
           return \mb_strlen($string, 'latin1'); 
        } else { 
           return \strlen($string); 
        }
    }
}