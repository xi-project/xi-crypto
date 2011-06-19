<?php

namespace Xi\Crypto;

/**
 * Functions for handling hash algorithms.
 * 
 * @author Petri Koivula <petri.koivula@iki.fi>
 */
class Hash
{
    /**
     * Get the length of the hash created by an hashing algorithm.
     * 
     * @param string $algorithm 
     * 
     * @throws \InvalidArgumentException
     */
    public static function hashLength($algorithm)
    {
        self::assertValidHashAlgorithm($algorithm);
        
        return \strlen(\hash($algorithm, null, true));
    }
    
    /**
     * Checks that the given algorhitm is supported by the current hashing
     * implementation.
     * 
     * @param string $algorithm
     * 
     * @throws \InvalidArgumentException
     */
    public static function assertValidHashAlgorithm($algorithm)
    {
        if (!\is_string($algorithm)) {
            throw new \InvalidArgumentException('The given algorithm is not a string.');
        }
        
        if (!\in_array($algorithm, \hash_algos())) {
            throw new \InvalidArgumentException('"' . $algorithm . '" is not a supported hashing algorithm.');
        }
    }
}