package com.abbypan.cryptoutils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class Digest {
    
    /**
     * Computes the hash digest of the input data using the specified algorithm
     * @param hashName the name of the hash algorithm (e.g., "SHA-256", "SHA-1", "MD5")
     * @param data the input data to hash
     * @return the hash digest as a byte array
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     */
    public static byte[] digest(String hashName, byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(hashName);
        byte[] hash = digest.digest(data);
        return hash;
    }
    
    /**
     * Computes the hash digest of a string using the specified algorithm
     * @param hashName the name of the hash algorithm (e.g., "SHA-256", "SHA-1", "MD5")
     * @param input the input string to hash
     * @return the hash digest as a byte array
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     */
    public static byte[] digest(String hashName, String input) throws NoSuchAlgorithmException {
        return digest(hashName, input.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Computes the SHA-256 hash of the input data
     * @param data the input data to hash
     * @return the SHA-256 hash as a byte array
     * @throws NoSuchAlgorithmException if SHA-256 is not available
     */
    public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        return digest("SHA-256", data);
    }
    
    /**
     * Computes the SHA-256 hash of a string
     * @param input the input string to hash
     * @return the SHA-256 hash as a byte array
     * @throws NoSuchAlgorithmException if SHA-256 is not available
     */
    public static byte[] sha256(String input) throws NoSuchAlgorithmException {
        return digest("SHA-256", input);
    }
    
    /**
     * Computes the SHA-1 hash of the input data
     * @param data the input data to hash
     * @return the SHA-1 hash as a byte array
     * @throws NoSuchAlgorithmException if SHA-1 is not available
     */
    public static byte[] sha1(byte[] data) throws NoSuchAlgorithmException {
        return digest("SHA-1", data);
    }
    
    /**
     * Computes the SHA-1 hash of a string
     * @param input the input string to hash
     * @return the SHA-1 hash as a byte array
     * @throws NoSuchAlgorithmException if SHA-1 is not available
     */
    public static byte[] sha1(String input) throws NoSuchAlgorithmException {
        return digest("SHA-1", input);
    }
    
    /**
     * Computes the MD5 hash of the input data
     * @param data the input data to hash
     * @return the MD5 hash as a byte array
     * @throws NoSuchAlgorithmException if MD5 is not available
     */
    public static byte[] md5(byte[] data) throws NoSuchAlgorithmException {
        return digest("MD5", data);
    }
    
    /**
     * Computes the MD5 hash of a string
     * @param input the input string to hash
     * @return the MD5 hash as a byte array
     * @throws NoSuchAlgorithmException if MD5 is not available
     */
    public static byte[] md5(String input) throws NoSuchAlgorithmException {
        return digest("MD5", input);
    }
    
    /**
     * Computes the SHA-384 hash of the input data
     * @param data the input data to hash
     * @return the SHA-384 hash as a byte array
     * @throws NoSuchAlgorithmException if SHA-384 is not available
     */
    public static byte[] sha384(byte[] data) throws NoSuchAlgorithmException {
        return digest("SHA-384", data);
    }
    
    /**
     * Computes the SHA-512 hash of the input data
     * @param data the input data to hash
     * @return the SHA-512 hash as a byte array
     * @throws NoSuchAlgorithmException if SHA-512 is not available
     */
    public static byte[] sha512(byte[] data) throws NoSuchAlgorithmException {
        return digest("SHA-512", data);
    }
}
