package com.abbypan.cryptoutils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MAC {
    
    /**
     * Computes HMAC (Hash-based Message Authentication Code) for the given data
     * @param alg the MAC algorithm (e.g., "HmacSHA256", "HmacSHA1", "HmacMD5")
     * @param key the secret key for HMAC computation
     * @param data the data to authenticate
     * @return the HMAC as a byte array
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacMain(String alg, byte[] key, byte[] data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec k = new SecretKeySpec(key, alg);
        Mac m = Mac.getInstance(alg);
        m.init(k);
        byte[] res = m.doFinal(data);
        return res;
    }
    
    /**
     * Computes HMAC-SHA256 for the given data
     * @param key the secret key for HMAC computation
     * @param data the data to authenticate
     * @return the HMAC-SHA256 as a byte array
     * @throws NoSuchAlgorithmException if SHA256 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacMain("HmacSHA256", key, data);
    }
    
    /**
     * Computes HMAC-SHA256 for the given string data
     * @param key the secret key for HMAC computation
     * @param data the string data to authenticate
     * @return the HMAC-SHA256 as a byte array
     * @throws NoSuchAlgorithmException if SHA256 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacSha256(byte[] key, String data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacSha256(key, data.getBytes());
    }
    
    /**
     * Computes HMAC-SHA1 for the given data
     * @param key the secret key for HMAC computation
     * @param data the data to authenticate
     * @return the HMAC-SHA1 as a byte array
     * @throws NoSuchAlgorithmException if SHA1 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacSha1(byte[] key, byte[] data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacMain("HmacSHA1", key, data);
    }
    
    /**
     * Computes HMAC-SHA1 for the given string data
     * @param key the secret key for HMAC computation
     * @param data the string data to authenticate
     * @return the HMAC-SHA1 as a byte array
     * @throws NoSuchAlgorithmException if SHA1 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacSha1(byte[] key, String data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacSha1(key, data.getBytes());
    }
    
    /**
     * Computes HMAC-MD5 for the given data
     * @param key the secret key for HMAC computation
     * @param data the data to authenticate
     * @return the HMAC-MD5 as a byte array
     * @throws NoSuchAlgorithmException if MD5 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacMd5(byte[] key, byte[] data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacMain("HmacMD5", key, data);
    }
    
    /**
     * Computes HMAC-MD5 for the given string data
     * @param key the secret key for HMAC computation
     * @param data the string data to authenticate
     * @return the HMAC-MD5 as a byte array
     * @throws NoSuchAlgorithmException if MD5 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacMd5(byte[] key, String data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacMd5(key, data.getBytes());
    }
    
    /**
     * Computes HMAC-SHA384 for the given data
     * @param key the secret key for HMAC computation
     * @param data the data to authenticate
     * @return the HMAC-SHA384 as a byte array
     * @throws NoSuchAlgorithmException if SHA384 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacSha384(byte[] key, byte[] data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacMain("HmacSHA384", key, data);
    }
    
    /**
     * Computes HMAC-SHA512 for the given data
     * @param key the secret key for HMAC computation
     * @param data the data to authenticate
     * @return the HMAC-SHA512 as a byte array
     * @throws NoSuchAlgorithmException if SHA512 is not available
     * @throws InvalidKeyException if the key is invalid
     */
    public static byte[] hmacSha512(byte[] key, byte[] data) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacMain("HmacSHA512", key, data);
    }
}
