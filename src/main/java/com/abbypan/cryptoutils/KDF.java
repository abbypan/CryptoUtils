package com.abbypan.cryptoutils;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class KDF {
    
    /**
     * HKDF (HMAC-based Key Derivation Function) implementation
     * Based on RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
     * 
     * @param inputKeyMaterial the input key material (IKM)
     * @param salt the salt (optional, can be null or empty)
     * @param info the application-specific information (optional, can be null or empty)
     * @param outputLength the desired output length in bytes
     * @param hashAlgorithm the hash algorithm to use (e.g., "SHA-256", "SHA-1")
     * @return the derived key material
     * @throws NoSuchAlgorithmException if the specified hash algorithm is not available
     * @throws InvalidKeyException if there's an issue with the key
     */
    public static byte[] hkdf(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength, String hashAlgorithm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        // Step 1: Extract - derive a pseudorandom key (PRK) from the input key material
        byte[] prk = extract(inputKeyMaterial, salt, hashAlgorithm);
        
        // Step 2: Expand - derive the output key material from the PRK
        return expand(prk, info, outputLength, hashAlgorithm);
    }
    
    /**
     * HKDF Extract step - derives a pseudorandom key from input key material
     * 
     * @param inputKeyMaterial the input key material
     * @param salt the salt (if null or empty, uses zero-filled salt)
     * @param hashAlgorithm the hash algorithm to use
     * @return the pseudorandom key
     * @throws NoSuchAlgorithmException if the hash algorithm is not available
     * @throws InvalidKeyException if there's an issue with the key
     */
    private static byte[] extract(byte[] inputKeyMaterial, byte[] salt, String hashAlgorithm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        // If salt is null or empty, use zero-filled salt of hash length
        if (salt == null || salt.length == 0) {
            int hashLength = getHashLength(hashAlgorithm);
            salt = new byte[hashLength];
        }
        
        // PRK = HMAC-Hash(salt, IKM)
        return MAC.hmacMain("Hmac" + hashAlgorithm, salt, inputKeyMaterial);
    }
    
    /**
     * HKDF Expand step - derives output key material from pseudorandom key
     * 
     * @param prk the pseudorandom key from extract step
     * @param info the application-specific information
     * @param outputLength the desired output length
     * @param hashAlgorithm the hash algorithm to use
     * @return the derived key material
     * @throws NoSuchAlgorithmException if the hash algorithm is not available
     * @throws InvalidKeyException if there's an issue with the key
     */
    private static byte[] expand(byte[] prk, byte[] info, int outputLength, String hashAlgorithm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        int hashLength = getHashLength(hashAlgorithm);
        int n = (int) Math.ceil((double) outputLength / hashLength);
        
        if (n > 255) {
            throw new IllegalArgumentException("Output length too large for HKDF");
        }
        
        // Handle null info
        if (info == null) {
            info = new byte[0];
        }
        
        ByteBuffer result = ByteBuffer.allocate(outputLength);
        byte[] t = new byte[0];
        
        for (int i = 1; i <= n; i++) {
            // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
            ByteBuffer input = ByteBuffer.allocate(t.length + info.length + 1);
            input.put(t);
            input.put(info);
            input.put((byte) i);
            
            t = MAC.hmacMain("Hmac" + hashAlgorithm, prk, input.array());
            
            // Add to result (truncate if necessary)
            int bytesToAdd = Math.min(t.length, outputLength - result.position());
            result.put(t, 0, bytesToAdd);
        }
        
        return result.array();
    }
    
    /**
     * Gets the output length of a hash algorithm in bytes
     * 
     * @param hashAlgorithm the hash algorithm name
     * @return the hash length in bytes
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    private static int getHashLength(String hashAlgorithm) throws NoSuchAlgorithmException {
        switch (hashAlgorithm.toUpperCase()) {
            case "SHA-1":
                return 20;
            case "SHA-256":
                return 32;
            case "SHA-384":
                return 48;
            case "SHA-512":
                return 64;
            case "MD5":
                return 16;
            default:
                // Try to get the length by hashing a test input
                byte[] testHash = Digest.digest(hashAlgorithm, new byte[]{0});
                return testHash.length;
        }
    }
    
    /**
     * Convenience method for HKDF with SHA-256
     * 
     * @param inputKeyMaterial the input key material
     * @param salt the salt (optional)
     * @param info the application-specific information (optional)
     * @param outputLength the desired output length in bytes
     * @return the derived key material
     * @throws NoSuchAlgorithmException if SHA-256 is not available
     * @throws InvalidKeyException if there's an issue with the key
     */
    public static byte[] hkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hkdf(inputKeyMaterial, salt, info, outputLength, "SHA-256");
    }
    
    /**
     * Convenience method for HKDF with SHA-1
     * 
     * @param inputKeyMaterial the input key material
     * @param salt the salt (optional)
     * @param info the application-specific information (optional)
     * @param outputLength the desired output length in bytes
     * @return the derived key material
     * @throws NoSuchAlgorithmException if SHA-1 is not available
     * @throws InvalidKeyException if there's an issue with the key
     */
    public static byte[] hkdfSha1(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hkdf(inputKeyMaterial, salt, info, outputLength, "SHA-1");
    }
    
    /**
     * X9.63 Key Derivation Function
     * This is a key derivation function based on ANSI X9.63 standard
     * @param z the shared secret
     * @param sharedInfo additional shared information
     * @param keyDataLen the desired length of the derived key material
     * @param hashName the hash algorithm to use (e.g., "SHA-256", "SHA-1")
     * @return the derived key material
     * @throws NoSuchAlgorithmException if the specified hash algorithm is not available
     */
    public static byte[] x9_63_KDF(byte[] z, byte[] sharedInfo, int keyDataLen, String hashName) throws NoSuchAlgorithmException {
        int counter = 1;
        ByteBuffer buf = ByteBuffer.allocate(keyDataLen);
        
        while(keyDataLen > 0) {
            byte[] c4 = intToBigEndian(counter);
            byte[] raw = ByteBuffer.allocate(z.length + c4.length + sharedInfo.length)
                .put(z).put(c4).put(sharedInfo)
                .array();
            byte[] d = Digest.digest(hashName, raw);
            int dLen = d.length;
            if(dLen <= keyDataLen) {
                buf.put(d);
                keyDataLen -= dLen;
            } else {
                buf.put(d, 0, keyDataLen);
                keyDataLen = 0;
            }
            counter++;
        }
        byte[] result = buf.array();
        return result;
    }
    
    /**
     * Converts a long integer to big-endian byte array
     * @param i the long integer to convert
     * @return the big-endian byte array representation
     */
    private static byte[] intToBigEndian(long i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt((int) i);
        return bb.array();
    }
}
