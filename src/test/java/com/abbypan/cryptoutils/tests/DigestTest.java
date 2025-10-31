package com.abbypan.cryptoutils.tests;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.abbypan.cryptoutils.Digest;
//import com.abbypan.cryptoutils.Hex;

public class DigestTest {
    
    private static final String TEST_STRING = "Hello, World!";
    private static final byte[] TEST_BYTES = TEST_STRING.getBytes(StandardCharsets.UTF_8);
    
    @Test
    public void testDigestWithString() throws NoSuchAlgorithmException {
        // Test generic digest method with string input
        byte[] result = Digest.digest("SHA-256", TEST_STRING);
        
        assertNotNull("Digest result should not be null", result);
        assertEquals("SHA-256 should produce 32 bytes", 32, result.length);
    }
    
    @Test
    public void testDigestWithBytes() throws NoSuchAlgorithmException {
        // Test generic digest method with byte array input
        byte[] result = Digest.digest("SHA-256", TEST_BYTES);
        
        assertNotNull("Digest result should not be null", result);
        assertEquals("SHA-256 should produce 32 bytes", 32, result.length);
    }
    
    @Test
    public void testSha256String() throws NoSuchAlgorithmException {
        // Test SHA-256 with string input
        byte[] result = Digest.sha256(TEST_STRING);
        
        assertNotNull("SHA-256 result should not be null", result);
        assertEquals("SHA-256 should produce 32 bytes", 32, result.length);
        
        // Test consistency - same input should produce same output
        byte[] result2 = Digest.sha256(TEST_STRING);
        assertArrayEquals("SHA-256 should be deterministic", result, result2);
    }
    
    @Test
    public void testSha256Bytes() throws NoSuchAlgorithmException {
        // Test SHA-256 with byte array input
        byte[] result = Digest.sha256(TEST_BYTES);
        
        assertNotNull("SHA-256 result should not be null", result);
        assertEquals("SHA-256 should produce 32 bytes", 32, result.length);
    }
    
    @Test
    public void testSha1String() throws NoSuchAlgorithmException {
        // Test SHA-1 with string input
        byte[] result = Digest.sha1(TEST_STRING);
        
        assertNotNull("SHA-1 result should not be null", result);
        assertEquals("SHA-1 should produce 20 bytes", 20, result.length);
    }
    
    @Test
    public void testSha1Bytes() throws NoSuchAlgorithmException {
        // Test SHA-1 with byte array input
        byte[] result = Digest.sha1(TEST_BYTES);
        
        assertNotNull("SHA-1 result should not be null", result);
        assertEquals("SHA-1 should produce 20 bytes", 20, result.length);
    }
    
    @Test
    public void testMd5String() throws NoSuchAlgorithmException {
        // Test MD5 with string input
        byte[] result = Digest.md5(TEST_STRING);
        
        assertNotNull("MD5 result should not be null", result);
        assertEquals("MD5 should produce 16 bytes", 16, result.length);
    }
    
    @Test
    public void testMd5Bytes() throws NoSuchAlgorithmException {
        // Test MD5 with byte array input
        byte[] result = Digest.md5(TEST_BYTES);
        
        assertNotNull("MD5 result should not be null", result);
        assertEquals("MD5 should produce 16 bytes", 16, result.length);
    }
    
    @Test
    public void testSha384Bytes() throws NoSuchAlgorithmException {
        // Test SHA-384 with byte array input
        byte[] result = Digest.sha384(TEST_BYTES);
        
        assertNotNull("SHA-384 result should not be null", result);
        assertEquals("SHA-384 should produce 48 bytes", 48, result.length);
    }
    
    @Test
    public void testSha512Bytes() throws NoSuchAlgorithmException {
        // Test SHA-512 with byte array input
        byte[] result = Digest.sha512(TEST_BYTES);
        
        assertNotNull("SHA-512 result should not be null", result);
        assertEquals("SHA-512 should produce 64 bytes", 64, result.length);
    }
    
    @Test
    public void testSha3_256String() throws NoSuchAlgorithmException {
        // Test SHA3-256 with string input
        byte[] result = Digest.sha3_256(TEST_STRING);
        
        assertNotNull("SHA3-256 result should not be null", result);
        assertEquals("SHA3-256 should produce 32 bytes", 32, result.length);
        
        // Test consistency - same input should produce same output
        byte[] result2 = Digest.sha3_256(TEST_STRING);
        assertArrayEquals("SHA3-256 should be deterministic", result, result2);
    }
    
    @Test
    public void testSha3_256Bytes() throws NoSuchAlgorithmException {
        // Test SHA3-256 with byte array input
        byte[] result = Digest.sha3_256(TEST_BYTES);
        
        assertNotNull("SHA3-256 result should not be null", result);
        assertEquals("SHA3-256 should produce 32 bytes", 32, result.length);
    }
    
    @Test
    public void testSha3_256DifferentInputs() throws NoSuchAlgorithmException {
        // Test that different inputs produce different outputs
        byte[] result1 = Digest.sha3_256("Hello");
        byte[] result2 = Digest.sha3_256("World");
        
        assertNotNull("First result should not be null", result1);
        assertNotNull("Second result should not be null", result2);
        assertFalse("Different inputs should produce different outputs", 
                   java.util.Arrays.equals(result1, result2));
    }
    
    @Test
    public void testSha3_256EmptyInput() throws NoSuchAlgorithmException {
        // Test SHA3-256 with empty input
        byte[] result = Digest.sha3_256("");
        
        assertNotNull("SHA3-256 result for empty input should not be null", result);
        assertEquals("SHA3-256 should produce 32 bytes for empty input", 32, result.length);
    }
    
    @Test
    public void testSha3_256LongInput() throws NoSuchAlgorithmException {
        // Test SHA3-256 with long input
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("A");
        }
        String longInput = sb.toString();
        
        byte[] result = Digest.sha3_256(longInput);
        
        assertNotNull("SHA3-256 result for long input should not be null", result);
        assertEquals("SHA3-256 should produce 32 bytes for long input", 32, result.length);
    }
    
    @Test
    public void testSha3_256BinaryData() throws NoSuchAlgorithmException {
        // Test SHA3-256 with binary data
        byte[] binaryData = {0x00, 0x01, 0x02, 0x03, (byte)0xFF, (byte)0xFE, (byte)0xFD};
        
        byte[] result = Digest.sha3_256(binaryData);
        
        assertNotNull("SHA3-256 result for binary data should not be null", result);
        assertEquals("SHA3-256 should produce 32 bytes for binary data", 32, result.length);
    }
    
    @Test
    public void testConsistencyAcrossAlgorithms() throws NoSuchAlgorithmException {
        // Test that different algorithms produce different results for same input
        byte[] sha256Result = Digest.sha256(TEST_STRING);
        byte[] sha3_256Result = Digest.sha3_256(TEST_STRING);
        
        assertNotNull("SHA-256 result should not be null", sha256Result);
        assertNotNull("SHA3-256 result should not be null", sha3_256Result);
        assertFalse("SHA-256 and SHA3-256 should produce different results", 
                   java.util.Arrays.equals(sha256Result, sha3_256Result));
    }
    
    @Test
    public void testUnicodeString() throws NoSuchAlgorithmException {
        // Test with Unicode string
        String unicodeString = "Hello, 世界! 🌍";
        byte[] result = Digest.sha3_256(unicodeString);
        
        assertNotNull("SHA3-256 result for Unicode string should not be null", result);
        assertEquals("SHA3-256 should produce 32 bytes for Unicode string", 32, result.length);
    }
    
    @Test(expected = NoSuchAlgorithmException.class)
    public void testInvalidAlgorithm() throws NoSuchAlgorithmException {
        // Test that invalid algorithm throws exception
        Digest.digest("INVALID-ALGORITHM", TEST_STRING);
    }
    
    @Test
    public void testAllAlgorithms() throws NoSuchAlgorithmException {
        // Test all available algorithms
        String[] algorithms = {"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256"};
        
        for (String algorithm : algorithms) {
            byte[] result = Digest.digest(algorithm, TEST_STRING);
            assertNotNull("Result for " + algorithm + " should not be null", result);
            
            // Verify expected output lengths
            switch (algorithm) {
                case "MD5":
                    assertEquals("MD5 should produce 16 bytes", 16, result.length);
                    break;
                case "SHA-1":
                    assertEquals("SHA-1 should produce 20 bytes", 20, result.length);
                    break;
                case "SHA-256":
                case "SHA3-256":
                    assertEquals(algorithm + " should produce 32 bytes", 32, result.length);
                    break;
                case "SHA-384":
                    assertEquals("SHA-384 should produce 48 bytes", 48, result.length);
                    break;
                case "SHA-512":
                    assertEquals("SHA-512 should produce 64 bytes", 64, result.length);
                    break;
            }
        }
    }
}
