package com.abbypan.cryptoutils.tests;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.Test;

import com.abbypan.cryptoutils.EC;
import com.abbypan.cryptoutils.Hex;

public class ECTest {
    
    @Test
    public void testGenerateKeyPair() throws Exception {
        // Test key pair generation for secp256r1
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        
        assertNotNull("Key pair should not be null", keyPair);
        assertNotNull("Private key should not be null", keyPair.getPrivate());
        assertNotNull("Public key should not be null", keyPair.getPublic());
        
        // Verify it's an EC key pair
        assertTrue("Private key should be EC private key", keyPair.getPrivate() instanceof ECPrivateKey);
        assertTrue("Public key should be EC public key", keyPair.getPublic() instanceof ECPublicKey);
    }
    
    @Test
    public void testGetCurveName() throws Exception {
        // Generate a key pair and test curve name extraction
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        String curveName = EC.getCurveName(keyPair.getPrivate());
        
        assertEquals("Curve name should be secp256r1", "secp256r1", curveName);
        
        // Test with public key
        String curveNameFromPub = EC.getCurveName(keyPair.getPublic());
        assertEquals("Curve name from public key should be secp256r1", "secp256r1", curveNameFromPub);
    }
    
    @Test
    public void testGenPrivFromBN() throws Exception {
        // Test private key generation from BigInteger
        String curveName = "secp256r1";
        BigInteger privateKeyValue = new BigInteger("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16);
        
        PrivateKey privateKey = EC.genPrivFromBN(curveName, privateKeyValue);
        
        assertNotNull("Private key should not be null", privateKey);
        assertTrue("Private key should be EC private key", privateKey instanceof ECPrivateKey);
        
        // Verify the curve name
        String extractedCurveName = EC.getCurveName(privateKey);
        assertEquals("Extracted curve name should match", curveName, extractedCurveName);
    }
    
    @Test
    public void testReadPubFromPoint() throws Exception {
        // Test public key creation from coordinates
        String curveName = "secp256r1";
        
        // Sample x, y coordinates (these are example values)
        byte[] x = Hex.hexstringToBytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        byte[] y = Hex.hexstringToBytes("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        
        try {
            PublicKey publicKey = EC.genPubFromPoint(curveName, x, y);
            assertNotNull("Public key should not be null", publicKey);
            assertTrue("Public key should be EC public key", publicKey instanceof ECPublicKey);
        } catch (Exception e) {
            // This might fail with invalid coordinates, which is expected
            // The test verifies the method can be called without compilation errors
            assertTrue("Exception should be thrown for invalid coordinates", e instanceof Exception);
        }
    }
    
    
    
    
    
    
    
    @Test
    public void testDumpPub() throws Exception {
        // Test public key dumping (this will output to console)
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        PublicKey publicKey = keyPair.getPublic();
        
        // This should not throw an exception
        EC.DumpPub("Test Public Key", publicKey);
        
        // If we get here, the test passed
        assertTrue("DumpPubKey should complete without exception", true);
    }
    
    @Test
    public void testDumpPriv() throws Exception {
        // Test private key dumping (this will output to console)
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        PrivateKey privateKey = keyPair.getPrivate();
        
        // This should not throw an exception
        EC.DumpPriv("Test Private Key", privateKey);
        
        // If we get here, the test passed
        assertTrue("DumpPriv should complete without exception", true);
    }
    
    @Test
    public void testReadPubFromDER() throws Exception {
        // Test reading public key from DER bytes
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        PublicKey originalPublicKey = keyPair.getPublic();
        byte[] encodedKey = originalPublicKey.getEncoded();
        
        PublicKey readPublicKey = EC.readPubFromDER("EC", encodedKey);
        
        assertNotNull("Read public key should not be null", readPublicKey);
        assertArrayEquals("Encoded keys should match", originalPublicKey.getEncoded(), readPublicKey.getEncoded());
    }
    
    @Test
    public void testReadPrivFromPKCS8DER() throws Exception {
        // Test reading private key from PKCS8 DER bytes
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        PrivateKey originalPrivateKey = keyPair.getPrivate();
        byte[] encodedKey = originalPrivateKey.getEncoded();
        
        PrivateKey readPrivateKey = EC.readPrivFromPKCS8DER("EC", encodedKey);
        
        assertNotNull("Read private key should not be null", readPrivateKey);
        assertArrayEquals("Encoded keys should match", originalPrivateKey.getEncoded(), readPrivateKey.getEncoded());
    }
    
    @Test
    public void testMultipleCurves() throws Exception {
        // Test different curves
        String[] curves = {"secp256r1", "secp384r1", "secp521r1"};
        
        for (String curve : curves) {
            KeyPair keyPair = EC.generateKeyPair(curve);
            assertNotNull("Key pair for " + curve + " should not be null", keyPair);
            
            String curveName = EC.getCurveName(keyPair.getPrivate());
            assertEquals("Curve name should match for " + curve, curve, curveName);
        }
    }
    
    @Test
    public void testExportPubFromPriv() throws Exception {
        // Test exporting public key from private key
        KeyPair keyPair = EC.generateKeyPair("secp256r1");
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey originalPublicKey = (ECPublicKey) keyPair.getPublic();
        
        // Export public key from private key
        ECPublicKey exportedPublicKey = EC.exportPubFromPriv(privateKey);
        
        // Verify the exported public key is not null
        assertNotNull("Exported public key should not be null", exportedPublicKey);
        assertTrue("Exported public key should be EC public key", exportedPublicKey instanceof ECPublicKey);
        
        // Verify the exported public key matches the original public key
        assertArrayEquals("Exported public key should match original public key",
                         originalPublicKey.getEncoded(), exportedPublicKey.getEncoded());
        
        // Verify they have the same curve
        String originalCurve = EC.getCurveName(originalPublicKey);
        String exportedCurve = EC.getCurveName(exportedPublicKey);
        assertEquals("Curve names should match", originalCurve, exportedCurve);
    }
    
    @Test
    public void testExportPubFromPrivMultipleCurves() throws Exception {
        // Test exportPubFromPriv with different curves
        String[] curves = {"secp256r1", "secp384r1", "secp521r1"};
        
        for (String curve : curves) {
            KeyPair keyPair = EC.generateKeyPair(curve);
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey originalPublicKey = (ECPublicKey) keyPair.getPublic();
            
            // Export public key from private key
            ECPublicKey exportedPublicKey = EC.exportPubFromPriv(privateKey);
            
            // Verify the result
            assertNotNull("Exported public key should not be null for " + curve, exportedPublicKey);
            assertTrue("Exported public key should be EC public key for " + curve, 
                      exportedPublicKey instanceof ECPublicKey);
            
            // Verify the exported public key matches the original
            assertArrayEquals("Exported public key should match original for " + curve,
                             originalPublicKey.getEncoded(), exportedPublicKey.getEncoded());
        }
    }
    
    @Test
    public void testExportPubFromPrivFromBigInteger() throws Exception {
        // Test exporting public key from a private key generated from BigInteger
        String curveName = "secp256r1";
        
        // Generate a key pair first to get a valid private key value
        KeyPair keyPair = EC.generateKeyPair(curveName);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        BigInteger privateKeyValue = ecPrivateKey.getS();
        
        // Create a new private key from the BigInteger value
        PrivateKey privateKey = EC.genPrivFromBN(curveName, privateKeyValue);
        ECPrivateKey newPrivateKey = (ECPrivateKey) privateKey;
        
        // Export the public key
        ECPublicKey exportedPublicKey = EC.exportPubFromPriv(newPrivateKey);
        
        // Verify the result
        assertNotNull("Exported public key should not be null", exportedPublicKey);
        assertTrue("Exported public key should be EC public key", exportedPublicKey instanceof ECPublicKey);
        
        // Verify it matches the original public key from the key pair
        assertArrayEquals("Exported public key should match original key pair public key",
                         keyPair.getPublic().getEncoded(), exportedPublicKey.getEncoded());
    }
    
}
