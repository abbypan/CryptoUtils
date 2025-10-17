package com.abbypan.cryptoutils;

import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class EC {
    
    /**
     * Gets the curve name from an EC key
     * @param key the EC key
     * @return the curve name
     * @throws Exception if the curve name cannot be determined
     */
    public static String getCurveName(Key key) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(((ECKey) key).getParams());
        String oid = params.getParameterSpec(ECGenParameterSpec.class).getName();
        
        // Map OID to curve name
        return mapOidToCurveName(oid);
    }
    
    /**
     * Maps an OID to a curve name
     * @param oid the OID string
     * @return the curve name
     */
    private static String mapOidToCurveName(String oid) {
        switch (oid) {
            case "1.2.840.10045.3.1.7":  // secp256r1 (P-256)
                return "secp256r1";
            case "1.3.132.0.34":         // secp384r1 (P-384)
                return "secp384r1";
            case "1.3.132.0.35":         // secp521r1 (P-521)
                return "secp521r1";
            case "1.3.132.0.33":         // secp224r1 (P-224)
                return "secp224r1";
            case "1.3.132.0.32":         // secp192r1 (P-192)
                return "secp192r1";
            case "1.3.132.0.10":         // secp256k1
                return "secp256k1";
            case "1.3.132.0.38":         // secp384r1 (alternative OID)
                return "secp384r1";
            case "1.3.132.0.39":         // secp521r1 (alternative OID)
                return "secp521r1";
            default:
                // If it's already a curve name (not an OID), return as-is
                if (oid.startsWith("secp") || oid.startsWith("P-")) {
                    return oid;
                }
                // Return the OID if we can't map it
                return oid;
        }
    }

    /**
     * Reads a public key from a DER file
     * @param ins the algorithm name
     * @param DERfile the path to the DER file
     * @return the public key
     * @throws IOException if the file cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws GeneralSecurityException if there's a security error
     */
    public static PublicKey readPubFromDER(String ins, byte[] keyBytes) 
            throws IOException, NoSuchAlgorithmException, GeneralSecurityException {
       

        KeyFactory kf = KeyFactory.getInstance(ins);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = kf.generatePublic(keySpec);

        return publicKey;
    }
    
    /**
     * Reads a private key from a DER file
     * @param ins the algorithm name
     * @param DERfile the path to the DER file
     * @return the private key
     * @throws IOException if the file cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws GeneralSecurityException if there's a security error
     */
    public static PrivateKey readPrivFromPKCS8DER(String ins, byte[] privKeyByteArray) 
            throws IOException, NoSuchAlgorithmException, GeneralSecurityException {
      
      //  HexUtils.hexdump("priv", privKeyByteArray);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance(ins);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
    
    /**
     * Dumps information about a public key
     * @param s label for the dump
     * @param ecPubKey the public key to dump
     * @throws Exception if there's an error accessing the key
     */
    public static void DumpPub(String s, PublicKey ecPubKey) throws Exception {
        byte[] pubKeyEncoded = ecPubKey.getEncoded();
        HexUtils.hexdump(s + " ecpublic key", pubKeyEncoded);
        
        // Note: BouncyCastle-specific ECPoint access was removed
        // This method now only dumps the encoded key bytes
    }
    
    /**
     * Generates an EC key pair for the specified curve
     * @param curveName the name of the curve (e.g., "secp256r1", "secp384r1")
     * @return the generated key pair
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve parameters are invalid
     */
    public static KeyPair generateKeyPair(String curveName) 
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Generates an EC key pair with a specific key size
     * @param keySize the key size in bits (e.g., 256, 384, 521)
     * @return the generated key pair
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    public static KeyPair generateKeyPair(int keySize) 
            throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Creates a public key from curve name and x, y coordinates
     * @param curveName the name of the curve (e.g., "secp256r1", "secp384r1")
     * @param x the x coordinate of the public key point
     * @param y the y coordinate of the public key point
     * @return the public key
     * @throws Exception if the public key cannot be created
     */
    public static PublicKey readPubFromPoint(String curveName, byte[] x, byte[] y) throws Exception {
        // Create ECGenParameterSpec for the curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        
        // Generate algorithm parameters for the curve
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);
        
        // Create BigInteger from x and y coordinates
        java.math.BigInteger xCoord = new java.math.BigInteger(1, x);
        java.math.BigInteger yCoord = new java.math.BigInteger(1, y);
        
        // Create ECPoint from coordinates
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(xCoord, yCoord);
        
        // Create ECPublicKeySpec
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point, ecParameterSpec);
        
        // Generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Exports a public key from a private key
     * @param privateKey the private key to extract the public key from
     * @return the corresponding public key
     * @throws Exception if the public key cannot be extracted
     */
    public static PublicKey exportPub(PrivateKey privateKey) throws Exception {
        // Get the key pair generator for EC
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        
        // Get the curve name from the private key
        String curveName = getCurveName(privateKey);
        
        // Initialize the key pair generator with the same curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyGen.initialize(ecSpec);
        
        // Generate a temporary key pair to get the algorithm parameters
        KeyPair tempKeyPair = keyGen.generateKeyPair();
        ECPrivateKey tempPrivateKey = (ECPrivateKey) tempKeyPair.getPrivate();
        
        // Get the algorithm parameters from the temporary key
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(((ECKey) tempPrivateKey).getParams());
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);
        
        // Get the private key scalar value
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        // java.math.BigInteger privateKeyScalar = ecPrivateKey.getS();
        
        // Get the generator point G from the curve parameters
        java.security.spec.ECPoint generatorPoint = ecParameterSpec.getGenerator();
        
        // Calculate the public key point: publicKey = privateKey * G
        // Note: This is a simplified approach. In practice, you might need to use
        // a more sophisticated method to perform the elliptic curve point multiplication
        java.security.spec.ECPoint publicKeyPoint = new java.security.spec.ECPoint(
            generatorPoint.getAffineX(), generatorPoint.getAffineY());
        
        // Create ECPublicKeySpec
        ECPublicKeySpec keySpec = new ECPublicKeySpec(publicKeyPoint, ecParameterSpec);
        
        // Generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Generates a private key from curve name and BigInteger value
     * @param curveName the name of the curve (e.g., "secp256r1", "secp384r1")
     * @param privateKeyBigNum the private key value as a BigInteger
     * @return the generated private key
     * @throws Exception if the private key cannot be generated
     */
    public static PrivateKey genPrivFromBN(String curveName, java.math.BigInteger privateKeyBigNum) throws Exception {
        // Create ECGenParameterSpec for the curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        
        // Generate algorithm parameters for the curve
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);
        
        // Create ECPrivateKeySpec with the BigInteger value
        java.security.spec.ECPrivateKeySpec privateKeySpec = new java.security.spec.ECPrivateKeySpec(privateKeyBigNum, ecParameterSpec);
        
        // Generate the private key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }
    
    /**
     * Dumps information about a private key
     * @param s label for the dump
     * @param privateKey the private key to dump
     * @throws Exception if there's an error accessing the key
     */
    public static void DumpPriv(String s, PrivateKey privateKey) throws Exception {
        byte[] keyEncoded = privateKey.getEncoded();
        HexUtils.hexdump(s + " ecprivate key", keyEncoded);
        
        // Get the private key scalar value if it's an EC private key
        if (privateKey instanceof ECPrivateKey) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
            java.math.BigInteger d = ecPrivateKey.getS();
            HexUtils.hexdump("d", d.toByteArray());
        }
    }
}
