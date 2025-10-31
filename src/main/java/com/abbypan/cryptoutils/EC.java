package com.abbypan.cryptoutils;

import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.IOException;

import org.conscrypt.Conscrypt;

public class EC {
    
    // Conscrypt provider instance
    private static final Provider CONSCRYPT_PROVIDER;
    
    static {
        // Initialize Conscrypt provider at class load time
        CONSCRYPT_PROVIDER = Conscrypt.newProvider();
        // Insert Conscrypt as the first provider for EC operations
        Security.insertProviderAt(CONSCRYPT_PROVIDER, 1);
    }
    
    /**
     * Gets the Conscrypt provider instance
     * @return the Conscrypt provider
     */
    public static Provider getConscryptProvider() {
        return CONSCRYPT_PROVIDER;
    }
    
    /**
     * Gets the curve name from an EC key
     * @param key the EC key
     * @return the curve name
     * @throws Exception if the curve name cannot be determined
     */
    public static String getCurveName(Key key) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", CONSCRYPT_PROVIDER);
        params.init(((ECKey) key).getParams());
        String oid = params.getParameterSpec(ECGenParameterSpec.class).getName();
        
        // Map OID to curve name
        return mapOidToCurveName(oid);
    }
    
    /**
     * Maps an OID or curve name alias to a canonical curve name
     * Handles Conscrypt's curve name aliases (e.g., "prime256v1" -> "secp256r1")
     * @param oid the OID string or curve name
     * @return the canonical curve name
     */
    private static String mapOidToCurveName(String oid) {
        // Handle Conscrypt's curve name aliases
        switch (oid) {
            case "prime256v1":
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
                // If it's already a curve name (not an OID), normalize aliases
                if (oid.equals("prime256v1")) {
                    return "secp256r1";
                }
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
     * @param keyBytes the DER-encoded public key bytes
     * @return the public key
     * @throws IOException if the file cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws GeneralSecurityException if there's a security error
     */
    public static PublicKey readPubFromDER(String ins, byte[] keyBytes) 
            throws IOException, NoSuchAlgorithmException, GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance(ins, CONSCRYPT_PROVIDER);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = kf.generatePublic(keySpec);

        return publicKey;
    }
    
    /**
     * Reads a private key from a DER file
     * @param ins the algorithm name
     * @param privKeyByteArray the PKCS8 DER-encoded private key bytes
     * @return the private key
     * @throws IOException if the file cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws GeneralSecurityException if there's a security error
     */
    public static PrivateKey readPrivFromPKCS8DER(String ins, byte[] privKeyByteArray) 
            throws IOException, NoSuchAlgorithmException, GeneralSecurityException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance(ins, CONSCRYPT_PROVIDER);
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
        Hex.hexdump(s + " ecpublic key", pubKeyEncoded);
    }
    
    /**
     * Generates an EC key pair for the specified curve using Conscrypt
     * @param curveName the name of the curve (e.g., "secp256r1", "secp384r1")
     * @return the generated key pair
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve parameters are invalid
     */
    public static KeyPair generateKeyPair(String curveName) 
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", CONSCRYPT_PROVIDER);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyGen.initialize(ecSpec);
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
    public static PublicKey genPubFromPoint(String curveName, byte[] x, byte[] y) throws Exception {
        // Create ECGenParameterSpec for the curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        
        // Generate algorithm parameters for the curve using Conscrypt
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", CONSCRYPT_PROVIDER);
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);
        
        // Create BigInteger from x and y coordinates
        java.math.BigInteger xCoord = new java.math.BigInteger(1, x);
        java.math.BigInteger yCoord = new java.math.BigInteger(1, y);
        
        // Create ECPoint from coordinates
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(xCoord, yCoord);
        
        // Create ECPublicKeySpec
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point, ecParameterSpec);
        
        // Generate the public key using Conscrypt
        KeyFactory keyFactory = KeyFactory.getInstance("EC", CONSCRYPT_PROVIDER);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Generates a private key from curve name and BigInteger value using Conscrypt
     * @param curveName the name of the curve (e.g., "secp256r1", "secp384r1")
     * @param privateKeyBigNum the private key value as a BigInteger
     * @return the generated private key
     * @throws Exception if the private key cannot be generated
     */
    public static PrivateKey genPrivFromBN(String curveName, java.math.BigInteger privateKeyBigNum) throws Exception {
        // Create ECGenParameterSpec for the curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        
        // Generate algorithm parameters for the curve using Conscrypt
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", CONSCRYPT_PROVIDER);
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);
        
        // Create ECPrivateKeySpec with the BigInteger value
        java.security.spec.ECPrivateKeySpec privateKeySpec = 
            new java.security.spec.ECPrivateKeySpec(privateKeyBigNum, ecParameterSpec);
        
        // Generate the private key using Conscrypt
        KeyFactory keyFactory = KeyFactory.getInstance("EC", CONSCRYPT_PROVIDER);
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
        Hex.hexdump(s + " ecprivate key", keyEncoded);
        
        // Get the private key scalar value if it's an EC private key
        if (privateKey instanceof ECPrivateKey) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
            java.math.BigInteger d = ecPrivateKey.getS();
            Hex.hexdump("d", d.toByteArray());
        }
    }

    public static ECPublicKey exportPubFromPriv(ECPrivateKey privateKey) throws Exception {
        ECParameterSpec params = privateKey.getParams();
        ECPoint generator = params.getGenerator();
        java.math.BigInteger s = privateKey.getS();

        // Compute public point Q = s * G
        ECPoint w = multiplyECPoint(generator, s, params);

        // Create the public key spec
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, params);

        // Generate public key from spec
        KeyFactory kf = KeyFactory.getInstance("EC", "Conscrypt");
        return (ECPublicKey) kf.generatePublic(pubSpec);
    }

    /**
     * Multiplies an EC point by a scalar (s * G).
     * Conscrypt supports this internally, but Java doesn’t expose it directly.
     * So we can use EC math from the provider.
     */
    private static ECPoint multiplyECPoint(ECPoint g, java.math.BigInteger s, ECParameterSpec params) throws Exception {
        // Use KeyPairGenerator to generate ephemeral public key as a shortcut
        // for performing the scalar multiplication inside provider
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "Conscrypt");
        kpg.initialize(params);
        KeyPair kp = kpg.generateKeyPair();

        // Use private key value s to build correct point
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC", "Conscrypt");
        algParams.init(params);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(s, params);

        KeyFactory kf = KeyFactory.getInstance("EC", "Conscrypt");
        PrivateKey privKey = kf.generatePrivate(privSpec);

        // Use KeyAgreement to derive the public point (this computes s * G)
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "Conscrypt");
        ka.init(privKey);
        ka.doPhase(kp.getPublic(), true);

        // In this context, the result is a shared secret, not a full point.
        // For a true public key derivation, use an EC math lib or JNI to Conscrypt’s native EC APIs.
        // But since Conscrypt has limited EC math exposure, you can also rely on standard EC keypair generator.

        // Simplify: Just return generator * s through built-in math (use JCE ECParameterSpec API)
        // We'll re-create the ECPoint using EC math from the curve
        java.security.spec.EllipticCurve curve = params.getCurve();
        return ECPointUtil.scalarMultiply(curve, g, s); // Java 17+ only
    }
    
    /**
     * Converts an EC public key to hex string format
     * @param ecPubKey the EC public key to convert
     * @param format the format type ("compressed" or "uncompressed")
     * @return hex string representation of the public key
     * @throws Exception if there's an error processing the key
     */
    public static String publicKeyToHex(PublicKey ecPubKey, String format) throws Exception {
        if (!(ecPubKey instanceof java.security.interfaces.ECPublicKey)) {
            throw new IllegalArgumentException("Key must be an EC public key");
        }
        
        java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) ecPubKey;
        java.security.spec.ECPoint point = ecPublicKey.getW();
        
        java.math.BigInteger x = point.getAffineX();
        java.math.BigInteger y = point.getAffineY();
        
        // Get the curve parameters to determine the field size
        java.security.spec.ECParameterSpec params = ecPublicKey.getParams();
        int fieldSize = params.getCurve().getField().getFieldSize();
        int keyLength = (fieldSize + 7) / 8; // Convert bits to bytes
        
        if ("compressed".equalsIgnoreCase(format)) {
            // Compressed format: 0x02 or 0x03 + x coordinate
            // 0x02 if y is even, 0x03 if y is odd
            byte prefix = y.testBit(0) ? (byte) 0x03 : (byte) 0x02;
            byte[] xBytes = x.toByteArray();
            
            // Ensure x coordinate is the correct length
            byte[] xPadded = new byte[keyLength];
            int startIndex = Math.max(0, keyLength - xBytes.length);
            System.arraycopy(xBytes, 0, xPadded, startIndex, Math.min(xBytes.length, keyLength));
            
            byte[] compressed = new byte[keyLength + 1];
            compressed[0] = prefix;
            System.arraycopy(xPadded, 0, compressed, 1, keyLength);
            
            return Hex.bytesToHexstring(compressed);
            
        } else if ("uncompressed".equalsIgnoreCase(format)) {
            // Uncompressed format: 0x04 + x coordinate + y coordinate
            byte[] xBytes = x.toByteArray();
            byte[] yBytes = y.toByteArray();
            
            // Ensure coordinates are the correct length
            byte[] xPadded = new byte[keyLength];
            byte[] yPadded = new byte[keyLength];
            
            int xStartIndex = Math.max(0, keyLength - xBytes.length);
            int yStartIndex = Math.max(0, keyLength - yBytes.length);
            
            System.arraycopy(xBytes, 0, xPadded, xStartIndex, Math.min(xBytes.length, keyLength));
            System.arraycopy(yBytes, 0, yPadded, yStartIndex, Math.min(yBytes.length, keyLength));
            
            byte[] uncompressed = new byte[2 * keyLength + 1];
            uncompressed[0] = 0x04;
            System.arraycopy(xPadded, 0, uncompressed, 1, keyLength);
            System.arraycopy(yPadded, 0, uncompressed, 1 + keyLength, keyLength);
            
            return Hex.bytesToHexstring(uncompressed);
            
        } else {
            throw new IllegalArgumentException("Format must be 'compressed' or 'uncompressed'");
        }
    }
    
    /**
     * Converts a hex string representation of an EC public key back to a PublicKey object
     * @param hexString the hex string representation of the public key
     * @param curveName the curve name (e.g., "secp256r1", "secp384r1", "secp521r1")
     * @return the PublicKey object
     * @throws Exception if there's an error parsing the hex string or creating the key
     */
    public static PublicKey hexToPublicKey(String hexString, String curveName) throws Exception {
        // Remove any whitespace and convert to uppercase
        hexString = hexString.replaceAll("\\s+", "").toUpperCase();
        
        // Convert hex string to bytes
        byte[] keyBytes = Hex.hexstringToBytes(hexString);
        
        if (keyBytes.length == 0) {
            throw new IllegalArgumentException("Hex string cannot be empty");
        }
        
        // Determine format based on first byte
        byte format = keyBytes[0];
        
        if (format == 0x04) {
            // Uncompressed format: 0x04 + x + y
            return parseUncompressedKey(keyBytes, curveName);
        } else if (format == 0x02 || format == 0x03) {
            // Compressed format: 0x02/0x03 + x
            return parseCompressedKey(keyBytes, curveName);
        } else {
            throw new IllegalArgumentException("Invalid key format. First byte must be 0x02, 0x03, or 0x04");
        }
    }
    
    /**
     * Parses an uncompressed public key from bytes
     * @param keyBytes the key bytes (0x04 + x + y)
     * @param curveName the curve name
     * @return the PublicKey object
     * @throws Exception if there's an error creating the key
     */
    private static PublicKey parseUncompressedKey(byte[] keyBytes, String curveName) throws Exception {
        // Get curve parameters using Conscrypt
        java.security.spec.ECParameterSpec params = getECParameterSpec(curveName);
        int fieldSize = params.getCurve().getField().getFieldSize();
        int keyLength = (fieldSize + 7) / 8;
        
        // Expected length: 1 (prefix) + 2 * keyLength
        int expectedLength = 1 + 2 * keyLength;
        if (keyBytes.length != expectedLength) {
            throw new IllegalArgumentException("Invalid key length for uncompressed format. Expected " + 
                expectedLength + " bytes, got " + keyBytes.length);
        }
        
        // Extract x and y coordinates
        byte[] xBytes = new byte[keyLength];
        byte[] yBytes = new byte[keyLength];
        
        System.arraycopy(keyBytes, 1, xBytes, 0, keyLength);
        System.arraycopy(keyBytes, 1 + keyLength, yBytes, 0, keyLength);
        
        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        java.math.BigInteger y = new java.math.BigInteger(1, yBytes);
        
        // Create ECPoint and ECPublicKeySpec
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(x, y);
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point, params);
        
        // Generate the public key using Conscrypt
        KeyFactory keyFactory = KeyFactory.getInstance("EC", CONSCRYPT_PROVIDER);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Parses a compressed public key from bytes
     * @param keyBytes the key bytes (0x02/0x03 + x)
     * @param curveName the curve name
     * @return the PublicKey object
     * @throws Exception if there's an error creating the key
     */
    private static PublicKey parseCompressedKey(byte[] keyBytes, String curveName) throws Exception {
        // Get curve parameters using Conscrypt
        java.security.spec.ECParameterSpec params = getECParameterSpec(curveName);
        int fieldSize = params.getCurve().getField().getFieldSize();
        int keyLength = (fieldSize + 7) / 8;
        
        // Expected length: 1 (prefix) + keyLength
        int expectedLength = 1 + keyLength;
        if (keyBytes.length != expectedLength) {
            throw new IllegalArgumentException("Invalid key length for compressed format. Expected " + 
                expectedLength + " bytes, got " + keyBytes.length);
        }
        
        // Extract x coordinate
        byte[] xBytes = new byte[keyLength];
        System.arraycopy(keyBytes, 1, xBytes, 0, keyLength);
        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        
        // Determine if y is even or odd from the prefix
        boolean yIsOdd = (keyBytes[0] == 0x03);
        
        // Calculate y coordinate from x
        throw new UnsupportedOperationException("Y coordinate calculation from X is not implemented. " +
            "This requires solving the elliptic curve equation for the specific curve.");
    }
    
    /**
     * Gets EC parameter specification for a given curve name using Conscrypt
     * @param curveName the curve name
     * @return the EC parameter specification
     * @throws Exception if the curve is not supported
     */
    private static java.security.spec.ECParameterSpec getECParameterSpec(String curveName) throws Exception {
        // Generate a temporary key pair to get the parameters using Conscrypt
        KeyPair tempKeyPair = generateKeyPair(curveName);
        java.security.interfaces.ECPublicKey tempPubKey = (java.security.interfaces.ECPublicKey) tempKeyPair.getPublic();
        return tempPubKey.getParams();
    }
}