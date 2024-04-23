package com.abbypan.cryptoutils;

import at.favre.lib.hkdf.*;
import com.google.common.primitives.*;
import org.apache.commons.io.HexDump;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

//import java.security.spec.ECParameterSpec;
//import java.security.spec.ECPublicKeySpec;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

//import org.bouncycastle.jce.spec.ECGenParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey ;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey ;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;



public class CryptoUtils 
{
    public static void CryptoUtils() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String getCurveName(Key key) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "BC");
        params.init(((ECKey) key).getParams());
        String name = params.getParameterSpec(ECGenParameterSpec.class).getName();
        return name;
    }

    public static void printAlgList(String utilName){
        System.out.println(Security.getAlgorithms(utilName));
    }
    public static void printProviderList(){
        System.out.println(Arrays.toString(Security.getProviders()));
    }

    public static byte[] hexstringToBytes(String s) {
        return HexFormat.of().parseHex(s);
    }

    public static void hexdump(String s, byte[] bin) 
            throws IOException
        {
            System.out.println("\n" + s + "\n" + bytesToHexstring(bin) + "\n");
            //  OutputStream stdout = System.out;
            //  HexDump.dump(bin, 0, stdout, 0);
        }

    public static String bytesToHexstring(byte[] bin) {
        return HexFormat.of().formatHex(bin);
    }

    public static byte[] hkdfMain(HKDF h, byte[] ss, byte[] salt, byte[] info, int n) throws NoSuchAlgorithmException {
        byte[] tmpKey = h.extract(salt, ss);

        byte[] okm = h.expand(tmpKey, info, n);
        return okm;
    }





    public static BCECPublicKey genBCECPublicKeyFromPoint(String ins, String curveName, ECPoint publicPoint)
            throws Exception
        {
            KeyFactory keyFactory = KeyFactory.getInstance(ins, "BC");
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec (curveName);
            BCECPublicKey pk = (BCECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(publicPoint, ecSpec));
            return pk;
        }

    public static BCECPublicKey genBCECPublicKeyFromPriv(String ins, BCECPrivateKey priv)
            throws Exception
        {
            KeyFactory keyFactory = KeyFactory.getInstance(ins, "BC");

            String curveName = getCurveName(priv);
            // ECGenParameterSpec ecsp;
            // ecsp = new ECGenParameterSpec(curveName);
            //  AlgorithmParameters algParameters = AlgorithmParameters.getInstance(ins,"BC");
            //  algParameters.init(ecsp);
            //   ECParameterSpec ecSpec = algParameters.getParameterSpec(ECParameterSpec.class);
            //    ECPublicKeySpec pubSpec ;

            //   pubSpec = new ECPublicKeySpec(Q, ecSpec);
            //   BCECPublicKey publicKey = (BCECPublicKey) keyFactory.generatePublic(pubSpec);

            //   ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
            //   ECNamedCurveSpec params = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
            ECPoint publicPoint = priv.getParameters().getG().multiply(priv.getS());
            hexdump("calc pub---", publicPoint.getEncoded(false));

            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec (curveName);
            //org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().decodePoint (temp);
            //KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            //PublicKey pk = keyFactory.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec));
            BCECPublicKey pk = (BCECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(publicPoint, ecSpec));

            //ECPoint publicPoint =  ECPointUtil.decodePoint(params.getCurve(), publicKeyByteArray);
            //    ECPublicKeySpec pubKeySpec = new BCECPublicKeySpec(publicPoint, params);
            //   BCECPublicKey publicKey = (BCECPublicKey) keyFactory.generatePublic(pubSpec);

            //  ECParametersSpec ecDomainParameters = priv.getParameters();
            //  ECDomainParameters ecDomainParameters = generateDomainParameters();
            //  ECPublicKeyParameters ecPublicKeyParameters =
            //         new ECPublicKeyParameters(ecDomainParameters.getG(), ecDomainParameters);
            // return new BCECPublicKey(ECDSA, ecPublicKeyParameters, null);

            //   BouncyCastleProvider provider = new BouncyCastleProvider();
            //  X9ECParameters parameters = GMNamedCurves.getByName("sm2p256v1");
            //  ECParameterSpec ecParameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            // ECPoint ecPoint = parameters.getCurve().decodePoint(Hex.decode(publicKey));
            //  KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
            //  ECParameterSpec ecParameterSpec = priv.getParameters();

            // BCECPublicKey publicKey = (BCECPublicKey) keyFactory.generatePublic(        		new ECPublicKeySpec(publicPoint, ecParameterSpec));

            //  return publicKey;
            return pk;
        }

    public static BCECPrivateKey genBCECPrivateKeyFromBN(String ins, String curveName, BigInteger privBN)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {


            //AlgorithmParameters algoParameters = AlgorithmParameters.getInstance(ins, "BC");
        //algoParameters.init(new ECGenParameterSpec(curveName));
    //ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);
//KeySpec privateKeySpec = new ECPrivateKeySpec(privBN, parameterSpec);
            //KeyFactory kf = KeyFactory.getInstance(ins,"BC");

            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec (curveName);
            KeySpec privateKeySpec = new ECPrivateKeySpec(privBN, ecSpec);
            KeyFactory kf = KeyFactory.getInstance(ins,"BC");

            BCECPrivateKey pk = (BCECPrivateKey) kf.generatePrivate(privateKeySpec);

            //BCECPrivateKey privateKey = (BCECPrivateKey) kf.generatePrivate(privateKeySpec);

            return pk;
    }

    public static BCECPrivateKey readPrivFromDER(String ins, String DERfile) 
            throws IOException, NoSuchAlgorithmException, GeneralSecurityException

        {


            Path path = Paths.get(DERfile);
            byte[] privKeyByteArray = Files.readAllBytes(path);
            hexdump("priv", privKeyByteArray);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance(ins, "BC");
            BCECPrivateKey privateKey=  (BCECPrivateKey) keyFactory.generatePrivate(keySpec);
            return privateKey;
        }

    public static BCECPublicKey readPubFromDER(String ins, String DERfile) 
            throws IOException, NoSuchAlgorithmException, GeneralSecurityException
        {
            Path path = Paths.get(DERfile);
            byte[] keyBytes= Files.readAllBytes(path);

            KeyFactory kf = KeyFactory.getInstance(ins,"BC");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            BCECPublicKey publicKey = (BCECPublicKey) kf.generatePublic(keySpec);

            //ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            //ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN());
            //ECPoint publicPoint =  ECPointUtil.decodePoint(params.getCurve(), publicKeyByteArray);
            //ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(publicPoint, params);
            //PublicKey publicKey =  keyFactory.generatePublic(pubKeySpec);

            return publicKey;
        }


    public static byte[] digest( String hashName,  byte[] s) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(hashName);
        byte[] hash = digest.digest(s);
        return hash;
    }

    public static byte[] hmacMain(String alg, byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException
        {
            SecretKeySpec k = new SecretKeySpec(key, alg);
            Mac m = Mac.getInstance(alg);
            m.init(k);
            byte[] res = m.doFinal(data);
            return res;
        }

    public static void BCECPrivteKeyDump(String s, BCECPrivateKey ecPrivKey)             throws IOException

    {
        byte[] KeyEncoded = ecPrivKey.getEncoded();
        hexdump(s + " ecpriv key", KeyEncoded);

        BigInteger d = ecPrivKey.getS();
        hexdump("d", d.toByteArray());
    }

    public static void BCECPublicKeyDump(String s, BCECPublicKey ecPubKey)             throws Exception

    {
        byte[] pubKeyEncoded = ecPubKey.getEncoded();
        hexdump(s + " ecpublic key", pubKeyEncoded);

        ECPoint ecPubPoint = ecPubKey.getQ();
        hexdump("point",  ecPubPoint.getEncoded(false));
        // hexdump("x", ecPubPoint.getAffineXCoord().getEncoded());
        //hexdump("y", ecPubPoint.getAffineYCoord().getEncoded());

        //   ECNamedCurveParameterSpec param=ECNamedCurveTable.getParameterSpec(getCurveName(ecPubKey));
        //   ECCurve worker=param.getCurve();
        //    ECCurve worker=   ecPubKey.getParams().getCurve();

        //  ECPoint ecPubPoint = worker.decodePoint(pubKeyEncoded);
        //res = p.multiply(privBN);
        //ecPubKey.getParams().getOrder();
        //   ECPoint ecPubPoint = ecPubKey.getW();
        //   BigInteger x = ecPubPoint.getAffineX();
        //  BigInteger y = ecPubPoint.getAffineY();
        //hexdump("x", x.toByteArray());
        // hexdump("y", y.toByteArray());

    }


    public static byte[] intToBigEndian(long i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt((int) i);
        return bb.array();
    }

    public static byte[] stringToBytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] x9_63_KDF(byte[] z, byte[] sharedInfo, int keyDataLen, String hashName) throws NoSuchAlgorithmException {
        int counter = 1;

        ByteBuffer buf = ByteBuffer.allocate(keyDataLen) ; 

        while(keyDataLen>0) {
            byte[] c4 = intToBigEndian(counter);
            byte [] raw = ByteBuffer.allocate(z.length + c4.length + sharedInfo.length)
                .put(z).put(c4).put(sharedInfo)
                .array();
            byte[] d = digest(hashName, raw);
            int dLen = d.length;
            if(dLen<= keyDataLen) {
                buf.put(d); 
                keyDataLen-=dLen;
            }else {
                buf.put(d,0, keyDataLen);
                keyDataLen = 0;
            }
            counter++;
        }
        byte[] result = buf.array();
        return result;
    }

}
