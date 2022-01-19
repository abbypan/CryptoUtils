package com.abbypan.cryptoutils;

import java.security.Security;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.apache.commons.io.HexDump;

public class CryptoUtils {
    public static void printAlgList(String utilName){
        System.out.println(Security.getAlgorithms(utilName));
    }
    public static void printProviderList(){
        System.out.println(Arrays.toString(Security.getProviders()));
    }
    
  
      
    public static void main(String[] args) throws Exception {
    	byte[] z = Utils.stringToByteArray("input key");
    	byte[] sharedInfo = Utils.stringToByteArray("ANSI X9.63 Example");
    	byte[] res = KDF.x9_63_KDF(z, sharedInfo, 99, "SHA-256");
        Utils.hexdump(res);

     //   printProviderList();
    //    printAlgList("MessageDigest");
      //  printAlgList("Cipher");
    //    printAlgList("Signature");
    //    printAlgList("KeyPair");
     //   printAlgList("SecretKeyFactory");
        
    //    String s = "abc";
   //     byte[] hash = Digest.digest("SHA-256", s);
        
     //   int i = 1;
    //    Utils.hexdump(Utils.intToBigEndian(i));

        
    }
}
