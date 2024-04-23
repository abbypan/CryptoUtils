package com.abbypan.cryptoutils.tests;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.Test;

import com.abbypan.cryptoutils.CryptoUtils;

public class CryptoUtilsTest {
       @Test
       public void x963kdf() throws NoSuchAlgorithmException {
    	   byte[] z = CryptoUtils.stringToBytes("input key");
           byte[] sharedInfo = CryptoUtils.stringToBytes("ANSI X9.63 Example");
           byte[] res = CryptoUtils.x9_63_KDF(z, sharedInfo, 99, "SHA-256");
           byte[] exp = CryptoUtils.hexstringToBytes("e232c1da499317cdc90bece39e37cadc2322eb32c3c921fb24283dde34794ff5342b73c495ea7d036a7c708fe98d50f2b56b7033e5f2e2df7361208aa01f008b7403e057cf735ca39f2af77a84766c2a82d7f6376d2c4b83e73b889ff73c2e83d1f4a5");
           //CrytpoUtils.hexdump("x9.63 kdf", res);
         
         
          assertArrayEquals(res, exp);
       }

    
}
