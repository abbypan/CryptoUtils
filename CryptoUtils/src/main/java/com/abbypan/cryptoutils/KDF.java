package com.abbypan.cryptoutils;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

public class KDF {
	  public static byte[] x9_63_KDF(byte[] z, byte[] sharedInfo, int keyDataLen, String hashName) throws NoSuchAlgorithmException {
   	   int counter = 1;

   	   ByteBuffer buf = ByteBuffer.allocate(keyDataLen) ; 
   	   
   	   while(keyDataLen>0) {
   		   byte[] c4 = Utils.intToBigEndian(counter);
   		   byte [] raw = ByteBuffer.allocate(z.length + c4.length + sharedInfo.length)
  			        .put(z).put(c4).put(sharedInfo)
  			        .array();
   		   byte[] d = Digest.digest(hashName, raw);
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
